/*******************************************************************************
 * Copyright (c) 2022 Bosch IO GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.util.AbstractCollection;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock.ReadLock;
import java.util.concurrent.locks.ReentrantReadWriteLock.WriteLock;

/**
 * An in-memory cache with a maximum capacity and support for evicting stale
 * entries based on an LRU policy.
 * <p>
 * The cache keeps track of the value's last-update time. Every time a value is
 * updated or put to the store, the access-time is updated. In difference to
 * {@link LeastRecentlyUsedCache}, a read-access doesn't update this time. That
 * enables to use a {@link ReentrantReadWriteLock} with clear read and write
 * semantic. An update of last-update time on read access would mix that up.
 * </p>
 * <p>
 * A value can be successfully added to the cache if any of the following
 * conditions is met:
 * </p>
 * <ul>
 * <li>The cache's remaining capacity is greater than zero.</li>
 * <li>The cache contains at least one <em>stale</em> entry, i.e. an entry that
 * has not been updated for at least the cache's <em>expiration threshold</em>
 * period. In such a case the least-recently updated stale entry gets evicted
 * from the cache to make place for the new value to be added.</li>
 * </ul>
 * <p>
 * This implementation uses a {@link java.util.HashMap} as its backing store. In
 * addition to that the cache keeps a doubly-linked list of the entries in
 * access-time order.
 * </p>
 * <p>
 * Insertion, lookup and removal of entries is done in <em>O(log n)</em>. Except
 * the insertion with a past timepoint, which uses <em>O(n)</em> (see
 * {@link #put(Object, Object, long)}).
 * </p>
 * 
 * @param <K> The type of the keys used in the cache.
 * @param <V> The type of the values used in the cache.
 * @since 3.5
 */
public class LeastRecentlyUpdatedCache<K, V> {

	/**
	 * The cache's default initial capacity.
	 */
	public static final int DEFAULT_INITIAL_CAPACITY = 16;
	/**
	 * The default number of seconds after which an entry is considered
	 * <em>stale</em> if it hasn't been accessed for that amount of time.
	 */
	public static final long DEFAULT_THRESHOLD_SECS = TimeUnit.MINUTES.toSeconds(30);
	/**
	 * The cache's default maximum capacity.
	 */
	public static final int DEFAULT_CAPACITY = 150000;

	/**
	 * ReadWrite lock to protect access to map and queue.
	 */
	private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
	private final ConcurrentMap<K, CacheEntry<K, V>> cache;
	private final CacheEntry<K, V> header = new CacheEntry<>();
	private Collection<V> values;
	private volatile int capacity;

	/**
	 * Threshold for expiration in nanoseconds.
	 */
	private volatile long expirationThresholdNanos;

	/**
	 * Hide stale values.
	 * 
	 * Return {@code null} instead of stale values and don't apply
	 * {@link #update(Object)}.
	 * 
	 * @see #get(Object)
	 * @see #getTimestamped(Object)
	 * @see #update(Object)
	 * @since 3.9
	 */
	private volatile boolean hideStaleValues;

	private final List<EvictionListener<V>> evictionListeners = new LinkedList<>();

	/**
	 * Creates a cache with an initial capacity of
	 * {@link #DEFAULT_INITIAL_CAPACITY}, a maximum capacity of
	 * {@link #DEFAULT_CAPACITY} entries and an expiration threshold of
	 * {@link #DEFAULT_THRESHOLD_SECS} seconds.
	 */
	public LeastRecentlyUpdatedCache() {
		this(DEFAULT_INITIAL_CAPACITY, DEFAULT_CAPACITY, DEFAULT_THRESHOLD_SECS, TimeUnit.SECONDS);
	}

	/**
	 * Creates a cache based on given configuration parameters.
	 * <p>
	 * The cache's initial capacity is set to the lesser of
	 * {@link #DEFAULT_INITIAL_CAPACITY} and <em>capacity</em>.
	 * 
	 * @param capacity the maximum number of entries the cache can manage
	 * @param threshold the period of time of inactivity after which an entry is
	 *            considered stale and can be evicted from the cache if a new
	 *            entry is to be added to the cache
	 * @param unit TimeUnit for threshold
	 */
	public LeastRecentlyUpdatedCache(int capacity, long threshold, TimeUnit unit) {
		this(Math.min(capacity, DEFAULT_INITIAL_CAPACITY), capacity, threshold, unit);
	}

	/**
	 * Creates a cache based on given configuration parameters.
	 * 
	 * @param initialCapacity The initial number of entries the cache will be
	 *            initialized to support. The cache's capacity will be doubled
	 *            dynamically every time 0.75 percent of its current capacity is
	 *            used but it will never exceed <em>maxCapacity</em>.
	 * @param maxCapacity The maximum number of entries the cache can manage
	 * @param threshold The period of time of inactivity after which an entry is
	 *            considered stale and can be evicted from the cache if a new
	 *            entry is to be added to the cache
	 * @param unit TimeUnit for threshold
	 */
	public LeastRecentlyUpdatedCache(int initialCapacity, int maxCapacity, long threshold, TimeUnit unit) {

		if (initialCapacity > maxCapacity) {
			throw new IllegalArgumentException("initial capacity must be <= max capacity");
		} else {
			this.capacity = maxCapacity;
			this.cache = new ConcurrentHashMap<>(initialCapacity);
			setExpirationThreshold(threshold, unit);
		}
	}

	public final ReadLock readLock() {
		return lock.readLock();
	}

	public final WriteLock writeLock() {
		return lock.writeLock();
	}

	/**
	 * Registers a listener to be notified about (stale) entries being evicted
	 * from the cache.
	 * 
	 * @param listener the listener
	 */
	public void addEvictionListener(EvictionListener<V> listener) {
		if (listener != null) {
			this.evictionListeners.add(listener);
		}
	}

	/**
	 * Gets the period of time after which an entry is considered <em>stale</em>
	 * if it hasn't be updated.
	 * 
	 * @param unit time unit of return value.
	 * @return the threshold in provided units
	 */
	public final long getExpirationThreshold(TimeUnit unit) {
		return unit.convert(expirationThresholdNanos, TimeUnit.NANOSECONDS);
	}

	/**
	 * Sets the period of time after which an entry is to be considered stale if
	 * it hasn't been updated.
	 * 
	 * @param newThreshold the threshold
	 * @param unit TimeUnit for threshold
	 * @see #put(Object, Object)
	 * @see #get(Object)
	 * @see #find(Filter)
	 */
	public final void setExpirationThreshold(long newThreshold, TimeUnit unit) {
		this.expirationThresholdNanos = unit.toNanos(newThreshold);
	}

	/**
	 * Gets the maximum number of entries this cache can manage.
	 * 
	 * @return the number of entries
	 */
	public final int getCapacity() {
		return capacity;
	}

	/**
	 * Sets the maximum number of entries this cache can manage.
	 * 
	 * <em>NB</em>: invoking this method after creation of the cache does
	 * <em>not</em> have an immediate effect, i.e. no entries are purged from
	 * the cache. This happens only when a new entry is put to the cache.
	 * 
	 * @param capacity the maximum number of entries the cache can manage
	 * @see #put(Object, Object)
	 * @see #get(Object)
	 */
	public final void setCapacity(int capacity) {
		this.capacity = capacity;
	}

	/**
	 * Gets the cache's current number of entries.
	 * 
	 * @return the size
	 */
	public final int size() {
		return cache.size();
	}

	/**
	 * Gets the number of entries that can be added to this cache without the
	 * need for removing stale entries.
	 * 
	 * @return The number of entries.
	 */
	public final int remainingCapacity() {
		return Math.max(0, capacity - cache.size());
	}

	/**
	 * Check, if stale values are hidden.
	 * 
	 * @return {@code true}, if stale values are hidden, {@code false}
	 *         otherwise.
	 * @see #get(Object)
	 * @see #getTimestamped(Object)
	 * @see #update(Object)
	 * @since 3.9
	 */
	public boolean isHidingStaleValues() {
		return hideStaleValues;
	}

	/**
	 * Set to hide stale values.
	 * 
	 * @param hideStaleValues {@code true}, to hide stale values, {@code false}
	 *            otherwise.
	 * @since 3.9
	 */
	public void setHideStaleValues(boolean hideStaleValues) {
		this.hideStaleValues = hideStaleValues;
	}

	/**
	 * Removes all entries from the cache.
	 * 
	 * Acquires the write-lock.
	 */
	public final void clear() {
		lock.writeLock().lock();
		try {
			cache.clear();
			if (header != header.after && header.after != null) {
				// orphan the current doubly-linked list
				header.after.before = null;
			}
			if (header != header.before && header.before != null) {
				// orphan the current doubly-linked list
				header.before.after = null;
			}
			header.after = header.before = header;
		} finally {
			lock.writeLock().unlock();
		}
	}

	/**
	 * Gets the <em>eldest</em> value in the store.
	 * 
	 * The eldest value is the one that has been used least recently.
	 * 
	 * Acquires the read-lock.
	 * 
	 * @return the value, or {@code null}, if no value is available.
	 */
	final V getEldest() {
		try {
			lock.readLock().lock();
			if (header.after != header) {
				return header.after.getValue();
			}
		} finally {
			lock.readLock().unlock();
		}
		return null;
	}

	private final void notifyEvictionListeners(V value) {
		if (value != null && !evictionListeners.isEmpty()) {
			for (EvictionListener<V> listener : evictionListeners) {
				listener.onEviction(value);
			}
		}
	}

	/**
	 * Puts an entry to the cache.
	 * 
	 * An entry can be successfully added to the cache if any of the following
	 * conditions are met:
	 * <ul>
	 * <li>The cache's remaining capacity is greater than zero.</li>
	 * <li>The cache contains at least one <em>stale</em> entry, i.e. an entry
	 * that has not been accessed for at least the cache's <em> expiration
	 * threshold</em> period. In such a case the least- recently accessed stale
	 * entry gets evicted from the cache to make place for the new entry to be
	 * added.</li>
	 * </ul>
	 * 
	 * If an entry is evicted this method notifies all registered
	 * {@code EvictionListeners}.
	 * 
	 * Acquires the write-lock. <em>O(log n)</em>
	 * 
	 * @param key the key to store the value under
	 * @param value the value to store
	 * @return {@code true}, if the entry could be added to the cache,
	 *         {@code false}, otherwise, e.g. because the cache's remaining
	 *         capacity is zero and no stale entries can be evicted
	 * @see #addEvictionListener(EvictionListener)
	 */
	public final boolean put(K key, V value) {

		if (value != null) {
			V evict = null;
			lock.writeLock().lock();
			try {
				CacheEntry<K, V> existingEntry = cache.get(key);
				if (existingEntry != null) {
					existingEntry.remove();
					add(key, value);
					return true;
				} else if (cache.size() < capacity) {
					add(key, value);
					return true;
				} else {
					CacheEntry<K, V> eldest = header.after;
					if (eldest.isStale(expirationThresholdNanos)) {
						eldest.remove();
						cache.remove(eldest.getKey());
						add(key, value);
						evict = eldest.getValue();
					}
				}
			} finally {
				lock.writeLock().unlock();
			}
			if (evict != null) {
				notifyEvictionListeners(evict);
				return true;
			}
		}
		return false;
	}

	private final void add(K key, V value) {
		CacheEntry<K, V> entry = new CacheEntry<>(key, value);
		cache.put(key, entry);
		entry.addBefore(header);
	}

	/**
	 * Puts an entry with last-update-timestamp to the cache.
	 * 
	 * An entry can be successfully added to the cache if any of the following
	 * conditions are met:
	 * <ul>
	 * <li>The cache's remaining capacity is greater than zero.</li>
	 * <li>The cache contains at least one <em>stale</em> entry, i.e. an entry
	 * that has not been accessed for at least the cache's <em> expiration
	 * threshold</em> period. That entry must be before the provided
	 * last-update-timestamp. In such a case the least-recently accessed stale
	 * entry gets evicted from the cache to make place for the new entry to be
	 * added.</li>
	 * </ul>
	 * 
	 * Add the entries in ascending last-update-timestamp order for best
	 * performance.
	 * 
	 * If an entry is evicted this method notifies all registered
	 * {@code EvictionListeners}.
	 * 
	 * Acquires the write-lock. <em>O(n)</em>, if values passed in are not
	 * sorted ascending. <em>O(log n)</em>, if the values are sorted ascending.
	 * 
	 * @param key the key to store the value under
	 * @param value the value to store
	 * @param lastUpdate the last-update timestamp to store
	 * @return {@code true}, if the entry could be added to the cache,
	 *         {@code false}, otherwise.
	 * @see #addEvictionListener(EvictionListener)
	 */
	public final boolean put(K key, V value, long lastUpdate) {
		if (value != null) {
			V evict = null;
			lock.writeLock().lock();
			try {
				CacheEntry<K, V> existingEntry = cache.get(key);
				if (existingEntry != null) {
					existingEntry.remove();
					add(key, value, lastUpdate);
					return true;
				} else if (cache.size() < capacity) {
					add(key, value, lastUpdate);
					return true;
				} else {
					CacheEntry<K, V> eldest = header.after;
					if (eldest.isStale(expirationThresholdNanos) && (lastUpdate - eldest.lastUpdate) >= 0) {
						eldest.remove();
						cache.remove(eldest.getKey());
						add(key, value, lastUpdate);
						evict = eldest.getValue();
					}
				}
			} finally {
				lock.writeLock().unlock();
			}
			if (evict != null) {
				notifyEvictionListeners(evict);
				return true;
			}
		}
		return false;
	}

	/**
	 * Add entry with last-update timestamp.
	 * 
	 * Add the entries in ascending last-update timestamp order for best
	 * performance.
	 * 
	 * @param key the key to store the value under
	 * @param value the value to store
	 * @param lastUpdate the last-update timestamp to store
	 */
	private final void add(K key, V value, long lastUpdate) {
		CacheEntry<K, V> entry = new CacheEntry<>(key, value, lastUpdate);
		cache.put(key, entry);
		if (header.before == header) {
			// first entry
			entry.addBefore(header);
		} else {
			CacheEntry<K, V> position = header;
			while ((lastUpdate - position.before.lastUpdate) < 0) {
				position = position.before;
				if (position == header) {
					break;
				}
			}
			entry.addBefore(position);
		}
	}

	/**
	 * Gets a value from the cache.
	 * 
	 * @param key the key to look up in the cache
	 * @return the value, if the key has been found in the cache, {@code null},
	 *         otherwise
	 */
	private final CacheEntry<K, V> getEntry(K key) {
		if (key == null) {
			return null;
		}
		return cache.get(key);
	}

	/**
	 * Check, if entry is stale.
	 * 
	 * @param key the key to look up in the cache
	 * @return {@code true}, if the entry is stale, {@code false}, if there is
	 *         either no entry, or the entry is not stale.
	 */
	public final boolean isStale(K key) {
		CacheEntry<K, V> entry = getEntry(key);
		if (entry == null) {
			return false;
		} else {
			return entry.isStale(expirationThresholdNanos);
		}
	}

	/**
	 * Gets a value from the cache.
	 * 
	 * Since 3.9 the {@link #isHidingStaleValues()} is supported and returns
	 * {@code null}, if the value is stale.
	 * 
	 * @param key the key to look up in the cache
	 * @return the value, if the key has been found in the cache, {@code null},
	 *         otherwise
	 * @see #isHidingStaleValues()
	 */
	public final V get(K key) {
		CacheEntry<K, V> entry = getEntry(key);
		if (entry != null) {
			if (!hideStaleValues || !entry.isStale(expirationThresholdNanos)) {
				return entry.getValue();
			}
		}
		return null;
	}

	/**
	 * Gets a timestamped value from the cache.
	 * 
	 * Since 3.9 the {@link #isHidingStaleValues()} is supported and returns
	 * {@code null}, if the value is stale.
	 * 
	 * @param key the key to look up in the cache
	 * @return the timestamped value, if the key has been found in the cache,
	 *         {@code null}, otherwise
	 * @see #isHidingStaleValues()
	 */
	public final Timestamped<V> getTimestamped(K key) {
		CacheEntry<K, V> entry = getEntry(key);
		if (entry != null) {
			if (!hideStaleValues || !entry.isStale(expirationThresholdNanos)) {
				return entry.getEntry();
			}
		}
		return null;
	}

	/**
	 * Update the last-access time.
	 * 
	 * Since 3.9 the {@link #isHidingStaleValues()} is supported preventing
	 * stale values from being updated and returns {@code null}.
	 * 
	 * Acquires the write-lock. <em>O(1)</em>
	 * 
	 * @param key the key to update the last-access time.
	 * @return the value, if the key has been found in the cache, {@code null},
	 *         otherwise
	 * @see #isHidingStaleValues()
	 */
	public final V update(K key) {
		if (key != null) {
			lock.writeLock().lock();
			try {
				CacheEntry<K, V> entry = cache.get(key);
				if (entry != null) {
					if (!hideStaleValues || !entry.isStale(expirationThresholdNanos)) {
						entry.recordAccess(header);
						return entry.getValue();
					}
				}
			} finally {
				lock.writeLock().unlock();
			}
		}
		return null;
	}

	/**
	 * Removes an entry from the cache.
	 * 
	 * Doesn't call {@code EvictionListeners}.
	 * 
	 * Acquires the write-lock. <em>O(log n)</em>
	 * 
	 * @param key the key of the entry to remove
	 * @return the removed value or {@code null}, if the cache does not contain
	 *         the key
	 */
	public final V remove(K key) {
		if (key == null) {
			return null;
		}
		lock.writeLock().lock();
		try {
			CacheEntry<K, V> entry = cache.remove(key);
			if (entry != null) {
				entry.remove();
				return entry.getValue();
			}
		} finally {
			lock.writeLock().unlock();
		}
		return null;
	}

	/**
	 * Removes provided entry from the cache.
	 * 
	 * Doesn't call {@code EvictionListeners}.
	 * 
	 * Acquires the write-lock. <em>O(log n)</em>
	 * 
	 * @param key the key of the entry to remove
	 * @param value value of the entry to remove
	 * @return the removed value or {@code null}, if the cache does not contain
	 *         the key or entry
	 */
	public final V remove(K key, V value) {
		if (key == null) {
			return null;
		}
		lock.writeLock().lock();
		try {
			CacheEntry<K, V> entry = cache.get(key);
			if (entry != null) {
				if (entry.getValue() == value) {
					cache.remove(key);
					entry.remove();
					return value;
				}
			}
		} finally {
			lock.writeLock().unlock();
		}
		return null;
	}

	/**
	 * Remove expired entries.
	 * 
	 * Acquires the read-lock and the write-lock. <em>O(entries * log n)</em>
	 * 
	 * @param maxEntries maximum expired entries to remove
	 * @return number of removed expired entries.
	 */
	public final int removeExpiredEntries(int maxEntries) {
		int counter = 0;
		while (maxEntries == 0 || counter < maxEntries) {
			CacheEntry<K, V> eldest = nextCacheEntry(header);
			if (header == eldest || !eldest.isStale(expirationThresholdNanos)) {
				break;
			}
			V evict = null;
			try {
				lock.writeLock().lock();
				if (eldest.remove()) {
					evict = eldest.getValue();
				}
				cache.remove(eldest.getKey(), eldest);
				++counter;
			} finally {
				lock.writeLock().unlock();
			}
			if (evict != null) {
				notifyEvictionListeners(evict);
			}
		}
		return counter;
	}

	/**
	 * Finds a value based on a predicate.
	 * 
	 * The {@link #isHidingStaleValues()} is supported preventing stale values
	 * from being found.
	 * 
	 * Returns the first matching value.
	 * 
	 * Acquires the read-lock.
	 * 
	 * @param filter the condition to match. Assumed to match entries in a
	 *            unique manner. Therefore stops on first match, even if that
	 *            gets evicted on the read access.
	 * @return the first value from the cache that matches according to the
	 *         given predicate, or {@code null}, if no value matches
	 * @since 3.10
	 */
	public V find(Filter<V> filter) {
		if (filter != null) {
			final Iterator<CacheEntry<K, V>> iterator = cache.values().iterator();
			while (iterator.hasNext()) {
				CacheEntry<K, V> entry = iterator.next();
				if (!hideStaleValues || !entry.isStale(expirationThresholdNanos)) {
					V value = entry.getValue();
					if (filter.accept(value)) {
						return value;
					}
				}
			}
		}
		return null;
	}

	/**
	 * Finds a value based on a predicate.
	 * 
	 * Since 3.9 the {@link #isHidingStaleValues()} is supported preventing
	 * stale values from being found.
	 * 
	 * Returns the first matching value.
	 * 
	 * Acquires the read-lock.
	 * 
	 * @param predicate the condition to match. Assumed to match entries in a
	 *            unique manner. Therefore stops on first match, even if that
	 *            gets evicted on the read access.
	 * @return the first value from the cache that matches according to the
	 *         given predicate, or {@code null}, if no value matches
	 * @deprecated use {@link #find(Filter)} instead
	 */
	@Deprecated
	public final V find(Predicate<V> predicate) {
		if (predicate != null) {
			final Iterator<CacheEntry<K, V>> iterator = cache.values().iterator();
			while (iterator.hasNext()) {
				CacheEntry<K, V> entry = iterator.next();
				if (!hideStaleValues || !entry.isStale(expirationThresholdNanos)) {
					V value = entry.getValue();
					if (predicate.accept(value)) {
						return value;
					}
				}
			}
		}
		return null;
	}

	/**
	 * A predicate to be applied to cache entries to determine the result set
	 * when searching for particular values.
	 *
	 * @param <V> The type of value the predicate can be evaluated on.
	 * @deprecated use {@link Filter} instead.
	 */
	@Deprecated
	public static interface Predicate<V> {

		/**
		 * Applies the predicate to a cache value.
		 * 
		 * @param value The value to evaluate the predicate for.
		 * @return {@code true} if the cache entry containing the value is part
		 *         of the result set.
		 */
		boolean accept(V value);
	}

	/**
	 * A callback for getting notified about entries being evicted from the
	 * cache.
	 *
	 * @param <V> The type of entry being evicted.
	 */
	public static interface EvictionListener<V> {

		/**
		 * Indicates that an entry has been evicted from the cache.
		 * 
		 * @param evictedValue The evicted entry.
		 */
		void onEviction(V evictedValue);
	}

	/**
	 * Gets iterator over all values contained in this cache.
	 * <p>
	 * The iterator returned is backed by this cache's underlying
	 * {@link ConcurrentHashMap#values()}. The iterator is a "weakly consistent"
	 * iterator that will never throw
	 * {@link java.util.ConcurrentModificationException}, and guarantees to
	 * traverse elements as they existed upon construction of the iterator, and
	 * may (but is not guaranteed to) reflect any modifications subsequent to
	 * construction.
	 * </p>
	 * Since 3.9 the {@link #isHidingStaleValues()} is supported preventing
	 * stale values from being returned.
	 * 
	 * @return an iterator over all values backed by the underlying map.
	 */
	public final Iterator<V> valuesIterator() {

		return new Iterator<V>() {

			private final Iterator<CacheEntry<K, V>> iterator = cache.values().iterator();
			private volatile boolean hasNextCalled;
			private volatile CacheEntry<K, V> nextEntry;

			@Override
			public boolean hasNext() {
				if (!hasNextCalled) {
					nextEntry = null;
					while (iterator.hasNext()) {
						CacheEntry<K, V> entry = iterator.next();
						if (!hideStaleValues || !entry.isStale(expirationThresholdNanos)) {
							nextEntry = entry;
							break;
						}
					}
					hasNextCalled = true;
				}
				return nextEntry != null;
			}

			@Override
			public V next() {
				hasNext();
				hasNextCalled = false;
				if (nextEntry == null) {
					throw new NoSuchElementException();
				}
				return nextEntry.value;
			}

			@Override
			public void remove() {
				if (nextEntry == null || hasNextCalled) {
					throw new IllegalStateException("next() must be called before remove()!");
				}
				lock.writeLock().lock();
				try {
					iterator.remove();
					nextEntry.remove();
				} finally {
					lock.writeLock().unlock();
				}
				nextEntry = null;
			}
		};
	}

	/**
	 * Gets all connections contained in this cache.
	 * 
	 * The returned collection is intended to be used as read access, therefore
	 * the modifying methods will throw a {@link UnsupportedOperationException}.
	 * 
	 * Since 3.9 the {@link #isHidingStaleValues()} is supported preventing
	 * stale values from being returned.
	 * 
	 * @return an collection of all connections backed by the underlying map.
	 */
	public final Collection<V> values() {
		Collection<V> vs = values;
		if (vs == null) {
			vs = new AbstractCollection<V>() {

				@Override
				public final int size() {
					return cache.size();
				}

				@Override
				public final boolean contains(final Object o) {
					return null != find(new Filter<V>() {

						@Override
						public boolean accept(final V value) {
							return value.equals(o);
						}
					});
				}

				@Override
				public final Iterator<V> iterator() {
					return valuesIterator();
				}

				@Override
				public final boolean add(Object o) {
					throw new UnsupportedOperationException();
				}

				@Override
				public final boolean remove(Object o) {
					throw new UnsupportedOperationException();
				}

				@Override
				public final void clear() {
					throw new UnsupportedOperationException();
				}
			};
			values = vs;
		}
		return vs;
	}

	/**
	 * Gets iterator over all values contained in this cache.
	 * <p>
	 * The iterator is a "weakly consistent" iterator that will never throw
	 * {@link java.util.ConcurrentModificationException}. It traverse elements
	 * as they existed upon {@link Iterator#hasNext()} and
	 * {@link Iterator#next()}, and reflects any modifications subsequent to
	 * construction. In rare cases, if the current {@code next} entry is
	 * updated, the iterator will skip the entries in between. That doesn't harm
	 * too much, if the iterator is used frequently to collect up some entries.
	 * Additionally, if after the last {@link Iterator#hasNext()} returning
	 * {@code true} and the the follow up call of {@link Iterator#next()}, the
	 * last values are removed, {@link Iterator#next()} will return an already
	 * removed value.
	 * </p>
	 * <p>
	 * Since 3.9 the {@link #isHidingStaleValues()} is supported preventing
	 * stale values from being returned.
	 * </p>
	 * Acquires the read-lock.
	 * 
	 * @return an iterator over all values backed by the underlying map.
	 */
	public final Iterator<V> ascendingIterator() {

		return new Iterator<V>() {

			final Iterator<CacheEntry<K, V>> iterator = new AscendingIterator();

			@Override
			public boolean hasNext() {
				return iterator.hasNext();
			}

			@Override
			public V next() {
				CacheEntry<K, V> entry = iterator.next();
				return entry.value;
			}

			@Override
			public void remove() {
				iterator.remove();
			}
		};
	}

	/**
	 * Gets iterator over all values with timestamp contained in this cache.
	 * <p>
	 * The iterator is a "weakly consistent" iterator that will never throw
	 * {@link java.util.ConcurrentModificationException}. It traverse elements
	 * as they existed upon {@link Iterator#hasNext()} and
	 * {@link Iterator#next()}, and reflects any modifications subsequent to
	 * construction. In rare cases, if the current {@code next} entry is
	 * updated, the iterator will skip the entries in between. That doesn't harm
	 * too much, if the iterator is used frequently to collect up some entries.
	 * Additionally, if after the last {@link Iterator#hasNext()} returning
	 * {@code true} and the the follow up call of {@link Iterator#next()}, the
	 * last values are removed, {@link Iterator#next()} will return an already
	 * removed value.
	 * </p>
	 * 
	 * @return an iterator over all values backed by the underlying
	 *         doubly-linked list.
	 */
	public final Iterator<Timestamped<V>> timestampedIterator() {
		return new Iterator<Timestamped<V>>() {

			final Iterator<CacheEntry<K, V>> iterator = new AscendingIterator();

			@Override
			public boolean hasNext() {
				return iterator.hasNext();
			}

			@Override
			public Timestamped<V> next() {
				CacheEntry<K, V> entry = iterator.next();
				return entry.getEntry();
			}

			@Override
			public void remove() {
				iterator.remove();
			}
		};
	}

	/**
	 * A iterator traversing the doubly-linked list.
	 * 
	 * The iterator is a "weakly consistent" iterator that will never throw
	 * {@link java.util.ConcurrentModificationException}. It traverse elements
	 * as they existed upon {@link Iterator#hasNext()} and
	 * {@link Iterator#next()}, and reflects any modifications subsequent to
	 * construction. In rare cases, if the current {@code next} entry is
	 * updated, the iterator will skip the entries in between. That doesn't harm
	 * too much, if the iterator is used frequently to collect up some entries.
	 * Additionally, if after the last {@link Iterator#hasNext()} returning
	 * {@code true} and the the follow up call of {@link Iterator#next()}, the
	 * last values are removed, {@link Iterator#next()} will return an already
	 * removed value.
	 */
	private class AscendingIterator implements Iterator<CacheEntry<K, V>> {

		CacheEntry<K, V> current = null;
		CacheEntry<K, V> next = nextEntry(header);

		public CacheEntry<K, V> nextEntry(CacheEntry<K, V> entry) {
			return nextCacheEntry(entry);
		}

		@Override
		public boolean hasNext() {
			while (next != header && next != null
					&& (next.isRemoved() || (hideStaleValues && next.isStale(expirationThresholdNanos)))) {
				next = nextEntry(next);
			}
			return next != null && !next.isRemoved();
		}

		@Override
		public CacheEntry<K, V> next() {
			current = next;
			if (hasNext()) {
				current = next;
			} else {
				if (current == null || current == header) {
					throw new NoSuchElementException();
				}
			}
			next = nextEntry(next);
			hasNext();
			return current;
		}

		@Override
		public void remove() {
			if (current == null) {
				throw new IllegalStateException("next() must be called before remove()!");
			}
			LeastRecentlyUpdatedCache.this.remove(current.key, current.value);
			current = null;
		}
	};

	private CacheEntry<K, V> nextCacheEntry(CacheEntry<K, V> entry) {
		try {
			lock.readLock().lock();
			return entry.after;
		} finally {
			lock.readLock().unlock();
		}
	}

	private static class CacheEntry<K, V> {

		private static long REMOVED = -1;

		private final K key;
		private final V value;
		private volatile long lastUpdate;
		private CacheEntry<K, V> after;
		private CacheEntry<K, V> before;

		private CacheEntry() {
			this.key = null;
			this.value = null;
			this.lastUpdate = REMOVED;
			this.after = this;
			this.before = this;
		}

		private CacheEntry(K key, V value) {
			this(key, value, ClockUtil.nanoRealtime());
		}

		private CacheEntry(K key, V value, long lastUpdate) {
			this.key = key;
			this.value = value;
			this.lastUpdate = lastUpdate;
		}

		private final Timestamped<V> getEntry() {
			return new Timestamped<V>(value, lastUpdate);
		}

		private final K getKey() {
			return key;
		}

		private final V getValue() {
			return value;
		}

		private final boolean isStale(long thresholdNanos) {
			return (ClockUtil.nanoRealtime() - lastUpdate) >= thresholdNanos;
		}

		private final boolean recordAccess(CacheEntry<K, V> header) {
			if (remove()) {
				lastUpdate = ClockUtil.nanoRealtime();
				addBefore(header);
				return true;
			} else {
				return false;
			}
		}

		private final void addBefore(CacheEntry<K, V> existingEntry) {
			after = existingEntry;
			before = existingEntry.before;
			before.after = this;
			after.before = this;
		}

		private final boolean remove() {
			if (before != null && after != null) {
				lastUpdate = REMOVED;
				before.after = after;
				after.before = before;
				before = null;
				// keep after, in the case that a
				// ascending iterator is using it
				return true;
			} else {
				return false;
			}
		}

		private final boolean isRemoved() {
			return lastUpdate == REMOVED;
		}

		@Override
		public String toString() {
			return new StringBuilder("CacheEntry [key: ").append(key).append(", last access: ").append(lastUpdate)
					.append("]").toString();
		}
	}

	public static final class Timestamped<V> {

		private final V value;
		private final long lastUpdate;

		public Timestamped(V value, long lastUpdate) {
			this.value = value;
			this.lastUpdate = lastUpdate;
		}

		public final V getValue() {
			return value;
		}

		public final long getLastUpdate() {
			return lastUpdate;
		}

		@Override
		public int hashCode() {
			int hash = (int) (lastUpdate ^ (lastUpdate >>> 32));
			if (value != null) {
				return hash + value.hashCode();
			}
			return hash;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			} else if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			Timestamped<?> other = (Timestamped<?>) obj;
			if (lastUpdate != other.lastUpdate) {
				return false;
			}
			if (value == null) {
				return other.value == null;
			} else {
				return value.equals(other.value);
			}
		}

		@Override
		public String toString() {
			return lastUpdate + ": " + value;
		}
	}
}
