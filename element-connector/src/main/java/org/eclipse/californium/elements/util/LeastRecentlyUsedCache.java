/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Kai Hudalla (Bosch Software Innovations GmbH) - Initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * An in-memory cache with a maximum capacity
 * and support for evicting stale entries based on an LRU policy.
 * <p>
 * The cache keeps track of the values' last-access time automatically.
 * Every time a value is read from or put to the store, the access-time
 * is updated.
 * </p>
 * <p>
 * A value can be successfully added to the cache if any of the
 * following conditions is met:
 * </p>
 * <ul>
 * <li>The cache's remaining capacity is greater than zero.</li>
 * <li>The cache contains at least one <em>stale</em> entry, i.e. an
 * entry that has not been accessed for at least the cache's
 * <em>expiration threshold</em> period. In such a case the least-
 * recently accessed stale entry gets evicted from the cache to make
 * place for the new value to be added.</li>
 * </ul>
 * <p>
 * This implementation uses a <code>java.util.HashMap</code> as its backing store.
 * In addition to that the cache keeps a doubly-linked list of the
 * entries in access-time order.
 * </p>
 * <p>
 * Access to the cache's entries (e.g. <em>put</em>, <em>get</em>, <em>remove</em>)
 * is <em>not</em> thread safe. Clients should explicitly serialize access to the cache
 * from multiple threads.
 * </p>
 * <p>
 * Insertion, lookup and removal of entries is done in
 * <em>O(log n)</em>.
 * </p>
 * 
 * @param <K> The type of the keys used in the cache.
 * @param <V> The type of the values used in the cache.
 */
public class LeastRecentlyUsedCache<K, V> {

	/**
	 * The cache's default initial capacity.
	 */
	public static final int DEFAULT_INITIAL_CAPACITY = 16;
	/**
	 * The default number of seconds after which an entry is considered
	 * <em>stale</em> if it hasn't been accessed for that amount of time.
	 */
	public static final long DEFAULT_THRESHOLD_SECS = 30 * 60; // 30 minutes
	/**
	 * The cache's default maximum capacity.
	 */
	public static final int DEFAULT_CAPACITY = 150000;

	private Map<K, CacheEntry<K, V>> cache;
	private volatile int capacity;
	private CacheEntry<K, V> header;
	private volatile long expirationThreshold;
	private List<EvictionListener<V>> evictionListeners = new LinkedList<>();

	/**
	 * Creates a cache with an initial capacity of {@link #DEFAULT_INITIAL_CAPACITY}, a maximum
	 * capacity of {@link #DEFAULT_CAPACITY} entries and an expiration threshold of
	 * {@link #DEFAULT_THRESHOLD_SECS} seconds.
	 */
	public LeastRecentlyUsedCache() {
		this(DEFAULT_INITIAL_CAPACITY, DEFAULT_CAPACITY, DEFAULT_THRESHOLD_SECS);
	}

	/**
	 * Creates a cache based on given configuration parameters.
	 * <p>
	 * The cache's initial capacity is set to the lesser of {@link #DEFAULT_INITIAL_CAPACITY}
	 * and <em>capacity</em>.
	 * 
	 * @param capacity the maximum number of entries the cache can manage
	 * @param threshold the period of time of inactivity (in seconds) after which an
	 *            entry is considered stale and can be evicted from the cache if
	 *            a new entry is to be added to the cache
	 */
	public LeastRecentlyUsedCache(final int capacity, final long threshold) {

		this(Math.min(capacity, DEFAULT_INITIAL_CAPACITY), capacity, threshold);
	}

	/**
	 * Creates a cache based on given configuration parameters.
	 * 
	 * @param initialCapacity The initial number of entries the cache will be initialized to support.
	 *            The cache's capacity will be doubled dynamically every time 0.75 percent of its
	 *            current capacity is used but it will never exceed <em>maxCapacity</em>.
	 * @param maxCapacity The maximum number of entries the cache can manage
	 * @param threshold The period of time of inactivity (in seconds) after which an
	 *            entry is considered stale and can be evicted from the cache if
	 *            a new entry is to be added to the cache
	 */
	public LeastRecentlyUsedCache(final int initialCapacity, final int maxCapacity, final long threshold) {

		if (initialCapacity > maxCapacity) {
			throw new IllegalArgumentException("initial capacity must be <= max capacity");
		} else {
			this.capacity = maxCapacity;
			this.expirationThreshold = threshold;
			this.cache = new HashMap<>(initialCapacity);
			initLinkedList();
		}
	}

	private void initLinkedList() {
		header = new CacheEntry<>(null, null, -1);
		header.after = header.before = header;
	}

	/**
	 * Registers a listener to be notified about (stale) entries being evicted from the cache.
	 * 
	 * @param listener the listener
	 */
	public void addEvictionListener(EvictionListener<V> listener) {
		if (listener != null) {
			this.evictionListeners.add(listener);
		}
	}

	/**
	 * Gets the period of time after which an entry is considered <em>stale</em> if it hasn't be accessed.
	 *  
	 * @return the threshold in seconds
	 */
	public final long getExpirationThreshold() {
		return expirationThreshold;
	}

	/**
	 * Sets the period of time after which an entry is to be considered
	 * stale if it hasn't be accessed.
	 * 
	 * <em>NB</em>: invoking this method after creation of the cache does <em>not</em> have an
	 * immediate effect, i.e. no (now stale) entries are purged from the cache.
	 * This happens only when a new entry is put to the cache or a stale entry is read from the cache.
	 *  
	 * @param newThreshold the threshold in seconds
	 * @see #put(Object, Object)
	 * @see #get(Object)
	 */
	public final void setExpirationThreshold(long newThreshold) {
		this.expirationThreshold = newThreshold;
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
	 * <em>NB</em>: invoking this method after creation of the cache does <em>not</em> have an
	 * immediate effect, i.e. no entries are purged from the cache.
	 * This happens only when a new entry is put to the cache or a stale entry is read from the cache.
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
	 * Gets the number of entries that can be added to this cache without
	 * the need for removing stale entries.
	 * 
	 * @return The number of entries.
	 */
	public final int remainingCapacity() {
		return Math.max(0, capacity - cache.size());
	}

	/**
	 * Removes all entries from the cache.
	 */
	public final void clear() {
		cache.clear();
		initLinkedList();
	}

	/**
	 * Puts an entry to the cache.
	 * 
	 * An entry can be successfully added to the cache if any of the
	 * following conditions are met:
	 * <ul>
	 * <li>The cache's remaining capacity is greater than zero.</li>
	 * <li>The cache contains at least one <em>stale</em> entry, i.e. an
	 * entry that has not been accessed for at least the cache's <em>
	 * expiration threshold</em> period. In such a case the least-
	 * recently accessed stale entry gets evicted from the cache to make
	 * place for the new entry to be added.</li>
	 * </ul>
	 * 
	 * If an entry is evicted this method notifies all registered
	 * <code>EvictionListeners</code>.
	 * 
	 * @param key the key to store the value under
	 * @param value the value to store
	 * @return <code>true</code> if the entry could be added to the
	 * cache, <code>false</code> otherwise, e.g. because the cache's
	 * remaining capacity is zero and no stale entries can be evicted
	 * @see #addEvictionListener(EvictionListener)
	 */
	public final boolean put(K key, V value) {

		if (value != null) {
			CacheEntry<K, V> existingEntry = cache.get(key);
			if (existingEntry != null) {
				existingEntry.remove();
				add(key, value);
				return true;
			} else if (cache.size() < capacity) {
				add(key, value);
				return true;
			} else {
				long thresholdDate = System.currentTimeMillis() - expirationThreshold * 1000;
				CacheEntry<K, V> eldest = header.after;
				if (eldest.isStale(thresholdDate)) {
					eldest.remove();
					cache.remove(eldest.getKey());
					add(key, value);
					notifyEvictionListeners(eldest.getValue());
					return true;
				}
			}
		}
		return false;
	}

	private void notifyEvictionListeners(V session) {
		for (EvictionListener<V> listener : evictionListeners) {
			listener.onEviction(session);
		}
	}

	/**
	 * Gets the <em>eldest</em> value in the store.
	 * 
	 * The eldest value is the one that has been used least recently.
	 * 
	 * @return the value
	 */
	final V getEldest() {
		CacheEntry<K, V> eldest = header.after;
		return eldest.getValue();
	}

	private void add(K key, V value) {
		CacheEntry<K, V> entry = new CacheEntry<>(key, value, System.currentTimeMillis());
		cache.put(key, entry);
		entry.addBefore(header);
	}

	/**
	 * Gets a value from the cache.
	 * 
	 * If the cache contains the key but the value is <em>stale</em>
	 * the entry is removed from the cache.
	 * 
	 * @param key the key to look up in the cache
	 * @return the value if the key has been found in the cache and the value is
	 *           not stale, <code>null</code> otherwise
	 */
	public final V get(K key) {
		if (key == null) {
			return null;
		}
		CacheEntry<K, V> entry = cache.get(key);
		if (entry == null) {
			return null;
		} else if (entry.isStale(expirationThreshold)) {
			cache.remove(entry.getKey());
			entry.remove();
			return null;
		} else {
			entry.recordAccess(header);
			return entry.getValue();
		}
	}

	/**
	 * Removes an entry from the cache.
	 * 
	 * @param key the key of the entry to remove
	 * @return the removed value or <code>null</code> if the cache does not
	 *            contain the key
	 */
	public final V remove(K key) {
		if (key == null) {
			return null;
		}
		CacheEntry<K, V> entry = cache.remove(key);
		if (entry != null) {
			entry.remove();
			return entry.getValue();
		} else {
			return null;
		}
	}

	/**
	 * Finds a value based on a predicate.
	 * 
	 * @param predicate the condition to match
	 * @return the first value from the cache that matches according to the given
	 *          predicate or <code>null</code> if no value matches
	 */
	public final V find(Predicate<V> predicate) {
		if (predicate != null) {
			for (CacheEntry<K, V> entry : cache.values()) {
				if (predicate.accept(entry.getValue())) {
					return entry.getValue();
				}
			}
		}
		return null;
	}

	/**
	 * A predicate to be applied to cache entries to determine the result set when searching for particular
	 * values.
	 *
	 * @param <V> The type of value the predicate can be evaluated on.
	 */
	public static interface Predicate<V> {

		/**
		 * Applies the predicate to a cache value.
		 * 
		 * @param value The value to evaluate the predicate for.
		 * @return {@code true} if the cache entry containing the value is part of the result set.
		 */
		public boolean accept(V value);
	}

	/**
	 * A callback for getting notified about entries being evicted from the cache.
	 *
	 * @param <V> The type of entry being evicted.
	 */
	public static interface EvictionListener<V> {

		/**
		 * Indicates that an entry has been evicted from the cache.
		 * 
		 * @param evictedValue The evicted entry.
		 */
		public void onEviction(V evictedValue);
	}

	/**
	 * Gets all connections contained in this cache.
	 * <p>
	 * The iterator returned is directly backed by this cache's underlying map.
	 * If the cache is modified while an iteration over the values is in progress,
	 * the results of the iteration are undefined.
	 * </p>
	 * <p>
	 * Removal of connections from the iterator is unsupported.
	 * </p>
	 *  
	 * @return an iterator over all connections backed by the underlying map.
	 */
	public final Iterator<V> values() {
		final Iterator<CacheEntry<K, V>> iter = cache.values().iterator();

		return new Iterator<V>() {
			@Override
			public boolean hasNext() {
				return iter.hasNext();
			}

			@Override
			public V next() {
				return iter.next().value;
			}

			@Override
			public void remove() {
				throw new UnsupportedOperationException();
			}
		};
	}

	private static class CacheEntry<K, V> {
		private K key;
		private V value;
		private long lastUpdate;
		private CacheEntry<K, V> after;
		private CacheEntry<K, V> before;

		private CacheEntry(K key, V value, long lastUpdate) {
			this.value = value;
			this.key = key;
			this.lastUpdate = lastUpdate;
		}

		private K getKey() {
			return key;
		}

		private V getValue() {
			return value;
		}

		private boolean isStale(long threshold) {
			return lastUpdate <= threshold;
		}

		private void recordAccess(CacheEntry<K, V> header) {
			remove();
			lastUpdate = System.currentTimeMillis();
			addBefore(header);
		}

		private void addBefore(CacheEntry<K, V> existingEntry) {
			after  = existingEntry;
			before = existingEntry.before;
			before.after = this;
			after.before = this;
		}

		private void remove() {
			before.after = after;
			after.before = before;
		}

		@Override
		public String toString() {
			return new StringBuilder("CacheEntry [key: ").append(key)
					.append(", last access: ").append(lastUpdate).append("]")
					.toString();
		}
	}
}
