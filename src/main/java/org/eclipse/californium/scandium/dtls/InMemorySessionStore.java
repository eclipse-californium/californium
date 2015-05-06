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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add support for stale
 *                                                    session expiration (466554)
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * An in-memory <code>SessionStore</code> with a maximum capacity
 * and support for evicting stale sessions based on an LRU policy.
 * 
 * The store keeps track of the sessions' last-access time automatically.
 * Every time a session is read from or put to the store, the access-time
 * is updated.
 * 
 * A session can be successfully added to the store if any of the
 * following conditions is met:
 * <ul>
 * <li>The store's remaining capacity is greater than zero.</li>
 * <li>The store contains at least one <em>stale<em> session, i.e. a
 * session that has not been accessed for at least the store's <em>
 * session expiration threshold</em> period. In such a case the least-
 * recently accessed stale session gets evicted from the store to make
 * place for the new session to be added.</li>
 * </ul>
 * 
 * This implementation uses a <code>java.util.HashMap</code> with
 * a session's peer address as key as its backing store.
 * In addition to that the store keeps a doubly-linked list of the
 * sessions in access-time order.
 * 
 * Insertion, lookup and removal of sessions is done in
 * <em>O(log n)</em>.
 */
public class InMemorySessionStore implements SessionStore {

	private static final Logger LOG = Logger.getLogger(InMemorySessionStore.class.getName());
	private static final long DEFAULT_THRESHOLD_SECS = 36 * 60 * 60; // 36 hours
	private static final int DEFAULT_CAPACITY = 500000;

	/** Storing sessions according to peer-addresses */
	private Map<InetSocketAddress, SessionEntry> cache;
	private int capacity;
	private SessionEntry header;
	private long expirationThreshold;
	private List<EvictionListener> evictionListeners = new LinkedList<>();
	
	/**
	 * Creates a store with a capacity of 500000 sessions and
	 * a session expiration threshold of 36 hours.
	 */
	public InMemorySessionStore() {
		this(DEFAULT_CAPACITY, DEFAULT_THRESHOLD_SECS);
	}
	
	/**
	 * Creates a store based on given configuration parameters.
	 * 
	 * @param capacity the maximum number of sessions the store can manage
	 * @param threshold the period of time of inactivity (in seconds) after which a
	 *            session is considered stale and can be evicted from the store if
	 *            a new session is to be added to the store
	 */
	public InMemorySessionStore(int capacity, final long threshold) {
		header = new SessionEntry(null, -1);
		header.after = header.before = header;
		
		this.capacity = capacity;
		this.expirationThreshold = threshold;
		this.cache = new HashMap<>(capacity + 1, 1.0f); // add one to prevent re-sizing
		LOG.log(Level.CONFIG, "Created new InMemorySessionStore [capacity: {0}, session expiration threshold: {1}s]",
				new Object[]{capacity, expirationThreshold});
	}

	/**
	 * Registers a listener to be notified about sessions being evicted from the store.
	 * 
	 * @param listener the listener
	 */
	void addEvictionListener(EvictionListener listener) {
		if (listener != null) {
			this.evictionListeners.add(listener);
		}
	}
	
	/**
	 * Sets the period of time after which a session is to be considered
	 * stale if it hasn't be accessed.
	 *  
	 * @param newThreshold the threshold in seconds
	 */
	void setExpirationThreshold(long newThreshold) {
		this.expirationThreshold = newThreshold;
	}
	
	/**
	 * Gets the number of sessions currently managed by the store.
	 * 
	 * @return the size
	 */
	synchronized int size() {
		return cache.size();
	}
	
	@Override
	public synchronized int remainingCapacity() {
		return capacity - cache.size();
	}
	
	/**
	 * Puts a session to the store.
	 * 
	 * The session's peer address is used as the key.
	 * 
	 * A session can be successfully added to the store if any of the
	 * following conditions is met:
	 * <ul>
	 * <li>The store's remaining capacity is greater than zero.</li>
	 * <li>The store contains at least one <em>stale<em> session, i.e. a
	 * session that has not been accessed for at least the store's <em>
	 * session expiration threshold</em> period. In such a case the least-
	 * recently accessed stale session gets evicted from the store to make
	 * place for the new session to be added.</li>
	 * </ul>
	 * 
	 * If a session is evicted this method notifies all registered
	 * <code>EvictionListeners</code>.
	 * 
	 * @returns <code>true</code> if the session could be added to the
	 * store, <code>false</code> otherwise, e.g. because the store's
	 * remaining capacity is zero and no stale session can be evicted
	 * @see {@link #addEvictionListener(EvictionListener)}
	 */
	@Override
	public final synchronized boolean put(DTLSSession session) {
		
		if (session != null) {
			SessionEntry value = cache.get(session.getPeer());
			if (value != null) {				
				LOG.log(Level.FINER, "Replacing existing session [{0}] in cache", value);
				value.remove();
				add(session);
				return true;
			} else if (cache.size() < capacity) {
				add(session);
				return true;
			} else {
				long thresholdDate = System.currentTimeMillis() - expirationThreshold * 1000;
				SessionEntry eldest = header.after;
				if (eldest.isStale(thresholdDate)) {
					LOG.log(Level.FINER, "Evicting eldest session [{0}] from cache.", eldest);
					eldest.remove();
					cache.remove(eldest.getPeer());
					add(session);
					notifyEvictionListeners(eldest.getSession());
					return true;
				}
			}
		}
		return false;
	}

	private synchronized void notifyEvictionListeners(DTLSSession session) {
		for (EvictionListener listener : evictionListeners) {
			listener.onEviction(session);
		}
	}
	
	/**
	 * Gets the <em>eldest</em> session in the store.
	 * 
	 * The eldest session is the one that has been used least recently.
	 * 
	 * @return the session
	 */
	final synchronized DTLSSession getEldest() {
		SessionEntry eldest = header.after;
		return eldest.getSession();
	}
	
	private synchronized void add(DTLSSession session) {
		SessionEntry value = new SessionEntry(session, System.currentTimeMillis());
		LOG.log(Level.FINER, "Adding session to cache [{0}]", value);
		cache.put(session.getPeer(), value);
		value.addBefore(header);
	}
	
	@Override
	public final synchronized DTLSSession get(InetSocketAddress peerAddress) {
		if (peerAddress == null) {
			return null;
		}
		SessionEntry value = cache.get(peerAddress);
		if (value != null) {
			value.recordAccess(header);
			return value.getSession();
		} else {
			return null;
		}
	}

	@Override
	public final synchronized DTLSSession find(SessionId id) {
		if (id == null) {
			return null;
		} else {
			
			for (SessionEntry value : cache.values()) {
				if (id.equals(value .getSession().getSessionIdentifier())) {
					value.recordAccess(header);
					return value.getSession();
				}
			}
			
			return null;
		}
	}

	@Override
	public final synchronized DTLSSession remove(InetSocketAddress peerAddress) {
		if (peerAddress != null) {
			SessionEntry value = cache.remove(peerAddress);
			if (value != null) {
				value.remove();
				return value.getSession();
			}
		}
		return null;
	}

	@Override
	public final void update(DTLSSession session) {
		// nothing to do
		// access time has already been updated during get or put
	}

	static interface EvictionListener {
		void onEviction(DTLSSession evictedSession);
	}
	
	private static class SessionEntry {
		private InetSocketAddress peer;
		private DTLSSession session;
		private long lastUpdate;
		private SessionEntry after;
		private SessionEntry before;
				
		private SessionEntry(DTLSSession session, long lastUpdate) {
			this.session = session;
			if (session != null) {
				this.peer = session.getPeer();
			}
			this.lastUpdate = lastUpdate;
		}
		
		private InetSocketAddress getPeer() {
			return peer;
		}
		
		private DTLSSession getSession() {
			return session;
		}
		
		private boolean isStale(long threshold) {
			return lastUpdate <= threshold;
		}
		
		private void recordAccess(SessionEntry header) {
			LOG.log(Level.FINER, "Refreshing last access time of session [{0}]", this);
			remove();
			lastUpdate = System.currentTimeMillis();
			addBefore(header);
		}
		
		private void addBefore(SessionEntry existingEntry) {
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
			return new StringBuffer("SessionEntry [key: ").append(peer)
					.append(", last access: ").append(lastUpdate).append("]")
					.toString();
		}
	}
	
}
