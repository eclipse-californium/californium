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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - re-factor LRU cache into separate generic class
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.scandium.util.LeastRecentlyUsedCache;

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
 * <li>The store contains at least one <em>stale</em> session, i.e. a
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
public class InMemorySessionStore extends LeastRecentlyUsedCache<InetSocketAddress, DTLSSession> implements SessionStore {

	private static final Logger LOG = Logger.getLogger(InMemorySessionStore.class.getName());
	
	/**
	 * Creates a store with a capacity of 500000 sessions and
	 * a session expiration threshold of 36 hours.
	 */
	public InMemorySessionStore() {
		super();
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
		super(capacity, threshold);
		LOG.log(Level.CONFIG, "Created new InMemorySessionStore [capacity: {0}, session expiration threshold: {1}s]",
				new Object[]{capacity, threshold});
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
	 * <li>The store contains at least one <em>stale</em> session, i.e. a
	 * session that has not been accessed for at least the store's <em>
	 * session expiration threshold</em> period. In such a case the least-
	 * recently accessed stale session gets evicted from the store to make
	 * place for the new session to be added.</li>
	 * </ul>
	 * 
	 * @return <code>true</code> if the session could be added to the
	 * store, <code>false</code> otherwise, e.g. because the store's
	 * remaining capacity is zero and no stale session can be evicted
	 */
	@Override
	public final synchronized boolean put(DTLSSession session) {
		
		if (session != null) {
			return put(session.getPeer(), session);
		} else {
			return false;
		}
	}
	
	@Override
	public final synchronized DTLSSession find(final SessionId id) {
		if (id == null) {
			return null;
		} else {
			return find(new Predicate<DTLSSession>() {
				@Override
				public boolean accept(DTLSSession session) {
					return id.equals(session.getSessionIdentifier());
				}
			});
		}
	}

}
