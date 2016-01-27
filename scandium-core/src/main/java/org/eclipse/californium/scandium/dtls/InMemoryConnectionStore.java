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
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.scandium.util.LeastRecentlyUsedCache;

/**
 * An in-memory <code>ConnectionStore</code> with a configurable maximum capacity
 * and support for evicting stale connections based on a <em>least recently used</em> policy.
 * 
 * The store keeps track of the connections' last-access time automatically.
 * Every time a connection is read from or put to the store the access-time
 * is updated.
 * 
 * A connection can be successfully added to the store if any of the
 * following conditions is met:
 * <ul>
 * <li>The store's remaining capacity is greater than zero.</li>
 * <li>The store contains at least one <em>stale</em> connection, i.e. a
 * connection that has not been accessed for at least the store's <em>
 * connection expiration threshold</em> period. In such a case the least
 * recently accessed stale connection gets evicted from the store to make
 * place for the new connection to be added.</li>
 * </ul>
 * 
 * This implementation uses a <code>java.util.HashMap</code> with
 * a connection's peer address as key as its backing store.
 * In addition to that the store keeps a doubly-linked list of the
 * connections in access-time order.
 * 
 * Insertion, lookup and removal of connections is done in
 * <em>O(log n)</em>.
 * 
 * Storing and reading to/from the store is thread safe.
 */
public class InMemoryConnectionStore extends LeastRecentlyUsedCache<InetSocketAddress, Connection> implements ConnectionStore {

	private static final Logger LOG = Logger.getLogger(InMemoryConnectionStore.class.getName());
	
	/**
	 * Creates a store with a capacity of 500000 sessions and
	 * a connection expiration threshold of 36 hours.
	 */
	public InMemoryConnectionStore() {
		super();
	}
	
	/**
	 * Creates a store based on given configuration parameters.
	 * 
	 * @param capacity the maximum number of connections the store can manage
	 * @param threshold the period of time of inactivity (in seconds) after which a
	 *            connection is considered stale and can be evicted from the store if
	 *            a new connection is to be added to the store
	 */
	public InMemoryConnectionStore(int capacity, final long threshold) {
		super(capacity, threshold);
		LOG.log(Level.CONFIG, "Created new InMemoryConnectionStore [capacity: {0}, connection expiration threshold: {1}s]",
				new Object[]{capacity, threshold});
	}

	/**
	 * Puts a connection to the store.
	 * 
	 * The connection's peer address is used as the key.
	 * 
	 * A connection can be successfully added to the store if any of the
	 * following conditions is met:
	 * <ul>
	 * <li>The store's remaining capacity is greater than zero.</li>
	 * <li>The store contains at least one <em>stale</em> connection, i.e. a
	 * connection that has not been accessed for at least the store's <em>
	 * connection expiration threshold</em> period. In such a case the least-
	 * recently accessed stale connection gets evicted from the store to make
	 * place for the new connection to be added.</li>
	 * </ul>
	 * 
	 * @return <code>true</code> if the connection could be added to the
	 * store, <code>false</code> otherwise, e.g. because the store's
	 * remaining capacity is zero and no stale connection can be evicted
	 */
	@Override
	public final synchronized boolean put(Connection connection) {
		
		if (connection != null) {
			return put(connection.getPeerAddress(), connection);
		} else {
			return false;
		}
	}
	
	@Override
	public final synchronized Connection find(final SessionId id) {
		if (id == null) {
			return null;
		} else {
			return find(new Predicate<Connection>() {
				@Override
				public boolean accept(Connection connection) {
					DTLSSession session = connection.getEstablishedSession();
					if (session != null) {
						return id.equals(session.getSessionIdentifier());
					} else {
						return false;
					}
				}
			});
		}
	}

}
