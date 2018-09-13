/*******************************************************************************
 * Copyright (c) 2015, 2017 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add empty implementation
 *                                                    for handshakeFailed.
 *    Achim Kraus (Bosch Software Innovations GmbH) - use final for collections
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - configure LRU to return
 *                                                    expired entries on read access.
 *                                                    See issue #707
 *    Achim Kraus (Bosch Software Innovations GmbH) - configure LRU to update
 *                                                    connection only, if access
 *                                                    is validated with the MAC
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix session resumption with
 *                                                    session cache. issue #712
 *    Achim Kraus (Bosch Software Innovations GmbH) - add more logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - restore connection from
 *                                                    client session cache,
 *                                                    when provided.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add putEstablishedSession
 *                                                    and removeFromEstablishedSessions
 *                                                    for faster find
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.elements.util.LeastRecentlyUsedCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An in-memory <code>ConnectionStore</code> with a configurable maximum capacity
 * and support for evicting stale connections based on a <em>least recently used</em> policy.
 * <p>
 * The store keeps track of the connections' last-access time automatically.
 * Every time a connection is read from or put to the store the access-time
 * is updated.
 * </p>
 * <p>
 * A connection can be successfully added to the store if any of the
 * following conditions is met:
 * </p>
 * <ul>
 * <li>The store's remaining capacity is greater than zero.</li>
 * <li>The store contains at least one <em>stale</em> connection, i.e. a
 * connection that has not been accessed for at least the store's <em>
 * connection expiration threshold</em> period. In such a case the least
 * recently accessed stale connection gets evicted from the store to make
 * place for the new connection to be added.</li>
 * </ul>
 * <p>
 * This implementation uses a <code>java.util.HashMap</code> with
 * a connection's peer address as key as its backing store.
 * In addition to that the store keeps a doubly-linked list of the
 * connections in access-time order.
 * </p>
 * <p>
 * Insertion, lookup and removal of connections is done in
 * <em>O(log n)</em>.
 * </p>
 * <p>
 * Storing and reading to/from the store is thread safe.
 * </p>
 */
public final class InMemoryConnectionStore implements ResumptionSupportingConnectionStore {

	private static final Logger LOG = LoggerFactory.getLogger(InMemoryConnectionStore.class.getName());
	private static final int DEFAULT_CACHE_SIZE = 150000;
	private static final long DEFAULT_EXPIRATION_THRESHOLD = 36 * 60 * 60; // 36h
	private final LeastRecentlyUsedCache<InetSocketAddress, Connection> connections;
	private final Map<SessionId, Connection> connectionsByEstablishedSession;
	private final SessionCache sessionCache;

	private String tag = "";

	/**
	 * Creates a store with a capacity of 500000 connections and
	 * a connection expiration threshold of 36 hours.
	 */
	public InMemoryConnectionStore() {
		this(DEFAULT_CACHE_SIZE, DEFAULT_EXPIRATION_THRESHOLD);
	}

	/**
	 * Creates a store with a capacity of 500000 connections and a connection
	 * expiration threshold of 36 hours.
	 * 
	 * @param sessionCache a second level cache to use for <em>current</em>
	 *            connection state of established DTLS sessions.
	 */
	public InMemoryConnectionStore(final SessionCache sessionCache) {
		this(DEFAULT_CACHE_SIZE, DEFAULT_EXPIRATION_THRESHOLD, sessionCache);
	}

	/**
	 * Creates a store based on given configuration parameters.
	 * 
	 * @param capacity the maximum number of connections the store can manage
	 * @param threshold the period of time of inactivity (in seconds) after which a
	 *            connection is considered stale and can be evicted from the store if
	 *            a new connection is to be added to the store
	 */
	public InMemoryConnectionStore(final int capacity, final long threshold) {
		this(capacity, threshold, null);
	}

	/**
	 * Creates a store based on given configuration parameters.
	 * 
	 * @param capacity the maximum number of connections the store can manage
	 * @param threshold the period of time of inactivity (in seconds) after which a
	 *            connection is considered stale and can be evicted from the store if
	 *            a new connection is to be added to the store
	 * @param sessionCache a second level cache to use for <em>current</em>
	 *                     connection state of established DTLS sessions.
	 *                     If implements {@link ClientSessionCache}, restore
	 *                     connection from the cache and mark them to resume. 
	 */
	public InMemoryConnectionStore(final int capacity, final long threshold, final SessionCache sessionCache) {
		connections = new LeastRecentlyUsedCache<>(capacity, threshold);
		connections.setEvictingOnReadAccess(false);
		connections.setUpdatingOnReadAccess(false);
		connectionsByEstablishedSession = new HashMap<>();
		this.sessionCache = sessionCache;

		if (sessionCache != null) {
			// make sure that session state for stale (evicted) connections is removed from second level cache
			connections.addEvictionListener(new LeastRecentlyUsedCache.EvictionListener<Connection>() {

				@Override
				public void onEviction(Connection staleConnection) {
					removeFromEstablishedSessions(staleConnection);
					removeSessionFromCache(staleConnection);
				}
			});
			
			if (sessionCache instanceof ClientSessionCache) {
				ClientSessionCache clientCache = (ClientSessionCache) sessionCache;
				LOG.debug("resume client sessions {}", clientCache);
				for (InetSocketAddress peer : clientCache) {
					SessionTicket ticket = clientCache.getSessionTicket(peer);
					SessionId id = clientCache.getSessionIdentity(peer);
					if (ticket != null && id != null) {
						// restore connection from session ticket 
						Connection connection = new Connection(ticket, id);
						connection.setResumptionRequired(true);
						connections.put(peer, connection);
						LOG.debug("resume {} {}", peer, id);
					}
				}
			}
		}
		LOG.info("Created new InMemoryConnectionStore [capacity: {}, connection expiration threshold: {}s]",
				capacity, threshold);
	}

	/**
	 * Set tag for logging outputs.
	 * 
	 * @param tag tag for logging
	 */
	public synchronized void setTag(final String tag) {
		if (tag.endsWith(" ")) {
			this.tag = tag;
		} else {
			this.tag = tag + " ";
		}
	}

	/**
	 * Puts a connection to the store.
	 * <p>
	 * The connection's peer address is used as the key.
	 * <p>
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
	 *         store, <code>false</code> otherwise, e.g. because the store's
	 *         remaining capacity is zero and no stale connection can be evicted
	 */
	@Override
	public synchronized boolean put(final Connection connection) {

		if (connection != null) {
			if (connections.put(connection.getPeerAddress(), connection)) {
				LOG.debug("{}connection: add {}", tag, connection.getPeerAddress());
				return true;
			} else {
				LOG.debug("{}connection store is full! {} max. entries.", tag, connections.getCapacity());
				dump();
				return false;
			}
		} else {
			return false;
		}
	}

	@Override
	public synchronized boolean update(final Connection connection) {
		if (connection != null && connections.update(connection.getPeerAddress())) {
			return true;
		} else {
			return false;
		}
	}

	public synchronized void putEstablishedSession(final DTLSSession session, final Connection connection) {
		connectionsByEstablishedSession.put(session.getSessionIdentifier(), connection);
		if (sessionCache != null) {
			sessionCache.put(session);
		}
	}

	@Override
	public synchronized Connection find(final SessionId id) {

		if (id == null) {
			return null;
		} else {
			Connection conFromLocalCache = findLocally(id);

			if (sessionCache == null) {

				return conFromLocalCache;

			} else {

				// make sure a stale session cannot be resumed
				SessionTicket ticket = sessionCache.get(id);
				if (ticket == null) {
					// either a session with the given ID has never been established (on other nodes)
					// or another node has removed the session from the cache, e.g. because it became
					// stale

					if (conFromLocalCache != null) {
						// remove corresponding connection from this store
						remove(conFromLocalCache, false);
						// TODO: should we send a fatal alert to peer in this case?
					}

					return null;

				} else if (conFromLocalCache == null) {
					// this probably means that we are taking over the session from a failed node
					return new Connection(ticket, id);
					// connection will be put to first level cache as part of
					// the abbreviated handshake
				} else {
					// resume connection found in local cache (i.e. this store)
					return conFromLocalCache;
				}
			}
		}
	}

	private synchronized Connection findLocally(final SessionId id) {
		Connection connection = connectionsByEstablishedSession.get(id);
		if (connection != null) {
			connections.update(connection.getPeerAddress());
		}
		return connection;
	}

	@Override
	public synchronized void markAllAsResumptionRequired() {
		for (Connection connection : connections.values()) {
			connection.setResumptionRequired(true);
			LOG.debug("{}connection: mark for resumption {}!", tag, connection.getPeerAddress());
		}
	}

	@Override
	public synchronized int remainingCapacity() {
		return connections.remainingCapacity();
	}

	@Override
	public synchronized Connection get(final InetSocketAddress peerAddress) {
		return connections.get(peerAddress);
	}

	@Override
	public Connection remove(final InetSocketAddress peerAddress) {
		return remove(peerAddress, true);
	}

	@Override
	public synchronized Connection remove(final InetSocketAddress peerAddress, final boolean removeFromSessionCache) {
		Connection connection = connections.remove(peerAddress);
		if (connection != null) {
			if (LOG.isTraceEnabled()) {
				LOG.trace("{}connection: remove {}:{}", tag, connection, peerAddress,
						new Throwable("connection removed!"));
			} else {
				LOG.debug("{}connection: remove {}", tag, peerAddress);
			}
			removeFromEstablishedSessions(connection);
			if (removeFromSessionCache) {
				removeSessionFromCache(connection);
			}
		}
		return connection;
	}

	@Override
	public boolean remove(final Connection connection) {
		return remove(connection, true);
	}

	@Override
	public synchronized boolean remove(final Connection connection, final boolean removeFromSessionCache) {
		boolean removed = connections.remove(connection.getPeerAddress(), connection) == connection;
		if (removed) {
			if (LOG.isTraceEnabled()) {
				LOG.trace("{}connection: remove {}:{}", tag, connection, connection.getPeerAddress(),
						new Throwable("connection removed!"));
			} else {
				LOG.debug("{}connection: remove {}", tag, connection.getPeerAddress());
			}
			removeFromEstablishedSessions(connection);
			if (removeFromSessionCache) {
				removeSessionFromCache(connection);
			}
		}
		return removed;
	}

	private void removeFromEstablishedSessions(Connection connection) {
		DTLSSession establishedSession = connection.getEstablishedSession();
		if (establishedSession != null) {
			SessionId sessionId = establishedSession.getSessionIdentifier();
			Connection removedConnection = connectionsByEstablishedSession.remove(sessionId);
			if (removedConnection != connection) {
				connectionsByEstablishedSession.put(sessionId, removedConnection);
			}
		}
	}

	private synchronized void removeSessionFromCache(final Connection connection) {
		if (sessionCache != null && connection.hasEstablishedSession()) {
			sessionCache.remove(connection.getEstablishedSession().getSessionIdentifier());
		}
	}

	@Override
	public final synchronized void clear() {
		connections.clear();
		connectionsByEstablishedSession.clear();
		// TODO: does it make sense to clear the SessionCache as well?
	}

	/**
	 * Dump connections to logger. Intended to be used for unit tests.
	 */
	public synchronized void dump() {
		if (connections.size() == 0) {
			LOG.debug("  {}connections empty!", tag);
		} else {
			for (Connection connection : connections.values()) {
				LOG.debug("  {}connection: {}", tag, connection.getPeerAddress());
			}
		}
	}
}
