/*******************************************************************************
 * Copyright (c) 2015, 2017 Bosch Software Innovations GmbH and others.
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
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.eclipse.californium.elements.util.LeastRecentlyUsedCache;
import org.eclipse.californium.elements.util.SerialExecutor;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.ConnectionListener;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An in-memory <code>ResumptionSupportingConnectionStore</code> with a
 * configurable maximum capacity and support for evicting stale connections
 * based on a <em>least recently used</em> policy.
 * <p>
 * The store keeps track of the connections' last-access time automatically.
 * Every time a connection is read from or put to the store the access-time is
 * updated.
 * </p>
 * <p>
 * A connection can be successfully added to the store if any of the following
 * conditions is met:
 * </p>
 * <ul>
 * <li>The store's remaining capacity is greater than zero.</li>
 * <li>The store contains at least one <em>stale</em> connection, i.e. a
 * connection that has not been accessed for at least the store's <em>
 * connection expiration threshold</em> period. In such a case the least
 * recently accessed stale connection gets evicted from the store to make place
 * for the new connection to be added.</li>
 * </ul>
 * <p>
 * This implementation uses three <code>java.util.HashMap</code>. One with a
 * connection's id as key as its backing store, one with the peer address as
 * key, and one with the session id as key. In addition to that the store keeps
 * a doubly-linked list of the connections in access-time order.
 * </p>
 * <p>
 * Insertion, lookup and removal of connections is done in <em>O(log n)</em>.
 * </p>
 * <p>
 * Storing and reading to/from the store is thread safe.
 * </p>
 * <p>
 * Supports also a {@link SessionCache} implementation to keep sessions for
 * longer or in a distribute system. If this store evicts a connection in order
 * to gain storage for new connections, the associated session remains in the
 * cache. Therefore the cache requires a own, independent cleanup for stale
 * sessions. If a connection is removed by a critical ALERT, the session get's
 * removed also from the cache.
 * </p>
 */
public class InMemoryConnectionStore implements ResumptionSupportingConnectionStore, CloseSupportingConnectionStore {

	private static final Logger LOG = LoggerFactory.getLogger(InMemoryConnectionStore.class);
	private static final int DEFAULT_SMALL_EXTRA_CID_LENGTH = 2; // extra cid bytes additionally to required bytes for small capacity.
	private static final int DEFAULT_LARGE_EXTRA_CID_LENGTH = 3; // extra cid bytes additionally to required bytes for large capacity.
	private static final int DEFAULT_CACHE_SIZE = 150000;
	private static final long DEFAULT_EXPIRATION_THRESHOLD = 36 * 60 * 60; // 36h
	private final SessionCache sessionCache;
	protected final LeastRecentlyUsedCache<ConnectionId, Connection> connections;
	protected final ConcurrentMap<InetSocketAddress, Connection> connectionsByAddress;
	protected final ConcurrentMap<SessionId, Connection> connectionsByEstablishedSession;

	private ConnectionListener connectionListener;
	/**
	 * Connection id generator.
	 * 
	 * @see #attach(ConnectionIdGenerator)
	 */
	private ConnectionIdGenerator connectionIdGenerator;

	protected String tag = "";

	/**
	 * Creates a store with a capacity of 500000 connections and
	 * a connection expiration threshold of 36 hours.
	 */
	public InMemoryConnectionStore() {
		this(DEFAULT_CACHE_SIZE, DEFAULT_EXPIRATION_THRESHOLD, null);
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
	 * @param threshold the period of time of inactivity (in seconds) after
	 *            which a connection is considered stale and can be evicted from
	 *            the store if a new connection is to be added to the store
	 * @param sessionCache a second level cache to use for <em>current</em>
	 *            connection state of established DTLS sessions. If implements
	 *            {@link ClientSessionCache}, restore connection from the cache
	 *            and mark them to resume.
	 */
	public InMemoryConnectionStore(int capacity, long threshold, SessionCache sessionCache) {
		this.connections = new LeastRecentlyUsedCache<>(capacity, threshold);
		this.connections.setEvictingOnReadAccess(false);
		this.connections.setUpdatingOnReadAccess(false);
		this.connectionsByEstablishedSession = new ConcurrentHashMap<>();
		this.connectionsByAddress = new ConcurrentHashMap<>();
		this.sessionCache = sessionCache;

		// make sure that session state for stale (evicted) connections is removed from second level cache
		connections.addEvictionListener(new LeastRecentlyUsedCache.EvictionListener<Connection>() {

			@Override
			public void onEviction(final Connection staleConnection) {
				Runnable remove = new Runnable() {

					@Override
					public void run() {
						Handshaker handshaker = staleConnection.getOngoingHandshake();
						if (handshaker != null) {
							handshaker.handshakeFailed(new ConnectionEvictedException("Evicted!", staleConnection.getPeerAddress()));
						}
						synchronized (InMemoryConnectionStore.this) {
							removeFromAddressConnections(staleConnection);
							removeFromEstablishedSessions(staleConnection);
							ConnectionListener listener = connectionListener;
							if (listener != null) {
								listener.onConnectionRemoved(staleConnection);
							}
						}
					}
				};
				if (staleConnection.isExecuting()) {
					staleConnection.getExecutor().execute(remove);
				} else {
					remove.run();
				}
			}
		});

		LOG.info("Created new InMemoryConnectionStore [capacity: {}, connection expiration threshold: {}s]",
				capacity, threshold);
	}

	/**
	 * Set tag for logging outputs.
	 * 
	 * @param tag tag for logging
	 * @return this connection store for calls chaining
	 */
	public synchronized InMemoryConnectionStore setTag(final String tag) {
		this.tag = StringUtil.normalizeLoggingTag(tag);
		return this;
	}

	/**
	 * Creates a new unused connection id.
	 * 
	 * @return connection id, or {@code null}, if no free connection id could
	 *         created
	 * @see #connectionIdGenerator
	 * @see ConnectionIdGenerator
	 */
	private ConnectionId newConnectionId() {
		for (int i = 0; i < 10; ++i) {
			ConnectionId cid = connectionIdGenerator.createConnectionId();
			if (connections.get(cid) == null) {
				return cid;
			}
		}
		return null;
	}

	@Override
	public void setConnectionListener(ConnectionListener listener) {
		this.connectionListener = listener;
	}

	@Override
	public void attach(ConnectionIdGenerator connectionIdGenerator) {
		if (this.connectionIdGenerator != null) {
			throw new IllegalStateException("Connection id generator already attached!");
		}
		if (connectionIdGenerator == null || !connectionIdGenerator.useConnectionId()) {
			int bits = Integer.SIZE - Integer.numberOfLeadingZeros(connections.getCapacity());
			int cidLength = ((bits + 7) / 8); // required bytes for capacity
			cidLength += (cidLength < 3) ? DEFAULT_SMALL_EXTRA_CID_LENGTH : DEFAULT_LARGE_EXTRA_CID_LENGTH;
			this.connectionIdGenerator = new SingleNodeConnectionIdGenerator(cidLength);
		} else {
			this.connectionIdGenerator = connectionIdGenerator;
		}
		if (sessionCache instanceof ClientSessionCache) {
			ClientSessionCache clientCache = (ClientSessionCache) sessionCache;
			LOG.debug("resume client sessions {}", clientCache);
			for (InetSocketAddress peer : clientCache) {
				SessionTicket ticket = clientCache.getSessionTicket(peer);
				SessionId id = clientCache.getSessionIdentity(peer);
				if (ticket != null && id != null) {
					// restore connection from session ticket
					Connection connection = new Connection(ticket, id, peer);
					ConnectionId connectionId = newConnectionId();
					if (connectionId != null) {
						connection.setConnectionId(connectionId);
						connections.put(connectionId, connection);
						connectionsByAddress.put(peer, connection);
						LOG.debug("{}resume {} {}", tag, peer, id);
					} else {
						LOG.info("{}drop session {} {}, could not allocated cid!", tag, peer, id);
					}
				}
			}
		}
		
	}
	

	/**
	 * {@inheritDoc}
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
	 */
	@Override
	public synchronized boolean put(final Connection connection) {

		if (connection != null) {
			if (!connection.isExecuting()) {
				throw new IllegalStateException("Connection is not executing!");
			}
			ConnectionId connectionId = connection.getConnectionId();
			if (connectionId == null) {
				if (connectionIdGenerator == null) {
					throw new IllegalStateException("Connection id generator must be attached before!");
				}
				connectionId = newConnectionId();
				if (connectionId == null) {
					throw new IllegalStateException("Connection ids exhausted!");
				}
				connection.setConnectionId(connectionId);
			} else if (connectionId.isEmpty()) {
				throw new IllegalStateException("Connection must have a none empty connection id!");
			} else if (connections.get(connectionId) != null) {
				throw new IllegalStateException("Connection id already used! " + connectionId);
			}
			if (connections.put(connectionId, connection)) {
				if (LOG.isTraceEnabled()) {
					LOG.trace("{}connection: add {} (size {})", tag, connection, connections.size(), new Throwable("connection added!"));
				} else {
					LOG.debug("{}connection: add {} (size {})", tag, connectionId, connections.size());
				}
				addToAddressConnections(connection);
				DTLSSession session = connection.getEstablishedSession();
				if (session != null) {
					putEstablishedSession(session, connection);
				}
				return true;
			} else {
				LOG.warn("{}connection store is full! {} max. entries.", tag, connections.getCapacity());
				return false;
			}
		} else {
			return false;
		}
	}

	@Override
	public synchronized boolean update(final Connection connection, InetSocketAddress newPeerAddress) {
		if (connection == null) {
			return false;
		}
		if (connections.update(connection.getConnectionId())) {
			InetSocketAddress effectiveNewPeerAddress = newPeerAddress;
			if (effectiveNewPeerAddress != null && connectionsByAddress.get(effectiveNewPeerAddress) == connection) {
				// update optional router address info
				connection.updatePeerAddress(newPeerAddress);
				effectiveNewPeerAddress = null;
			}
			if (effectiveNewPeerAddress == null) {
				LOG.debug("{}connection: {} updated usage!", tag, connection.getConnectionId());
			} else {
				InetSocketAddress oldPeerAddress = connection.getPeerAddress();
				LOG.debug("{}connection: {} updated, address changed from {} to {}!", tag, connection.getConnectionId(),
						oldPeerAddress, newPeerAddress);
				if (oldPeerAddress != null) {
					connectionsByAddress.remove(oldPeerAddress, connection);
					connection.updatePeerAddress(null);
				}
				connection.updatePeerAddress(effectiveNewPeerAddress);
				addToAddressConnections(connection);
			}
			return true;
		} else {
			LOG.debug("{}connection: {} - {} update failed!", tag, connection.getConnectionId(), newPeerAddress);
			return false;
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @deprecated since 2.3 obsolete, see {@link Connection#close(Record)}.
	 */
	@Deprecated
	@Override
	public synchronized boolean removeFromAddress(final Connection connection) {
		if (connection != null) {
			InetSocketAddress peerAddress = connection.getPeerAddress();
			if (peerAddress != null) {
				LOG.debug("{}connection: {} removed from address {}!", tag, connection.getConnectionId(), peerAddress);
				connectionsByAddress.remove(peerAddress, connection);
				connection.updatePeerAddress(null);
				return true;
			}
		}
		return false;
	}

	@Override
	public synchronized void putEstablishedSession(final DTLSSession session, final Connection connection) {
		ConnectionListener listener = connectionListener;
		if (listener != null) {
			listener.onConnectionEstablished(connection);
		}
		SessionId sessionId = session.getSessionIdentifier();
		if (!sessionId.isEmpty()) {
			if (sessionCache != null) {
				sessionCache.put(session);
			}
			final Connection previous = connectionsByEstablishedSession.put(sessionId, connection);
			if (previous != null && previous != connection) {
				Runnable removePreviousConnection = new Runnable() {

					@Override
					public void run() {
						remove(previous, false);
					}
				};
				if (previous.isExecuting()) {
					previous.getExecutor().execute(removePreviousConnection);
				} else {
					removePreviousConnection.run();
				}
			}
		}
	}

	@Override
	public synchronized void removeFromEstablishedSessions(final DTLSSession session, final Connection connection) {
		SessionId sessionId = session.getSessionIdentifier();
		if (!sessionId.isEmpty()) {
			connectionsByEstablishedSession.remove(sessionId, connection);
		}
	}

	@Override
	public synchronized Connection find(final SessionId id) {

		if (id == null || id.isEmpty()) {
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
					return new Connection(ticket, id, null);
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
			DTLSSession establishedSession = connection.getEstablishedSession();
			if (establishedSession != null) {
				if (!establishedSession.getSessionIdentifier().equals(id)) {
					LOG.warn("{}connection {} changed session {}!={}!", tag, connection.getConnectionId(), id,
							establishedSession.getSessionIdentifier());
				}
			} else {
				LOG.warn("{}connection {} lost session {}!", tag, connection.getConnectionId(), id);
			}
			connections.update(connection.getConnectionId());
		}
		return connection;
	}

	@Override
	public synchronized void markAllAsResumptionRequired() {
		for (Connection connection : connections.values()) {
			if (connection.getPeerAddress() != null && !connection.isResumptionRequired()) {
				connection.setResumptionRequired(true);
				LOG.debug("{}connection: mark for resumption {}!", tag, connection);
			}
		}
	}

	@Override
	public synchronized int remainingCapacity() {
		int remaining = connections.remainingCapacity();
		LOG.debug("{}connection: size {}, remaining {}!", tag, connections.size(), remaining);
		return remaining;
	}

	@Override
	public synchronized Connection get(final InetSocketAddress peerAddress) {
		Connection connection = connectionsByAddress.get(peerAddress);
		if (connection == null) {
			LOG.debug("{}connection: missing connection for {}!", tag, peerAddress);
		} else {
			InetSocketAddress address = connection.getPeerAddress();
			if (address == null) {
				LOG.warn("{}connection {} lost ip-address {}!", tag, connection.getConnectionId(), peerAddress);
			} else if (!address.equals(peerAddress)) {
				LOG.warn("{}connection {} changed ip-address {}!={}!", tag, connection.getConnectionId(), peerAddress, address);
			}
		}
		return connection;
	}

	@Override
	public synchronized Connection get(final ConnectionId cid) {
		Connection connection = connections.get(cid);
		if (connection == null) {
			LOG.debug("{}connection: missing connection for {}!", tag, cid);
		} else {
			ConnectionId connectionId = connection.getConnectionId();
			if (connectionId == null) {
				LOG.warn("{}connection lost cid {}!", tag,  cid);
			} else if (!connectionId.equals(cid)) {
				LOG.warn("{}connection changed cid {}!={}!", tag, connectionId, cid);
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
		boolean removed = connections.remove(connection.getConnectionId(), connection) == connection;
		if (removed) {
			List<Runnable> pendings = connection.getExecutor().shutdownNow();
			if (LOG.isTraceEnabled()) {
				LOG.trace("{}connection: remove {} (size {}, left jobs: {})", tag, connection, connections.size(),
						pendings.size(), new Throwable("connection removed!"));
			} else if (pendings.isEmpty()) {
				LOG.debug("{}connection: remove {} (size {})", tag, connection, connections.size());
			} else {
				LOG.debug("{}connection: remove {} (size {}, left jobs: {})", tag, connection, connections.size(),
						pendings.size());
			}
			removeFromEstablishedSessions(connection);
			removeFromAddressConnections(connection);
			if (removeFromSessionCache) {
				removeSessionFromCache(connection);
			}
			ConnectionListener listener = connectionListener;
			if (listener != null) {
				listener.onConnectionRemoved(connection);
			}
		}
		return removed;
	}

	private void removeFromEstablishedSessions(Connection connection) {
		DTLSSession establishedSession = connection.getEstablishedSession();
		if (establishedSession != null) {
			SessionId sessionId = establishedSession.getSessionIdentifier();
			connectionsByEstablishedSession.remove(sessionId, connection);
			SecretUtil.destroy(establishedSession);
		}
	}

	private void removeFromAddressConnections(Connection connection) {
		InetSocketAddress peerAddress = connection.getPeerAddress();
		if (peerAddress != null) {
			connectionsByAddress.remove(peerAddress, connection);
			connection.updatePeerAddress(null);
		}
	}

	private synchronized void removeSessionFromCache(final Connection connection) {
		if (sessionCache != null) {
			DTLSSession establishedSession = connection.getEstablishedSession();
			if (establishedSession != null) {
				SessionId sessionId = establishedSession.getSessionIdentifier();
				sessionCache.remove(sessionId);
			}
		}
	}

	private void addToAddressConnections(Connection connection) {
		final InetSocketAddress peerAddress = connection.getPeerAddress();
		if (peerAddress != null) {
			final Connection previous = connectionsByAddress.put(peerAddress, connection);
			if (previous != null && previous != connection) {
				Runnable removeAddress = new Runnable() {

					@Override
					public void run() {
						if (previous.equalsPeerAddress(peerAddress)) {
							previous.updatePeerAddress(null);
						}
					}
				};
				LOG.debug("{}connection: {} - {} added! {} removed from address.", tag, connection.getConnectionId(),
						peerAddress, previous.getConnectionId());
				if (previous.isExecuting()) {
					previous.getExecutor().execute(removeAddress);
				} else {
					removeAddress.run();
				}
			} else {
				LOG.debug("{}connection: {} - {} added!", tag, connection.getConnectionId(), peerAddress);
			}
		} else {
			LOG.debug("{}connection: {} - missing address!", tag, connection.getConnectionId());
		}
	}

	@Override
	public final synchronized void clear() {
		for (Connection connection : connections.values()) {
			SerialExecutor executor = connection.getExecutor();
			if (executor != null) {
				executor.shutdownNow();
			}
		}
		connections.clear();
		connectionsByEstablishedSession.clear();
		connectionsByAddress.clear();
		// TODO: does it make sense to clear the SessionCache as well?
	}

	@Override
	public final synchronized void stop(List<Runnable> pending) {
		for (Connection connection : connections.values()) {
			SerialExecutor executor = connection.getExecutor();
			if (executor != null) {
				executor.shutdownNow(pending);
			}
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see LeastRecentlyUsedCache#valuesIterator()
	 */
	@Override
	public Iterator<Connection> iterator() {
		return connections.valuesIterator();
	}

}
