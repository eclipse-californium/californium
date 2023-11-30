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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.DataStreamReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.FilteredLogger;
import org.eclipse.californium.elements.util.LeastRecentlyUsedCache;
import org.eclipse.californium.elements.util.LeastRecentlyUsedCache.Timestamped;
import org.eclipse.californium.elements.util.SerialExecutor;
import org.eclipse.californium.elements.util.SerializationUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.ConnectionListener;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An in-memory {@code ResumptionSupportingConnectionStore} with a
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
 * This implementation uses three {@code java.util.HashMap}. One with a
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
 * Supports also a {@link SessionStore} implementation to keep sessions for
 * longer or in a distribute system. If the connection store evicts a connection
 * in order to gain storage for new connections, the associated session remains
 * in the session store. Therefore the session store requires a own, independent
 * cleanup for stale sessions. If a connection is removed by a critical ALERT,
 * the session get's removed also from the session store.
 * </p>
 * @deprecated please migrate to {@link InMemoryReadWriteLockConnectionStore}
 */
@Deprecated
public class InMemoryConnectionStore implements ResumptionSupportingConnectionStore {

	private static final Logger LOGGER = LoggerFactory.getLogger(InMemoryConnectionStore.class);
	private static final FilteredLogger WARN_FILTER = new FilteredLogger(LOGGER.getName(), 3, TimeUnit.SECONDS.toNanos(10));

	// extra cid bytes additionally to required bytes for small capacity.
	private static final int DEFAULT_SMALL_EXTRA_CID_LENGTH = 2;
	 // extra cid bytes additionally to required bytes for large capacity.
	private static final int DEFAULT_LARGE_EXTRA_CID_LENGTH = 3;
	private static final int DEFAULT_CACHE_SIZE = 150000;
	private static final long DEFAULT_EXPIRATION_THRESHOLD = 36 * 60 * 60; // 36h
	private static boolean SINGLE_SESSION_STORE = true;
	private final SessionStore sessionStore;
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
	 * @param sessionStore a second level store to use for <em>current</em>
	 *            connection state of established DTLS sessions.
	 */
	public InMemoryConnectionStore(final SessionStore sessionStore) {
		this(DEFAULT_CACHE_SIZE, DEFAULT_EXPIRATION_THRESHOLD, sessionStore);
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
	 * @param sessionStore a second level store to use for <em>current</em>
	 *            connection state of established DTLS sessions.
	 */
	public InMemoryConnectionStore(int capacity, long threshold, SessionStore sessionStore) {
		this.connections = new LeastRecentlyUsedCache<>(capacity, threshold);
		this.connections.setEvictingOnReadAccess(false);
		this.connections.setUpdatingOnReadAccess(false);
		this.connectionsByAddress = new ConcurrentHashMap<>();
		this.sessionStore = sessionStore;
		if (SINGLE_SESSION_STORE && sessionStore != null) {
			this.connectionsByEstablishedSession = null;
		} else {
			this.connectionsByEstablishedSession = new ConcurrentHashMap<>();
		}
		// make sure that stale (evicted) connection is removed from other maps.
		connections.addEvictionListener(new LeastRecentlyUsedCache.EvictionListener<Connection>() {

			@Override
			public void onEviction(final Connection staleConnection) {
				Runnable remove = new Runnable() {

					@Override
					public void run() {
						Handshaker handshaker = staleConnection.getOngoingHandshake();
						if (handshaker != null) {
							handshaker.handshakeFailed(new ConnectionEvictedException("Evicted!"));
						}
						synchronized (InMemoryConnectionStore.this) {
							removeByAddressConnections(staleConnection);
							removeByEstablishedSessions(staleConnection.getEstablishedSessionIdentifier(), staleConnection);
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

		LOGGER.info("Created new InMemoryConnectionStore [capacity: {}, connection expiration threshold: {}s]",
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
	public boolean put(final Connection connection) {
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
			DTLSSession session = connection.getEstablishedSession();
			boolean success = false;
			synchronized (this) {
				if (connections.put(connectionId, connection)) {
					if (LOGGER.isTraceEnabled()) {
						LOGGER.trace("{}connection: add {} (size {})", tag, connection, connections.size(),
								new Throwable("connection added!"));
					} else {
						LOGGER.debug("{}connection: add {} (size {})", tag, connectionId, connections.size());
					}
					addToAddressConnections(connection);
					if (session != null) {
						addToEstablishedConnections(session.getSessionIdentifier(), connection);
					}
					success = true;
				} else {
					WARN_FILTER.debug("{}connection store is full! {} max. entries.", tag, connections.getCapacity());
				}
			}
			if (success && sessionStore != null && session != null) {
				sessionStore.put(session);
			}
			return success;
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
			connection.refreshAutoResumptionTime();
			if (newPeerAddress == null) {
				LOGGER.debug("{}connection: {} updated usage!", tag, connection.getConnectionId());
			} else if (!connection.equalsPeerAddress(newPeerAddress)) {
				InetSocketAddress oldPeerAddress = connection.getPeerAddress();
				if (LOGGER.isTraceEnabled()) {
					LOGGER.trace("{}connection: {} updated, address changed from {} to {}!", tag,
							connection.getConnectionId(), StringUtil.toLog(oldPeerAddress),
							StringUtil.toLog(newPeerAddress), new Throwable("connection updated!"));
				} else {
					LOGGER.debug("{}connection: {} updated, address changed from {} to {}!", tag,
							connection.getConnectionId(), StringUtil.toLog(oldPeerAddress),
							StringUtil.toLog(newPeerAddress));
				}
				if (oldPeerAddress != null) {
					connectionsByAddress.remove(oldPeerAddress, connection);
					connection.updatePeerAddress(null);
				}
				connection.updatePeerAddress(newPeerAddress);
				addToAddressConnections(connection);
			}
			return true;
		} else {
			LOGGER.debug("{}connection: {} - {} update failed!", tag, connection.getConnectionId(),
					StringUtil.toLog(newPeerAddress));
			return false;
		}
	}

	@Override
	public void putEstablishedSession(Connection connection) {
		DTLSSession session = connection.getEstablishedSession();
		if (session == null) {
			throw new IllegalArgumentException("connection has no established session!");
		}
		ConnectionListener listener = connectionListener;
		if (listener != null) {
			listener.onConnectionEstablished(connection);
		}
		SessionId sessionId = session.getSessionIdentifier();
		if (!sessionId.isEmpty()) {
			synchronized (this) {
				addToEstablishedConnections(sessionId, connection);
			}
			if (sessionStore != null) {
				sessionStore.put(session);
			}
		}
	}

	@Override
	public synchronized void removeFromEstablishedSessions(Connection connection) {
		SessionId sessionId = connection.getEstablishedSessionIdentifier();
		if (sessionId == null) {
			throw new IllegalArgumentException("connection has no established session!");
		}
		removeByEstablishedSessions(sessionId, connection);
	}

	@Override
	public DTLSSession find(SessionId id) {

		if (id == null || id.isEmpty()) {
			return null;
		} else {
			DTLSSession session = null;
			if (sessionStore != null) {
				session = sessionStore.get(id);
			}
			synchronized (this) {
				Connection connection = findLocally(id);
				if (connection != null) {
					if (sessionStore == null) {
						DTLSSession establishedSession = connection.getEstablishedSession();
						if (establishedSession != null) {
							session = new DTLSSession(establishedSession);
						}
					} else if (session == null) {
						// remove corresponding connection from this store
						remove(connection, false);
						return null;
					}
				}
			}
			return session;
		}
	}

	private Connection findLocally(final SessionId id) {
		if (id == null) {
			throw new NullPointerException("DTLS Session ID must not be null!");
		}
		if (connectionsByEstablishedSession == null) {
			return null;
		}
		Connection connection = connectionsByEstablishedSession.get(id);
		if (connection != null) {
			SessionId establishedId = connection.getEstablishedSessionIdentifier();
			if (establishedId != null) {
				if (!id.equals(establishedId)) {
					LOGGER.warn("{}connection {} changed session {}!={}!", tag, connection.getConnectionId(), id,
							establishedId);
				}
			} else {
				LOGGER.warn("{}connection {} lost session {}!", tag, connection.getConnectionId(), id);
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
				LOGGER.trace("{}connection: mark for resumption {}!", tag, connection);
			}
		}
	}

	@Override
	public synchronized int remainingCapacity() {
		int remaining = connections.remainingCapacity();
		LOGGER.debug("{}connection: size {}, remaining {}!", tag, connections.size(), remaining);
		return remaining;
	}

	@Override
	public synchronized Connection get(final InetSocketAddress peerAddress) {
		Connection connection = connectionsByAddress.get(peerAddress);
		if (connection == null) {
			LOGGER.trace("{}connection: missing connection for {}!", tag, StringUtil.toLog(peerAddress));
		} else {
			InetSocketAddress address = connection.getPeerAddress();
			if (address == null) {
				LOGGER.warn("{}connection {} lost ip-address {}!", tag, connection.getConnectionId(),
						StringUtil.toLog(peerAddress));
			} else if (!address.equals(peerAddress)) {
				LOGGER.warn("{}connection {} changed ip-address {}!={}!", tag, connection.getConnectionId(),
						StringUtil.toLog(peerAddress), StringUtil.toLog(address));
			}
		}
		return connection;
	}

	@Override
	public Connection get(ConnectionId cid) {
		Connection connection;
		synchronized (this) {
			connection = connections.get(cid);
		}
		if (connection == null) {
			LOGGER.debug("{}connection: missing connection for {}!", tag, cid);
		} else {
			ConnectionId connectionId = connection.getConnectionId();
			if (connectionId == null) {
				LOGGER.warn("{}connection lost cid {}!", tag, cid);
			} else if (!connectionId.equals(cid)) {
				LOGGER.warn("{}connection changed cid {}!={}!", tag, connectionId, cid);
			}
		}
		return connection;
	}

	@Override
	public boolean remove(final Connection connection, final boolean removeFromSessionCache) {
		boolean removed;
		SessionId sessionId = connection.getEstablishedSessionIdentifier();
		synchronized (this) {
			removed = connections.remove(connection.getConnectionId(), connection) == connection;
			if (removed) {
				int pendings = connection.shutdown();
				if (LOGGER.isTraceEnabled()) {
					LOGGER.trace("{}connection: remove {} (size {}, left jobs: {})", tag, connection,
							connections.size(), pendings, new Throwable("connection removed!"));
				} else if (pendings == 0) {
					LOGGER.debug("{}connection: remove {} (size {})", tag, connection, connections.size());
				} else {
					LOGGER.debug("{}connection: remove {} (size {}, left jobs: {})", tag, connection,
							connections.size(), pendings);
				}
				connection.startByClientHello(null);
				removeByAddressConnections(connection);
				removeByEstablishedSessions(sessionId, connection);
				ConnectionListener listener = connectionListener;
				if (listener != null) {
					listener.onConnectionRemoved(connection);
				}
				// destroy keys.
				SecretUtil.destroy(connection.getDtlsContext());
			}
		}
		if (removeFromSessionCache) {
			removeSessionFromStore(sessionId);
		}
		return removed;
	}

	private void removeByEstablishedSessions(SessionId sessionId, Connection connection) {
		if (connectionsByEstablishedSession != null && sessionId != null && !sessionId.isEmpty()) {
			connectionsByEstablishedSession.remove(sessionId, connection);
		}
	}

	private void removeByAddressConnections(Connection connection) {
		InetSocketAddress peerAddress = connection.getPeerAddress();
		if (peerAddress != null) {
			connectionsByAddress.remove(peerAddress, connection);
			connection.updatePeerAddress(null);
		}
	}

	private void removeSessionFromStore(SessionId sessionId) {
		if (sessionStore != null  && sessionId != null && !sessionId.isEmpty()) {
			sessionStore.remove(sessionId);
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
							if (connectionsByEstablishedSession == null) {
								if (!previous.expectCid()) {
									remove(previous, false);
								}
							}
						}
					}
				};
				LOGGER.debug("{}connection: {} - {} added! {} removed from address.", tag, connection.getConnectionId(),
						StringUtil.toLog(peerAddress), previous.getConnectionId());
				if (previous.isExecuting()) {
					previous.getExecutor().execute(removeAddress);
				} else {
					removeAddress.run();
				}
			} else {
				LOGGER.debug("{}connection: {} - {} added!", tag, connection.getConnectionId(),
						StringUtil.toLog(peerAddress));
			}
		} else {
			LOGGER.debug("{}connection: {} - missing address!", tag, connection.getConnectionId());
		}
	}

	private void addToEstablishedConnections(SessionId sessionId, Connection connection) {
		if (connectionsByEstablishedSession != null) {
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
	public final synchronized void clear() {
		for (Connection connection : connections.values()) {
			SerialExecutor executor = connection.getExecutor();
			if (executor != null) {
				executor.shutdownNow();
			}
		}
		connections.clear();
		if (connectionsByEstablishedSession != null) {
			connectionsByEstablishedSession.clear();
		}
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
	 * @see LeastRecentlyUsedCache#valuesIterator(boolean)
	 */
	@Override
	public Iterator<Connection> iterator() {
		return connections.valuesIterator(false);
	}

	@Override
	public int saveConnections(OutputStream out, long maxQuietPeriodInSeconds) throws IOException {
		int size = connections.size();
		int progress = size / 20;
		int count = 0;
		DatagramWriter writer = new DatagramWriter(4096);
		long startNanos = ClockUtil.nanoRealtime();
		boolean writeProgress = false;
		long progressNanos = startNanos;
		synchronized (connections) {
			Iterator<Timestamped<Connection>> iterator = connections.timestampedIterator();
			while (iterator.hasNext()) {
				Timestamped<Connection> connection = iterator.next();
				long updateNanos = connection.getLastUpdate();
				long quiet = TimeUnit.NANOSECONDS.toSeconds(startNanos - updateNanos);
				if (quiet > maxQuietPeriodInSeconds) {
					LOGGER.trace("{}skip {} ts, {}s too quiet!", tag, updateNanos, quiet);
				} else {
					LOGGER.trace("{}write {} ts, {}s ", tag, updateNanos, quiet);
					if (connection.getValue().writeTo(writer)) {
						writer.writeTo(out);
						++count;
					} else {
						writer.reset();
					}
					if (progress > 100 && (count % progress) == 0) {
						writeProgress = true;
					}
					if (writeProgress) {
						long now = ClockUtil.nanoRealtime();
						if (writeProgress && (now - progressNanos) > TimeUnit.SECONDS.toNanos(2)) {
							LOGGER.info("{}written {} connections of {}", tag, count, size);
							writeProgress = false;
							progressNanos = now;
						}
					}
				}
			}
		}
		SerializationUtil.writeNoItem(out);
		out.flush();
		writer.close();
		clear();
		return count;
	}

	@Override
	public int loadConnections(InputStream in, long delta) throws IOException {
		boolean clear = true;
		int count = 0;
		long startNanos = ClockUtil.nanoRealtime();
		DataStreamReader reader = new DataStreamReader(in);
		long progressNanos = startNanos;
		try {
			Connection connection;
			while ((connection = Connection.fromReader(reader, delta)) != null) {
				long lastUpdate = connection.getLastMessageNanos();
				if (lastUpdate - startNanos > 0) {
					WARN_FILTER.warn("{}read {} ts is after {} (future)", tag, lastUpdate, startNanos);
				}
				LOGGER.trace("{}read {} ts, {}s", tag, lastUpdate,
						TimeUnit.NANOSECONDS.toSeconds(startNanos - lastUpdate));
				restore(connection);
				++count;
				long now = ClockUtil.nanoRealtime();
				if ((now - progressNanos) > TimeUnit.SECONDS.toNanos(2)) {
					LOGGER.info("{}read {} connections", tag, count);
					progressNanos = now;
				}
			}
			clear = false;
		} catch (IllegalArgumentException ex) {
			LOGGER.warn("{}reading failed after {} connections", tag, count, ex);
			clear();
			throw ex;
		} finally {
			if (clear) {
				clear();
				count = 0;
			}
		}
		return count;
	}

	@Override
	public boolean restore(Connection connection) {

		ConnectionId connectionId = connection.getConnectionId();
		if (connectionId == null) {
			throw new IllegalStateException("Connection must have a connection id!");
		} else if (connectionId.isEmpty()) {
			throw new IllegalStateException("Connection must have a none empty connection id!");
		} else if (connections.get(connectionId) != null) {
			throw new IllegalStateException("Connection id already used! " + connectionId);
		}
		boolean restored = false;
		synchronized (connections) {
			if (connections.put(connectionId, connection, connection.getLastMessageNanos())) {
				if (LOGGER.isTraceEnabled()) {
					LOGGER.trace("{}connection: add {} (size {})", tag, connection, connections.size(),
							new Throwable("connection added!"));
				} else {
					LOGGER.debug("{}connection: add {} (size {})", tag, connectionId, connections.size());
				}
				addToAddressConnections(connection);
				restored = true;
			} else {
				LOGGER.warn("{}connection store is full! {} max. entries.", tag, connections.getCapacity());
			}
		}
		if (restored && connection.hasEstablishedDtlsContext()) {
			putEstablishedSession(connection);
		}
		return restored;
	}
}
