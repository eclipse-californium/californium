/*******************************************************************************
 * Copyright (c) 2022 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial creation
 *                    Derived from InMemoryConnectionStore
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantReadWriteLock.ReadLock;
import java.util.concurrent.locks.ReentrantReadWriteLock.WriteLock;

import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.DataStreamReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.FilteredLogger;
import org.eclipse.californium.elements.util.LeastRecentlyUpdatedCache;
import org.eclipse.californium.elements.util.LeastRecentlyUpdatedCache.Timestamped;
import org.eclipse.californium.elements.util.SerialExecutor;
import org.eclipse.californium.elements.util.SerializationUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.ConnectionListener;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An in-memory {@code ReadWriteLockConnectionStore} with a configurable maximum
 * capacity and support for evicting stale connections based on a <em>least
 * recently update</em> policy.
 * <p>
 * The store keeps track of the connections' last-access time automatically.
 * Every time a verified record is received or a record is sent for a
 * connection, the access-time is updated.
 * </p>
 * <p>
 * A connection can be successfully added to the store if any of the following
 * conditions is met:
 * </p>
 * <ul>
 * <li>The store's remaining capacity is greater than zero.</li>
 * <li>The store contains at least one <em>stale</em> connection, i.e. a
 * connection that has not been updated for at least the store's <em> connection
 * expiration threshold</em> period. In such a case the least recently updated
 * stale connection gets evicted from the store to make place for the new
 * connection to be added.</li>
 * </ul>
 * <p>
 * This implementation uses four {@code java.util.HashMap}. One with a
 * connection's id as key as its backing store, one with the peer address as
 * key, one with the session id as key, and one with the principal as key. In
 * addition to that the store keeps a doubly-linked list of the connections in
 * update-time order.
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
 * 
 * @since 3.5
 */
public class InMemoryReadWriteLockConnectionStore implements ReadWriteLockConnectionStore {

	private static final Logger LOGGER = LoggerFactory.getLogger(InMemoryReadWriteLockConnectionStore.class);
	private static final FilteredLogger WARN_FILTER = new FilteredLogger(LOGGER.getName(), 3, TimeUnit.SECONDS.toNanos(10));

	// extra cid bytes additionally to required bytes for small capacity.
	private static final int DEFAULT_SMALL_EXTRA_CID_LENGTH = 2;
	// extra cid bytes additionally to required bytes for large capacity.
	private static final int DEFAULT_LARGE_EXTRA_CID_LENGTH = 3;
	private static boolean SINGLE_SESSION_STORE = true;
	private final SessionStore sessionStore;
	protected final LeastRecentlyUpdatedCache<ConnectionId, Connection> connections;
	protected final ConcurrentMap<InetSocketAddress, Connection> connectionsByAddress;
	protected final ConcurrentMap<SessionId, Connection> connectionsByEstablishedSession;
	protected final ConcurrentMap<Principal, Connection> connectionsByPrincipal;
	private final AtomicBoolean shrinking = new AtomicBoolean();
	private volatile long shrinkTime;

	private volatile ExecutorService executor;
	private ConnectionListener connectionListener;

	/**
	 * Connection id generator.
	 * 
	 * @see #attach(ConnectionIdGenerator)
	 */
	private ConnectionIdGenerator connectionIdGenerator;

	protected String tag = "";

	/**
	 * Creates a store based on given configuration parameters.
	 * 
	 * @param capacity the maximum number of connections the store can manage
	 * @param threshold the period of time of inactivity (in seconds) after
	 *            which a connection is considered stale and can be evicted from
	 *            the store if a new connection is to be added to the store
	 * @param sessionStore a second level store to use for <em>current</em>
	 *            connection state of established DTLS sessions.
	 * @param uniquePrincipals {@code true}, to limit stale connections by
	 *            unique principals, {@code false}, if not.
	 */
	public InMemoryReadWriteLockConnectionStore(int capacity, long threshold, SessionStore sessionStore,
			boolean uniquePrincipals) {
		this.connections = new LeastRecentlyUpdatedCache<>(capacity, threshold, TimeUnit.SECONDS);
		this.connectionsByAddress = new ConcurrentHashMap<>();
		this.connectionsByPrincipal = uniquePrincipals ? new ConcurrentHashMap<Principal, Connection>() : null;
		this.sessionStore = sessionStore;
		if (SINGLE_SESSION_STORE && sessionStore != null) {
			this.connectionsByEstablishedSession = null;
		} else {
			this.connectionsByEstablishedSession = new ConcurrentHashMap<>();
		}
		// make sure that stale (evicted) connection is removed from other maps.
		connections.addEvictionListener(new LeastRecentlyUpdatedCache.EvictionListener<Connection>() {

			@Override
			public void onEviction(final Connection staleConnection) {
				Runnable remove = new Runnable() {

					@Override
					public void run() {
						Handshaker handshaker = staleConnection.getOngoingHandshake();
						if (handshaker != null) {
							handshaker.handshakeFailed(new ConnectionEvictedException("Evicted!"));
						}
						synchronized (InMemoryReadWriteLockConnectionStore.this) {
							removeByAddressConnections(staleConnection);
							removeByEstablishedSessions(staleConnection.getEstablishedSessionIdentifier(),
									staleConnection);
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
	public synchronized InMemoryReadWriteLockConnectionStore setTag(final String tag) {
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
	public ReadLock readLock() {
		return connections.readLock();
	}

	@Override
	public WriteLock writeLock() {
		return connections.writeLock();
	}

	@Override
	public void setConnectionListener(ConnectionListener listener) {
		this.connectionListener = listener;
	}

	@Override
	public void setExecutor(ExecutorService executor) {
		this.executor = executor;
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
			connections.writeLock().lock();
			try {
				if (connections.put(connectionId, connection)) {
					if (LOGGER.isTraceEnabled()) {
						LOGGER.trace("{}connection: add {} (size {})", tag, connection, connections.size(),
								new Throwable("connection added!"));
					} else {
						LOGGER.debug("{}connection: add {} (size {})", tag, connectionId, connections.size());
					}
					addToAddressConnections(connection);
					if (session != null) {
						if (session.getPeerIdentity() != null) {
							addToPrincipalsConnections(session.getPeerIdentity(), connection, false);
						}
						addToEstablishedConnections(session.getSessionIdentifier(), connection);
					}
					success = true;
				} else {
					WARN_FILTER.debug("{}connection store is full! {} max. entries.", tag, connections.getCapacity());
				}
			} finally {
				connections.writeLock().unlock();
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
	public boolean update(final Connection connection, InetSocketAddress newPeerAddress) {
		if (connection == null) {
			return false;
		}
		connections.writeLock().lock();
		try {
			if (connections.update(connection.getConnectionId()) != null) {
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
		} finally {
			connections.writeLock().unlock();
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
		Principal principal = session.getPeerIdentity();
		SessionId sessionId = session.getSessionIdentifier();
		boolean hasSessionId = !sessionId.isEmpty();
		if (principal != null || hasSessionId) {
			connections.writeLock().lock();
			try {
				if (principal != null) {
					addToPrincipalsConnections(principal, connection, false);
				}
				if (hasSessionId) {
					addToEstablishedConnections(sessionId, connection);
				}
			} finally {
				connections.writeLock().unlock();
			}
			if (hasSessionId && sessionStore != null) {
				sessionStore.put(session);
			}
		}
	}

	@Override
	public void removeFromEstablishedSessions(Connection connection) {
		SessionId sessionId = connection.getEstablishedSessionIdentifier();
		if (sessionId == null) {
			throw new IllegalArgumentException("connection has no established session!");
		}
		connections.writeLock().lock();
		try {
			removeByEstablishedSessions(sessionId, connection);
		} finally {
			connections.writeLock().unlock();
		}
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
	public void markAllAsResumptionRequired() {
		for (Connection connection : connections.values()) {
			if (connection.getPeerAddress() != null && !connection.isResumptionRequired()) {
				connection.setResumptionRequired(true);
				LOGGER.trace("{}connection: mark for resumption {}!", tag, connection);
			}
		}
	}

	@Override
	public int remainingCapacity() {
		int remaining = connections.remainingCapacity();
		LOGGER.debug("{}connection: size {}, remaining {}!", tag, connections.size(), remaining);
		return remaining;
	}

	@Override
	public void shrink(int calls, AtomicBoolean running) {
		if (connectionsByPrincipal != null) {
			int size = connections.size();
			if (1024 < size) {
				int unique = connectionsByPrincipal.size();
				if (unique * 2 < size || (calls % 12 == 9)) {
					if (shrinking.compareAndSet(false, true)) {
						LOGGER.info("{}: start shrinking {}/{}", tag, unique, size);
						shrink(running, false);
					} else {
						LOGGER.info("{}: shrinking {}/{} ...", tag, unique, size);
					}
				} else {
					LOGGER.info("{}: no shrinking {}/{}", tag, unique, size);
				}
			}
		}
	}

	private void shrink(AtomicBoolean running, boolean full) {
		int loops = 0;
		int count = 0;
		int log = Math.max(10000, connections.size() / 5);
		Throwable error = null;
		shrinkTime = ClockUtil.nanoRealtime();
		Iterator<Connection> iterator = connections.ascendingIterator();
		try {
			while (running.get() && iterator.hasNext()) {
				final Connection connection = iterator.next();
				if ((++loops % log) == 0) {
					LOGGER.info("{}shrink {}: {}", tag, loops, connection.getConnectionId());
				}
				if (connection.isDouble()) {
					if (connections.isStale(connection.getConnectionId())) {
						Runnable removeConnection = new Runnable() {

							@Override
							public void run() {
								LOGGER.trace("{}Remove connection from stale principals", tag);
								remove(connection, false);
							}
						};
						if (connection.isExecuting()) {
							connection.getExecutor().execute(removeConnection);
						} else {
							remove(connection, false);
						}
						++count;
					} else if (!full) {
						break;
					}
				}
			}
		} catch (Throwable ex) {
			error = ex;
		} finally {
			shrinkTime = ClockUtil.nanoRealtime() - shrinkTime;
			int size = connections.size();
			int unique = connectionsByPrincipal.size();
			if (error != null) {
				LOGGER.error("{}: shrinking failed, {} of {}/{} in {} ms", tag, count, unique, size,
						TimeUnit.NANOSECONDS.toMillis(shrinkTime), error);
			} else if (count > 0) {
				LOGGER.info("{}: shrinked {} of {}/{} in {} ms", tag, count, unique, size,
						TimeUnit.NANOSECONDS.toMillis(shrinkTime), error);
			} else {
				LOGGER.info("{}: nothing shrinked, {}/{} in {} ms", tag, unique, size,
						TimeUnit.NANOSECONDS.toMillis(shrinkTime), error);
			}
			shrinking.set(false);
		}
	}

	@Override
	public Connection get(InetSocketAddress peerAddress) {
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
		Connection connection = connections.get(cid);
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
		DTLSSession session = connection.getEstablishedSession();
		SessionId sessionId = session == null ? null : session.getSessionIdentifier();
		Principal principal = session == null ? null : session.getPeerIdentity();
		connections.writeLock().lock();
		try {
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
				removeByPrincipal(principal, connection);
				ConnectionListener listener = connectionListener;
				if (listener != null) {
					listener.onConnectionRemoved(connection);
				}
				// destroy keys.
				SecretUtil.destroy(connection.getDtlsContext());
			}
		} finally {
			connections.writeLock().unlock();
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

	private void removeByPrincipal(Principal principal, Connection connection) {
		if (connectionsByPrincipal != null && principal != null) {
			connectionsByPrincipal.remove(principal, connection);
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
		if (sessionStore != null && sessionId != null && !sessionId.isEmpty()) {
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

	private boolean addToEstablishedConnections(SessionId sessionId, Connection connection) {
		if (connectionsByEstablishedSession != null) {
			final Connection previous = connectionsByEstablishedSession.put(sessionId, connection);
			if (previous != null && previous != connection) {
				removePreviousConnection("session", previous);
				return true;
			}
		}
		return false;
	}

	private boolean addToPrincipalsConnections(Principal principal, Connection connection, boolean removePrevious) {
		if (connectionsByPrincipal != null) {
			final Connection previous = connectionsByPrincipal.put(principal, connection);
			if (previous != null && previous != connection) {
				if (removePrevious) {
					removePreviousConnection("principal", previous);
					return true;
				} else {
					previous.setDouble();
					// replace principal, GC the old one.
					previous.getEstablishedSession().setPeerIdentity(principal);
				}
			}
		}
		return false;
	}

	private void removePreviousConnection(final String cause, final Connection connection) {
		Runnable removePreviousConnection = new Runnable() {

			@Override
			public void run() {
				LOGGER.debug("{}Remove connection from {}", tag, cause);
				remove(connection, false);
			}
		};
		if (connection.isExecuting()) {
			connection.getExecutor().execute(removePreviousConnection);
		} else {
			removePreviousConnection.run();
		}
	}

	@Override
	public final void clear() {
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
	public final void stop(List<Runnable> pending) {
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
	 * @see LeastRecentlyUpdatedCache#valuesIterator()
	 */
	@Override
	public Iterator<Connection> iterator() {
		return connections.valuesIterator();
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
				boolean restore = true;
				long lastUpdate = connection.getLastMessageNanos();
				if (lastUpdate - startNanos > 0) {
					WARN_FILTER.warn("{}read {} ts is after {} (future)", tag, lastUpdate, startNanos);
				} else if (connection.isDouble()) {
					restore = !connections.isStale(connection.getConnectionId());
				}
				if (restore) {
					LOGGER.trace("{}read {} ts, {}s", tag, lastUpdate,
							TimeUnit.NANOSECONDS.toSeconds(startNanos - lastUpdate));
					restore(connection);
					++count;
				}
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
		connections.writeLock().lock();
		try {
			if (connections.put(connectionId, connection, connection.getLastMessageNanos())) {
				if (LOGGER.isTraceEnabled()) {
					LOGGER.trace("{}connection: add {} (size {})", tag, connection, connections.size(),
							new Throwable("connection added!"));
				} else {
					LOGGER.debug("{}connection: add {} (size {})", tag, connectionId, connections.size());
				}
				addToAddressConnections(connection);
				if (!connection.isExecuting()) {
					connection.setConnectorContext(executor, connectionListener);
				}
				restored = true;
			} else {
				LOGGER.warn("{}connection store is full! {} max. entries.", tag, connections.getCapacity());
			}
		} finally {
			connections.writeLock().unlock();
		}
		if (restored && connection.hasEstablishedDtlsContext()) {
			putEstablishedSession(connection);
		}
		return restored;
	}

}
