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
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.DataStreamReader;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.LeastRecentlyUsedCache;
import org.eclipse.californium.elements.util.SerialExecutor;
import org.eclipse.californium.elements.util.SerializationUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.elements.util.WipAPI;
import org.eclipse.californium.scandium.ConnectionListener;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction;
import org.eclipse.californium.scandium.dtls.cipher.RandomManager;
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction.Label;
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
public class InMemoryConnectionStore implements ResumptionSupportingConnectionStore {

	private static final Logger LOGGER = LoggerFactory.getLogger(InMemoryConnectionStore.class);
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
							handshaker.handshakeFailed(new ConnectionEvictedException("Evicted!"));
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
		if (sessionCache instanceof ClientSessionCache) {
			ClientSessionCache clientCache = (ClientSessionCache) sessionCache;
			LOGGER.debug("{}resume client sessions {}", tag, clientCache);
			for (InetSocketAddress peer : clientCache) {
				SessionTicket ticket = clientCache.getSessionTicket(peer);
				SessionId id = clientCache.getSessionIdentity(peer);
				if (ticket != null && id != null) {
					// restore connection from session ticket
					Connection connection = new Connection(new DTLSSession(id, ticket), peer);
					ConnectionId connectionId = newConnectionId();
					if (connectionId != null) {
						connection.setConnectionId(connectionId);
						connections.put(connectionId, connection);
						connectionsByAddress.put(peer, connection);
						LOGGER.debug("{}resume {} {}", tag, StringUtil.toLog(peer), id);
					} else {
						LOGGER.info("{}drop session {} {}, could not allocated cid!", tag, StringUtil.toLog(peer), id);
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
				if (LOGGER.isTraceEnabled()) {
					LOGGER.trace("{}connection: add {} (size {})", tag, connection, connections.size(), new Throwable("connection added!"));
				} else {
					LOGGER.debug("{}connection: add {} (size {})", tag, connectionId, connections.size());
				}
				addToAddressConnections(connection);
				DTLSSession session = connection.getEstablishedSession();
				if (session != null) {
					putEstablishedSession(session, connection);
				}
				return true;
			} else {
				LOGGER.warn("{}connection store is full! {} max. entries.", tag, connections.getCapacity());
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
		connection.refreshAutoResumptionTime();
		if (connections.update(connection.getConnectionId())) {
			if (newPeerAddress == null) {
				LOGGER.debug("{}connection: {} updated usage!", tag, connection.getConnectionId());
			} else if (!connection.equalsPeerAddress(newPeerAddress)) {
				InetSocketAddress oldPeerAddress = connection.getPeerAddress();
				if (LOGGER.isTraceEnabled()) {
					LOGGER.trace("{}connection: {} updated, address changed from {} to {}!", tag,
							connection.getConnectionId(), StringUtil.toLog(oldPeerAddress), StringUtil.toLog(newPeerAddress),
							new Throwable("connection updated!"));
				} else {
					LOGGER.debug("{}connection: {} updated, address changed from {} to {}!", tag,
							connection.getConnectionId(), StringUtil.toLog(oldPeerAddress), StringUtil.toLog(newPeerAddress));
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
			LOGGER.debug("{}connection: {} - {} update failed!", tag, connection.getConnectionId(), StringUtil.toLog(newPeerAddress));
			return false;
		}
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
				if (sessionCache instanceof ClientSessionCache) {
					((ClientSessionCache)sessionCache).put(connection.getPeerAddress(), session);
				} else {
					sessionCache.put(session);
				}
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
					Connection connection = new Connection(new DTLSSession(id, ticket), null);
					SecretUtil.destroy(ticket);
					return connection;
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
		if (id == null) {
			throw new NullPointerException("DTLS Session ID must not be null!");
		}
		Connection connection = connectionsByEstablishedSession.get(id);
		if (connection != null) {
			DTLSSession establishedSession = connection.getEstablishedSession();
			if (establishedSession != null) {
				SessionId establishedId = establishedSession.getSessionIdentifier();
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
				LOGGER.debug("{}connection: mark for resumption {}!", tag, connection);
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
			LOGGER.debug("{}connection: missing connection for {}!", tag, StringUtil.toLog(peerAddress));
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
	public synchronized Connection get(final ConnectionId cid) {
		Connection connection = connections.get(cid);
		if (connection == null) {
			LOGGER.debug("{}connection: missing connection for {}!", tag, cid);
		} else {
			ConnectionId connectionId = connection.getConnectionId();
			if (connectionId == null) {
				LOGGER.warn("{}connection lost cid {}!", tag,  cid);
			} else if (!connectionId.equals(cid)) {
				LOGGER.warn("{}connection changed cid {}!={}!", tag, connectionId, cid);
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
			if (connection.isExecuting()) {
				List<Runnable> pendings = connection.getExecutor().shutdownNow();
				if (LOGGER.isTraceEnabled()) {
					LOGGER.trace("{}connection: remove {} (size {}, left jobs: {})", tag, connection, connections.size(),
							pendings.size(), new Throwable("connection removed!"));
				} else if (pendings.isEmpty()) {
					LOGGER.debug("{}connection: remove {} (size {})", tag, connection, connections.size());
				} else {
					LOGGER.debug("{}connection: remove {} (size {}, left jobs: {})", tag, connection, connections.size(),
							pendings.size());
				}
			} else {
				if (LOGGER.isTraceEnabled()) {
					LOGGER.trace("{}connection: remove {} (size {})", tag, connection, connections.size(),
							new Throwable("connection removed!"));
				} else {
					LOGGER.debug("{}connection: remove {} (size {})", tag, connection, connections.size());
				}
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
				LOGGER.debug("{}connection: {} - {} added! {} removed from address.", tag, connection.getConnectionId(),
						StringUtil.toLog(peerAddress), previous.getConnectionId());
				if (previous.isExecuting()) {
					previous.getExecutor().execute(removeAddress);
				} else {
					removeAddress.run();
				}
			} else {
				LOGGER.debug("{}connection: {} - {} added!", tag, connection.getConnectionId(), StringUtil.toLog(peerAddress));
			}
		} else {
			LOGGER.debug("{}connection: {} - missing address!", tag, connection.getConnectionId());
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

	@WipAPI
	public int saveConnections(OutputStream out, SecretKey password, long maxAgeInSeconds) throws IOException, GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		int count = 0;
		DatagramWriter writer = new DatagramWriter(4096);
		byte[] nonce = new byte[16];
		RandomManager.currentSecureRandom().nextBytes(nonce);
		byte[] data = PseudoRandomFunction.doPRF(
				CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256.getThreadLocalPseudoRandomFunctionMac(), password,
				Label.KEY_EXPANSION_LABEL, nonce, 16);
		SecretKey key = SecretUtil.create(data, "AES");
		MessageDigest messageDigest = CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256.getThreadLocalMacMessageDigest();
		try {
			long startMillis = System.currentTimeMillis();
			long startNanos = ClockUtil.nanoRealtime();
			synchronized (connections) {
				Iterator<LeastRecentlyUsedCache.Timestamped<Connection>> iterator = connections.timestampedIterator();
				while (iterator.hasNext()) {
					LeastRecentlyUsedCache.Timestamped<Connection> connection = iterator.next();
					long updateNanos = connection.getLastUpdate();
					long age = TimeUnit.NANOSECONDS.toSeconds(startNanos - updateNanos);
					if (age > maxAgeInSeconds) {
						LOGGER.trace("{}skip {} ts, {}s too aged!", tag, updateNanos, age);
					} else {
						LOGGER.trace("{}write {} ts, {}s ", tag, updateNanos, age);
						int position = writer.space(Short.SIZE);
						writer.writeLong(updateNanos, Long.SIZE);
						if (connection.getValue().write(writer)) {
							if (count == 0) {
								DatagramWriter writerHeader = new DatagramWriter(32);
								int positionHeader = writerHeader.space(Short.SIZE);
								writerHeader.writeVarBytes(nonce, Byte.SIZE);
								writerHeader.writeLong(startMillis, Long.SIZE);
								writerHeader.writeLong(startNanos, Long.SIZE);
								writerHeader.updateMessageDigest(positionHeader + 2, messageDigest);
								writerHeader.writeSize(positionHeader, Short.SIZE);
								writerHeader.writeTo(out);
								writerHeader.close();
								messageDigest.update(data);
							}
							AlgorithmParameterSpec parameterSpec = new IvParameterSpec(nonce);
							writer.encrypt(position + 2, cipher, parameterSpec, key);
							writer.updateMessageDigest(position + 2, messageDigest);
							writer.writeSize(position, Short.SIZE);
							writer.writeTo(out);
							increment(nonce);
							++count;
						} else {
							writer.reset();
						}
					}
				}
			}
		} finally {
			SecretUtil.destroy(key);
			Bytes.clear(data);
		}
		out.write(0);
		out.write(0);
		if (count > 0) {
			// digest
			byte[] digest = messageDigest.digest(nonce);
			writer.writeVarBytes(digest, Short.SIZE);
			writer.writeTo(out);
		}
		writer.close();
		clear();
		return count;
	}

	@WipAPI
	public int loadConnections(InputStream in, SecretKey password)
			throws GeneralSecurityException, IOException {
		Cipher cipher =  Cipher.getInstance("AES/CBC/PKCS5Padding");
		int count = 0;
		DataStreamReader reader = new DataStreamReader(in);
		int len = reader.read(Short.SIZE);
		if (len > 0) {
			boolean read = false;
			SecretKey key = null;
			try {
				MessageDigest messageDigest = CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256.getThreadLocalMacMessageDigest();
				DatagramReader rangeReader = reader.createRangeReader(len);
				rangeReader.updateMessageDigest(messageDigest);
				byte[] nonce = rangeReader.readVarBytes(Byte.SIZE);
				long millis = rangeReader.readLong(Long.SIZE);
				long nanos = rangeReader.readLong(Long.SIZE);
				if (rangeReader.bytesAvailable()) {
					throw new IOException("Invalid parameter block! " + (rangeReader.bitsLeft() / Byte.SIZE) + " bytes left!");
				}
				long startMillis = System.currentTimeMillis();
				long startNanos = ClockUtil.nanoRealtime();
				long delta1 = Math.max(TimeUnit.MILLISECONDS.toNanos(startMillis - millis), 0L);
				long delta2 = startNanos - nanos;
				long delta = delta2 - delta1;
				LOGGER.debug("{}delta {} {} => {}", tag, delta1, delta2, delta);
				byte[] data = PseudoRandomFunction.doPRF(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256.getThreadLocalPseudoRandomFunctionMac(), password,
						Label.KEY_EXPANSION_LABEL, nonce, 16);
				key = SecretUtil.create(data, "AES");
				messageDigest.update(data);
				Bytes.clear(data);
				while ((len = reader.read(Short.SIZE)) > 0) {
					rangeReader = reader.createRangeReader(len);
					rangeReader.updateMessageDigest(messageDigest);
					AlgorithmParameterSpec parameterSpec = new IvParameterSpec(nonce);
					rangeReader.decrypt(cipher, parameterSpec, key);
					long lastUpdate = rangeReader.readLong(Long.SIZE);
					long update = lastUpdate + delta;
					Connection connection = Connection.fromReader(rangeReader, delta, update);
					if (connection != null) {
						if (lastUpdate > nanos) {
							LOGGER.warn("{}read {} ts after {} ", tag, lastUpdate, nanos);
						}
						LOGGER.trace("{}read {} ts, {}s", tag, update,
								TimeUnit.NANOSECONDS.toSeconds(startNanos - update));
						restore(connection, update);
						increment(nonce);
						++count;
					}
				}
				byte[] readDigest = reader.readVarBytes(Short.SIZE);
				read = true;
				byte[] calculatedDigest = messageDigest.digest(nonce);
				if (!MessageDigest.isEqual(calculatedDigest, readDigest)) {
					LOGGER.error("{}MessageDigest failure ({} connections)!", tag, count);
					LOGGER.error("{}calc : {}", tag, StringUtil.byteArray2Hex(calculatedDigest));
					LOGGER.error("{}read : {}", tag, StringUtil.byteArray2Hex(readDigest));
					SimpleDateFormat format = new SimpleDateFormat("HH:mm:ss dd.MM.yyyy");
					LOGGER.error("{}nonce {} bytes, saved {}", tag, nonce.length, format.format(new Date(millis)));
					throw new GeneralSecurityException("MAC mismatch!");
				} else {
					LOGGER.debug("{}MessageDigest passed {} ({} connections)!", tag, StringUtil.byteArray2Hex(calculatedDigest), count);
				}
			} catch (IllegalStateException ex) {
				LOGGER.warn("{}reading failed after {} connections", tag, count, ex);
				// left connections
				SerializationUtil.skipBlocks(in, 0);
				// mac
				SerializationUtil.skipBlocks(in, 1);
				clear();
				throw ex;
			} catch (GeneralSecurityException ex) {
				if (!read) {
					LOGGER.warn("{}reading failed after {} connections", tag, count, ex);
					// left connections
					SerializationUtil.skipBlocks(in, 0);
					// mac
					SerializationUtil.skipBlocks(in, 1);
				}
				clear();
				throw ex;
			} finally {
				SecretUtil.destroy(key);
			}
		}
		return count;
	}

	private boolean restore(final Connection connection, long lastUsage) {

		ConnectionId connectionId = connection.getConnectionId();
		if (connectionId == null) {
			throw new IllegalStateException("Connection must have a connection id!");
		} else if (connectionId.isEmpty()) {
			throw new IllegalStateException("Connection must have a none empty connection id!");
		} else if (connections.get(connectionId) != null) {
			throw new IllegalStateException("Connection id already used! " + connectionId);
		}
		LeastRecentlyUsedCache.Timestamped<Connection> timestamped = new LeastRecentlyUsedCache.Timestamped<>(connection, lastUsage);
		synchronized (connections) {
			if (connections.put(connectionId, timestamped)) {
				if (LOGGER.isTraceEnabled()) {
					LOGGER.trace("{}connection: add {} (size {})", tag, connection, connections.size(),
							new Throwable("connection added!"));
				} else {
					LOGGER.debug("{}connection: add {} (size {})", tag, connectionId, connections.size());
				}
				addToAddressConnections(connection);
				DTLSSession session = connection.getEstablishedSession();
				if (session != null) {
					putEstablishedSession(session, connection);
				}
				return true;
			} else {
				LOGGER.warn("{}connection store is full! {} max. entries.", tag, connections.getCapacity());
				return false;
			}
		}
	}

	private static void increment(byte[] nonce) {
		for (int pos = 0; pos < nonce.length; ++pos) {
			if (++nonce[pos] != 0) {
				break;
			}
		}
	}

}
