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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add support for terminating a handshake
 *    Bosch Software Innovations GmbH - add constructor based on current connection state
 *    Achim Kraus (Bosch Software Innovations GmbH) - make pending flight and handshaker
 *                                                    access thread safe.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add handshakeFailed.
 *    Achim Kraus (Bosch Software Innovations GmbH) - use volatile for establishedSession.
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - add automatic resumption
 *    Achim Kraus (Bosch Software Innovations GmbH) - add session id to resume
 *                                                    connections created based
 *                                                    on the client session cache.
 *                                                    remove unused constructor.
 *    Achim Kraus (Bosch Software Innovations GmbH) - issue 744: use handshaker as 
 *                                                    parameter for session listener.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add handshakeFlightRetransmitted
 *    Achim Kraus (Bosch Software Innovations GmbH) - redesign connection session listener to
 *                                                    ensure, that the session listener methods
 *                                                    are called via the handshaker.
 *    Achim Kraus (Bosch Software Innovations GmbH) - move DTLSFlight to Handshaker
 *    Achim Kraus (Bosch Software Innovations GmbH) - move serial executor from dtlsconnector
 *    Achim Kraus (Bosch Software Innovations GmbH) - add connection id as primary 
 *                                                    lookup key. redesign to make 
 *                                                    the connection modifiable
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ConcurrentModificationException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.SerialExecutor;
import org.eclipse.californium.elements.util.SerialExecutor.ExecutionListener;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.ConnectionExecutionListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Information about the DTLS connection to a peer.
 * 
 * Contains status information regarding
 * <ul>
 * <li>a potentially ongoing handshake with the peer</li>
 * <li>an already established session with the peer</li>
 * </ul> 
 */
public final class Connection {

	private static final Logger LOGGER = LoggerFactory.getLogger(Connection.class);
	private static final Logger LOGGER_OWNER = LoggerFactory.getLogger(Connection.class + "owner");

	private final AtomicReference<Handshaker> ongoingHandshake = new AtomicReference<Handshaker>();
	private final SessionListener sessionListener = new ConnectionSessionListener();

	/**
	 * Random used by client to start the handshake. Maybe {@code null}, for
	 * client side connections. Note: used outside of serial-execution!
	 */
	private volatile Random startingClientHelloRandom;
	private int startingClientHelloMessageSeq;

	/**
	 * Expired real time nanoseconds of the last message send or received.
	 */
	private long lastMessageNanos;
	private long lastPeerAddressNanos;
	private SerialExecutor serialExecutor;
	private InetSocketAddress peerAddress;
	private ConnectionId cid;
	private SessionTicket ticket;
	private SessionId sessionId;

	private volatile DTLSSession establishedSession;
	// Used to know when an abbreviated handshake should be initiated
	private volatile boolean resumptionRequired; 

	private volatile ConnectionExecutionListener connectionExecutionListener;

	/**
	 * Creates a new connection to a given peer.
	 * 
	 * @param peerAddress the IP address and port of the peer the connection exists with
	 * @param serialExecutor serial executor.
	 * @throws NullPointerException if the peer address or the serial executor is {@code null}
	 */
	public Connection(InetSocketAddress peerAddress, SerialExecutor serialExecutor) {
		if (peerAddress == null) {
			throw new NullPointerException("Peer address must not be null");
		} else if (serialExecutor == null) {
			throw new NullPointerException("Serial executor must not be null");
		} else {
			long now = ClockUtil.nanoRealtime();
			this.sessionId = null;
			this.ticket = null;
			this.peerAddress = peerAddress;
			this.serialExecutor = serialExecutor;
			this.lastPeerAddressNanos = now;
			this.lastMessageNanos = now;
		}
	}

	/**
	 * Creates a new connection from a session ticket containing <em>current</em> state from another
	 * connection that should be resumed.
	 * 
	 * The connection is not {@link #isExecuting()}.
	 * 
	 * @param sessionTicket The other connection's current state.
	 * @param sessionId The other connection's session id.
	 * @param peerAddress optional peer address for {@link ClientSessionCache}.
	 *            May be {@code null}.
	 * @throws NullPointerException if the session ticket or id is {@code null}
	 */
	public Connection(SessionTicket sessionTicket, SessionId sessionId, InetSocketAddress peerAddress) {
		if (sessionTicket == null) {
			throw new NullPointerException("session ticket must not be null");
		} else if (sessionId == null) {
			throw new NullPointerException("session identity must not be null");
		} else {
			this.ticket = sessionTicket;
			this.sessionId =sessionId;
			this.resumptionRequired = true;
			this.peerAddress = peerAddress;
			this.cid = null;
			this.serialExecutor = null;
		}
	}

	public void setExecutionListener(final ConnectionExecutionListener listener) {
		this.connectionExecutionListener = listener;
		SerialExecutor executor = this.serialExecutor;
		if (executor != null) {
			if (listener == null) {
				executor.setExecutionListener(null);
			} else {
				executor.setExecutionListener(new ExecutionListener() {

					@Override
					public void beforeExecution() {
						listener.beforeExecution(Connection.this);
					}

					@Override
					public void afterExecution() {
						listener.afterExecution(Connection.this);
					}
				});
			}
		}
	}

	public void updateConnectionState() {
		ConnectionExecutionListener listener = this.connectionExecutionListener;
		if (listener != null) {
			listener.updateExecution(this);
		}
	}

	/**
	 * Set new executor to restart execution for stopped connection.
	 * 
	 * @param serialExecutor new serial executor
	 * @throws NullPointerException if the serial executor is {@code null}
	 * @throws IllegalStateException if the connection is already executing
	 */
	public void setExecutor(SerialExecutor serialExecutor) {
		if (serialExecutor == null) {
			throw new NullPointerException("Serial executor must not be null1");
		} else if (isExecuting()) {
			throw new IllegalStateException("Serial executor already available!");
		}
		this.serialExecutor = serialExecutor;
		setExecutionListener(this.connectionExecutionListener);
	}

	/**
	 * Gets the serial executor assigned to this connection.
	 * 
	 * @return serial executor. May be {@code null}, if the connection was
	 *         created with {@link #Connection(SessionTicket, SessionId, InetSocketAddress)}.
	 */
	public SerialExecutor getExecutor() {
		return serialExecutor;
	}

	/**
	 * Checks, if the connection has a executing serial executor.
	 * 
	 * @return {@code true}, if the connection has an executing serial executor.
	 *         {@code false}, if no serial executor is available, or the
	 *         executor is shutdown.
	 */
	public boolean isExecuting() {
		return serialExecutor != null && !serialExecutor.isShutdown();
	}

	/**
	 * Get session listener of connection.
	 * 
	 * @return session listener.
	 */
	public final SessionListener getSessionListener() {
		return sessionListener;
	}

	/**
	 * Checks whether this connection is either in use on this node or can be resumed by peers interacting with
	 * this node.
	 * <p>
	 * A connection that is not active is currently being negotiated by means of the <em>ongoingHandshake</em>.
	 * 
	 * @return {@code true} if this connection either already has an established session or
	 *         contains a session ticket that it can be resumed from.
	 */
	public boolean isActive() {
		return establishedSession != null || ticket != null;
	}

	/**
	 * Gets the session identity this connection can be resumed from.
	 * 
	 * @return The session identity or {@code null} if this connection has not been created from a session ticket.
	 */
	public SessionId getSessionIdentity() {
		return sessionId;
	}

	/**
	 * Gets the session ticket this connection can be resumed from.
	 * 
	 * @return The ticket or {@code null} if this connection has not been created from a session ticket.
	 */
	public SessionTicket getSessionTicket() {
		return ticket;
	}

	/**
	 * Check, if this connection expects connection ID for incoming records.
	 * 
	 * @return {@code true}, if connection ID is expected, {@code false},
	 *         otherwise
	 */
	public boolean expectCid() {
		DTLSSession session = getSession();
		return session != null && session.getWriteConnectionId() != null;
	}

	/**
	 * Gets the connection id.
	 * 
	 * @return the cid
	 */
	public ConnectionId getConnectionId() {
		return cid;
	}

	/**
	 * Sets the connection id.
	 * 
	 * @param cid the connection id
	 */
	public void  setConnectionId(ConnectionId cid) {
		this.cid = cid;
		updateConnectionState();
	}

	/**
	 * Get real time nanoseconds of last
	 * {@link #updatePeerAddress(InetSocketAddress)}.
	 * 
	 * @return real time nanoseconds
	 * @see ClockUtil#nanoRealtime()
	 */
	public long getLastPeerAddressNanos() {
		return lastPeerAddressNanos;
	}

	/**
	 * Gets the address of this connection's peer.
	 * 
	 * @return the address
	 */
	public InetSocketAddress getPeerAddress() {
		return peerAddress;
	}

	/**
	 * Update the address of this connection's peer.
	 * 
	 * If the new address is {@code null}, an ongoing handshake is failed. A
	 * non-null address could only be applied, if the session is established.
	 * 
	 * Note: to keep track of the associated address in the connection store,
	 * this method must not be called directly. It must be called by calling
	 * {@link ResumptionSupportingConnectionStore#update(Connection, InetSocketAddress)}
	 * or
	 * {@link ResumptionSupportingConnectionStore#remove(Connection, boolean)}.
	 * 
	 * @param peerAddress the address of the peer
	 * @throws IllegalArgumentException if the address should be updated with a
	 *             non-null value without an established session.
	 */
	public void updatePeerAddress(InetSocketAddress peerAddress) {
		if (equalsPeerAddress(peerAddress)) {
			// the router info of a RouterInetSocketAddress may have changed
			this.peerAddress = peerAddress;
			if (establishedSession != null) {
				establishedSession.setPeer(peerAddress);
			}
			updateConnectionState();
		} else {
			if (establishedSession == null && peerAddress != null) {
				throw new IllegalArgumentException("Address change without established sesson is not supported!");
			}
			this.lastPeerAddressNanos = ClockUtil.nanoRealtime();
			this.peerAddress = peerAddress;
			if (establishedSession != null) {
				establishedSession.setPeer(peerAddress);
			}
			if (peerAddress == null) {
				final Handshaker pendingHandshaker = getOngoingHandshake();
				if (pendingHandshaker != null) {
					if (establishedSession == null || pendingHandshaker.getSession() != establishedSession) {
						// this will only call the listener, if no other cause was set before!
						pendingHandshaker.handshakeFailed(new IOException("address changed!"));
					}
				}
			} else {
				// only update mdc, if address is changed to new one.
				updateConnectionState();
			}
		}
	}

	/**
	 * Check, if the provided address is the peers address.
	 * 
	 * @param peerAddress provided peer address
	 * @return {@code true}, if the addresses are equal
	 */
	public boolean equalsPeerAddress(InetSocketAddress peerAddress) {
		if (this.peerAddress == peerAddress) {
			return true;
		} else if (this.peerAddress == null) {
			return false;
		}
		return this.peerAddress.equals(peerAddress);
	}

	/**
	 * Gets the already established DTLS session that exists with this connection's peer.
	 * 
	 * @return the session or <code>null</code> if no session has been established (yet)
	 */
	public DTLSSession getEstablishedSession() {
		return establishedSession;
	}

	/**
	 * Checks whether a session has already been established with the peer.
	 * 
	 * @return <code>true</code> if a session has been established
	 */
	public boolean hasEstablishedSession() {
		return establishedSession != null;
	}

	/**
	 * Gets the handshaker managing the currently ongoing handshake with the peer.
	 * 
	 * @return the handshaker or <code>null</code> if no handshake is going on
	 */
	public Handshaker getOngoingHandshake() {
		return ongoingHandshake.get();
	}

	/**
	 * Checks whether there is a handshake going on with the peer.
	 * 
	 * @return <code>true</code> if a handshake is going on
	 */
	public boolean hasOngoingHandshake() {
		return ongoingHandshake.get() != null;
	}

	/**
	 * Checks whether this connection is started for the provided CLIENT_HELLO.
	 * 
	 * Use the random and message sequence number contained in the CLIENT_HELLO.
	 * 
	 * Note: called outside of serial-execution and so requires external synchronization!
	 * 
	 * @param clientHello the message to check.
	 * @return {@code true} if the given client hello has initially started this
	 *         connection.
	 * @see #startByClientHello(ClientHello)
	 * @throws NullPointerException if client hello is {@code null}.
	 */
	public boolean isStartedByClientHello(ClientHello clientHello) {
		if (clientHello == null) {
			throw new NullPointerException("client hello must not be null!");
		}
		Random startingClientHelloRandom = this.startingClientHelloRandom;
		if (startingClientHelloRandom != null) {
			if (startingClientHelloRandom.equals(clientHello.getRandom())) {
				if (startingClientHelloMessageSeq >= clientHello.getMessageSeq()) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Set starting CLIENT_HELLO.
	 * 
	 * Use the random and handshake message sequence number contained in the
	 * CLIENT_HELLO. Removed, if when the handshake fails or with configurable
	 * timeout after handshake completion.
	 * 
	 * Note: called outside of serial-execution and so requires external synchronization!
	 * 
	 * @param clientHello message which starts the connection.
	 * @see #isStartedByClientHello(ClientHello)
	 */
	public void startByClientHello(ClientHello clientHello) {
		if (clientHello == null) {
			startingClientHelloRandom = null;
		} else {
			startingClientHelloMessageSeq = clientHello.getMessageSeq();
			startingClientHelloRandom = clientHello.getRandom();
		}
	}

	/**
	 * Gets the session containing the connection's <em>current</em> state for
	 * the provided epoch.
	 * 
	 * This is the {@link #establishedSession}, if not {@code null} and the read
	 * epoch is matching. Or the session negotiated in the
	 * {@link #ongoingHandshake}, if not {@code null} and the read epoch is
	 * matching. If both are {@code null}, or the read epoch doesn't match,
	 * {@code null} is returned.
	 * 
	 * @param readEpoch the read epoch to match.
	 * @return the <em>current</em> session or {@code null}, if neither an
	 *         established session nor an ongoing handshake exists with an
	 *         matching read epoch
	 */
	public DTLSSession getSession(int readEpoch) {
		DTLSSession session = establishedSession;
		if (session != null && session.getReadEpoch() == readEpoch) {
			return session;
		}
		Handshaker handshaker = ongoingHandshake.get();
		if (handshaker != null) {
			session = handshaker.getSession();
			if (session != null && session.getReadEpoch() == readEpoch) {
				return session;
			}
		}
		return null;
	}

	/**
	 * Gets the session containing the connection's <em>current</em> state.
	 * 
	 * This is the {@link #establishedSession} if not {@code null} or the
	 * session negotiated in the {@link #ongoingHandshake}.
	 * 
	 * @return the <em>current</em> session or {@code null} if neither an
	 *         established session nor an ongoing handshake exists
	 */
	public DTLSSession getSession() {
		DTLSSession session = establishedSession;
		if (session == null) {
			Handshaker handshaker = ongoingHandshake.get();
			if (handshaker != null) {
				session = handshaker.getSession();
			}
		}
		return session;
	}

	/**
	 * Reset session.
	 * 
	 * Prepare connection for new handshake. Reset established session or
	 * session ticket and remove resumption mark.
	 * 
	 * @throws IllegalStateException if neither a established session nor a
	 *             ticket is available
	 */
	public void resetSession() {
		if (establishedSession == null && ticket == null) {
			throw new IllegalStateException("No session established nor ticket available!");
		}
		establishedSession = null;
		sessionId = null;
		ticket = null;
		resumptionRequired = false;
		updateConnectionState();
	}

	/**
	 * Check, if connection was closed.
	 * 
	 * @return {@code true}, if connection was closed, {@code false}, otherwise.
	 * @since 2.3
	 */
	public boolean isClosed() {
		DTLSSession session = establishedSession;
		return session != null && session.isMarkedAsClosed();
	}

	/**
	 * Close connection with record.
	 * 
	 * Mark session as closed. Received records with sequence numbers before
	 * will still be processed, others are dropped. No message will be send
	 * after this.
	 * 
	 * @param record received close notify record.
	 * @since 2.3
	 */
	public void close(Record record) {
		DTLSSession session = establishedSession;
		if (session != null) {
			session.markCloseNotiy(record.getEpoch(), record.getSequenceNumber());
		}
	}

	/**
	 * Check, if resumption is required.
	 * 
	 * @return true if an abbreviated handshake should be done next time a data
	 *         will be sent on this connection.
	 */
	public boolean isResumptionRequired() {
		return resumptionRequired;
	}

	/**
	 * Check, if the automatic session resumption should be triggered or is
	 * already required.
	 * 
	 * @param autoResumptionTimeoutMillis auto resumption timeout in
	 *            milliseconds. {@code null}, if auto resumption is not used.
	 * @return {@code true}, if the provided autoResumptionTimeoutMillis has
	 *         expired without exchanging messages.
	 */
	public boolean isAutoResumptionRequired(Long autoResumptionTimeoutMillis) {
		if (!resumptionRequired && autoResumptionTimeoutMillis != null && establishedSession != null) {
			long now = ClockUtil.nanoRealtime();
			long expires = lastMessageNanos + TimeUnit.MILLISECONDS.toNanos(autoResumptionTimeoutMillis);
			if ((now - expires) > 0) {
				setResumptionRequired(true);
			}
		}
		return resumptionRequired;
	}

	/**
	 * Refresh auto resumption timeout.
	 * 
	 * Uses {@link ClockUtil#nanoRealtime()}.
	 * 
	 * @see #lastMessageNanos
	 */
	public void refreshAutoResumptionTime() {
		lastMessageNanos = ClockUtil.nanoRealtime();
	}

	/**
	 * Use to force an abbreviated handshake next time a data will be sent on this connection.
	 * @param resumptionRequired true to force abbreviated handshake.
	 */
	public void setResumptionRequired(boolean resumptionRequired) {
		this.resumptionRequired = resumptionRequired;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder("dtls-con: ");
		if (cid != null) {
			builder.append(cid);
		}
		if (peerAddress != null) {
			builder.append(", ").append(peerAddress);
			if (getOngoingHandshake() != null) {
				builder.append(", ongoing handshake ");
				SessionId id = getOngoingHandshake().getSession().getSessionIdentifier();
				if (id != null && !id.isEmpty()) {
					// during handshake this may by not already set
					builder.append(StringUtil.byteArray2HexString(id.getBytes(), StringUtil.NO_SEPARATOR, 6));
				}
			}
			if (isResumptionRequired()) {
				builder.append(", resumption required");
			} else if (hasEstablishedSession()) {
				builder.append(", session established ");
				SessionId id = getEstablishedSession().getSessionIdentifier();
				if (id != null && !id.isEmpty()) {
					builder.append(StringUtil.byteArray2HexString(id.getBytes(), StringUtil.NO_SEPARATOR, 6));
				}
			}
		}
		if (sessionId != null) {
			builder.append(", ").append(sessionId);
			builder.append(", ").append(ticket);
		}
		if (isExecuting()) {
			builder.append(", is alive");
		}
		return builder.toString();
	}

	private class ConnectionSessionListener implements SessionListener {
		@Override
		public void handshakeStarted(Handshaker handshaker)	throws HandshakeException {
			ongoingHandshake.set(handshaker);
			LOGGER.debug("Handshake with [{}] has been started", handshaker.getPeerAddress());
		}

		@Override
		public void sessionEstablished(Handshaker handshaker, DTLSSession session) throws HandshakeException {
			establishedSession = session;
			LOGGER.debug("Session with [{}] has been established", session.getPeer());
		}

		@Override
		public void handshakeCompleted(Handshaker handshaker) {
			SerialExecutor executor = serialExecutor;
			if (executor != null && !executor.isShutdown() && LOGGER_OWNER.isErrorEnabled()) {
				try {
					executor.assertOwner();
				} catch (ConcurrentModificationException ex) {
					LOGGER_OWNER.error("on handshake completed: connection {}", ex.getMessage(), ex);
					if (LOGGER_OWNER.isDebugEnabled()) {
						throw ex;
					}
				}
			}
			if (ongoingHandshake.compareAndSet(handshaker, null)) {
				LOGGER.debug("Handshake with [{}] has been completed", handshaker.getPeerAddress());
			}
		}

		@Override
		public void handshakeFailed(Handshaker handshaker, Throwable error) {
			SerialExecutor executor = serialExecutor;
			if (executor != null && !executor.isShutdown() && LOGGER_OWNER.isErrorEnabled()) {
				try {
					executor.assertOwner();
				} catch (ConcurrentModificationException ex) {
					LOGGER_OWNER.error("on handshake failed: connection {}", ex.getMessage(), ex);
					if (LOGGER_OWNER.isDebugEnabled()) {
						throw ex;
					}
				}
			}
			if (ongoingHandshake.compareAndSet(handshaker, null)) {
				startingClientHelloRandom = null;
				LOGGER.debug("Handshake with [{}] has failed", handshaker.getPeerAddress());
			}
		}

		@Override
		public void handshakeFlightRetransmitted(Handshaker handshaker, int flight) {
		}
	}
}
