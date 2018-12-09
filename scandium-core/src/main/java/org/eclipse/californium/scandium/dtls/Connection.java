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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.californium.elements.util.ClockUtil;
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

	private static final Logger LOGGER = LoggerFactory.getLogger(Connection.class.getName());

	private final InetSocketAddress peerAddress;
	private final SessionTicket ticket;
	private final SessionId sessionId;
	private final SessionListener sessionListener;
	private final AtomicReference<Handshaker> ongoingHandshake = new AtomicReference<Handshaker>();
	/**
	 * Expired realtime nanoseconds of the last message send or received.
	 */
	private final AtomicLong lastMessageNanos = new AtomicLong();

	private volatile DTLSSession establishedSession;
	// Used to know when an abbreviated handshake should be initiated
	private volatile boolean resumptionRequired = false; 

	/**
	 * Creates a new connection to a given peer.
	 * 
	 * @param peerAddress the IP address and port of the peer the connection exists with
	 * @throws NullPointerException if the peer address is <code>null</code>
	 */
	public Connection(final InetSocketAddress peerAddress) {
		if (peerAddress == null) {
			throw new NullPointerException("Peer address must not be null");
		} else {
			this.sessionId = null;
			this.ticket = null;
			this.peerAddress = peerAddress;
			this.sessionListener = new ConnectionSessionListener();
		}
	}

	/**
	 * Creates a new connection from a session ticket containing <em>current</em> state from another
	 * connection that should be resumed.
	 * 
	 * @param sessionTicket The other connection's current state.
	 * @param sessionId The other connection's session id.
	 */
	public Connection(final SessionTicket sessionTicket, SessionId sessionId) {
		if (sessionTicket == null) {
			throw new NullPointerException("session ticket must not be null");
		}
		if (sessionId == null) {
			throw new NullPointerException("session identity must not be null");
		}
		this.ticket = sessionTicket;
		this.sessionId =sessionId;
		this.peerAddress = null;
		this.sessionListener = null;
	}

	/**
	 * Get session listener of connection.
	 * 
	 * @return session listener. {@code null}, if the connection just provides a
	 *         session ticket ({@link Connection#Connection(SessionTicket)}).
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
	 * Checks if this connection has been created from a session ticket instead of having been established
	 * locally.
	 * 
	 * @return {@code true} if this connection has been created from a ticket.
	 */
	public boolean hasSessionTicket() {
		return ticket != null;
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
	 * Checks whether this connection has a ongoing handshake initiated by the
	 * given message.
	 * 
	 * @param handshakeMessage the message to check.
	 * @return <code>true</code> if the given message has initially started this
	 *         ongoing handshake.
	 */
	public boolean hasOngoingHandshakeStartedByMessage(HandshakeMessage handshakeMessage) {
		Handshaker handshaker = ongoingHandshake.get();
		return handshaker != null && handshaker.hasBeenStartedByMessage(handshakeMessage);
	}

	/**
	 * Cancels any pending re-transmission of an outbound flight.
	 */
	public void cancelPendingFlight() {
		Handshaker handshaker = ongoingHandshake.get();
		if (handshaker != null) {
			handshaker.cancelPendingFlight();
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
	 *            milliseconds. {@code 0} milliseconds to force a resumption,
	 *            {@code null}, if auto resumption is not used.
	 * @return {@code true}, if the {@link #autoResumptionTimeout} has expired
	 *         without exchanging messages.
	 */
	public boolean isAutoResumptionRequired(Long autoResumptionTimeoutMillis) {
		if (!resumptionRequired && autoResumptionTimeoutMillis != null && establishedSession != null) {
			if (autoResumptionTimeoutMillis == 0) {
				setResumptionRequired(true);
			} else {
				long now = ClockUtil.nanoRealtime();
				long expires = lastMessageNanos.get() + TimeUnit.MILLISECONDS.toNanos(autoResumptionTimeoutMillis);
				if ((now - expires) > 0) {
					setResumptionRequired(true);
				}
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
		long now = ClockUtil.nanoRealtime();
		lastMessageNanos.set(now);
	}

	/**
	 * Use to force an abbreviated handshake next time a data will be sent on this connection.
	 * @param resumptionRequired true to force abbreviated handshake.
	 */
	public void setResumptionRequired(boolean resumptionRequired) {
		this.resumptionRequired = resumptionRequired;
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
			if (ongoingHandshake.compareAndSet(handshaker, null)) {
				LOGGER.debug("Handshake with [{}] has been completed", handshaker.getPeerAddress());
			}
		}

		@Override
		public void handshakeFailed(Handshaker handshaker, Throwable error) {
			if (ongoingHandshake.compareAndSet(handshaker, null)) {
				LOGGER.debug("Handshake with [{}] has failed", handshaker.getPeerAddress());
			}
		}

		@Override
		public void handshakeFlightRetransmitted(Handshaker handshaker, int flight) {
			
		}
	}
}
