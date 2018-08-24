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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Information about the DTLS connection to a peer.
 * 
 * Contains status information regarding
 * <ul>
 * <li>a potentially ongoing handshake with the peer</li>
 * <li>an already established session with the peer</li>
 * <li>a pending flight that has not been acknowledged by the peer yet</li>
 * </ul> 
 */
public final class Connection {

	private static final Logger LOGGER = LoggerFactory.getLogger(Connection.class.getName());

	private final InetSocketAddress peerAddress;
	private final SessionTicket ticket;
	private final SessionId sessionId;
	private final SessionListener sessionListener;
	private final AtomicReference<Handshaker> ongoingHandshake = new AtomicReference<Handshaker>();
	private final AtomicReference<DTLSFlight> pendingFlight = new AtomicReference<DTLSFlight>();
	private final AtomicLong lastMessage = new AtomicLong();
	private final Long autoResumptionTimeout;

	private volatile DTLSSession establishedSession;
	// Used to know when an abbreviated handshake should be initiated
	private volatile boolean resumptionRequired = false; 

	/**
	 * Creates a new connection to a given peer.
	 * 
	 * @param peerAddress the IP address and port of the peer the connection exists with
	 * @param autoResumptionTimeout
	 * @throws NullPointerException if the peer address is <code>null</code>
	 */
	public Connection(final InetSocketAddress peerAddress, final Long autoResumptionTimeout) {
		if (peerAddress == null) {
			throw new NullPointerException("Peer address must not be null");
		} else {
			this.sessionId = null;
			this.ticket = null;
			this.peerAddress = peerAddress;
			this.autoResumptionTimeout = autoResumptionTimeout;
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
		this.autoResumptionTimeout = null;
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
	 * Registers an outbound flight that has not been acknowledged by the peer
	 * yet in order to be able to cancel its re-transmission later once it has
	 * been acknowledged. The retransmission of a different previous pending
	 * flight will be cancelled also.
	 * 
	 * @param pendingFlight the flight
	 * @see #cancelPendingFlight()
	 */
	public void setPendingFlight(DTLSFlight pendingFlight) {
		DTLSFlight flight = this.pendingFlight.getAndSet(pendingFlight);
		if (flight != null && flight != pendingFlight) {
			flight.cancelRetransmission();
		}
	}

	/**
	 * Cancels any pending re-transmission of an outbound flight that has been registered
	 * previously using the {@link #setPendingFlight(DTLSFlight)} method.
	 * 
	 * This method is usually invoked once an flight has been acknowledged by the peer. 
	 */
	public void cancelPendingFlight() {
		setPendingFlight(null);
	}

	/**
	 * Gets the session containing the connection's <em>current</em> state.
	 * 
	 * This is the {@link #establishedSession} if not <code>null</code> or
	 * the session negotiated in the {@link #ongoingHandshake}.
	 * 
	 * @return the <em>current</em> session or <code>null</code> if neither
	 *                 an established session nor an ongoing handshake exists
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
	 * @return true if an abbreviated handshake should be done next time a data will be sent on this connection.
	 */
	public boolean isResumptionRequired() {
		return resumptionRequired || isAutoResumptionRequired();
	}

	/**
	 * Check, if the automatic session resumption should be triggered.
	 * 
	 * @return {@code true}, if the {@link #autoResumptionTimeout} has expired
	 *         without exchanging message.
	 */
	public boolean isAutoResumptionRequired() {
		if (autoResumptionTimeout != null && establishedSession != null) {
			long now = TimeUnit.NANOSECONDS.toMillis(System.nanoTime());
			if ((lastMessage.get() + autoResumptionTimeout - now) < 0) {
				setResumptionRequired(true);
				return resumptionRequired;
			}
		}
		return false;
	}

	/**
	 * Refresh auto resumption timeout.
	 * @see #autoResumptionTimeout
	 * @see #lastMessage
	 */
	public void refreshAutoResumptionTime() {
		if (autoResumptionTimeout != null) {
			long now = TimeUnit.NANOSECONDS.toMillis(System.nanoTime());
			lastMessage.set(now);
		}
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
				refreshAutoResumptionTime();
				cancelPendingFlight();
				LOGGER.debug("Handshake with [{}] has been completed", handshaker.getPeerAddress());
			}
		}

		@Override
		public void handshakeFailed(Handshaker handshaker, Throwable error) {
			if (ongoingHandshake.compareAndSet(handshaker, null)) {
				cancelPendingFlight();
				LOGGER.debug("Handshake with [{}] has failed", handshaker.getPeerAddress());
			}
		}

		@Override
		public void handshakeFlightRetransmitted(Handshaker handshaker, int flight) {
			
		}
	}
}
