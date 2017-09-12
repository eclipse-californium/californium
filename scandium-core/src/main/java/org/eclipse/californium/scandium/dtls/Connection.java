/*******************************************************************************
 * Copyright (c) 2015, 2016 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - use volatile for establishedSession.
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

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
public final class Connection implements SessionListener {

	private static final Logger LOGGER = Logger.getLogger(Connection.class.getName());
	private final InetSocketAddress peerAddress;
	private volatile DTLSSession establishedSession;
	private final SessionTicket ticket;
	private final AtomicReference<Handshaker> ongoingHandshake = new AtomicReference<Handshaker>();
	private final AtomicReference<DTLSFlight> pendingFlight = new AtomicReference<DTLSFlight>();

	// Used to know when an abbreviated handshake should be initiated
	private boolean resumptionRequired = false; 

	/**
	 * Creates a new connection to a given peer.
	 * 
	 * @param peerAddress the IP address and port of the peer the connection exists with
	 * @throws NullPointerException if the peer address is <code>null</code>
	 */
	public Connection(final InetSocketAddress peerAddress) {
		this(peerAddress, (Handshaker) null);
	}

	/**
	 * Creates a new connection from a session ticket containing <em>current</em> state from another
	 * connection that should be resumed.
	 * 
	 * @param sessionTicket The other connection's current state.
	 */
	public Connection(final SessionTicket sessionTicket) {
		if (sessionTicket == null) {
			throw new NullPointerException("session ticket must not be null");
		}
		this.ticket = sessionTicket;
		this.peerAddress = null;
	}

	/**
	 * Creates a new new connection to a given peer.
	 * 
	 * @param peerAddress the IP address and port of the peer the connection exists with
	 * @param ongoingHandshake the object responsible for managing the already ongoing
	 *                   handshake with the peer 
	 * @throws NullPointerException if the peer address is <code>null</code>
	 */
	public Connection(final InetSocketAddress peerAddress, final Handshaker ongoingHandshake) {
		if (peerAddress == null) {
			throw new NullPointerException("Peer address must not be null");
		} else {
			this.ticket = null;
			this.peerAddress = peerAddress;
			this.ongoingHandshake.set(ongoingHandshake);
		}
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
	 * Sets the handshaker managing the currently ongoing handshake with the peer.
	 * 
	 * @param ongoingHandshake the handshaker
	 */
	public void setOngoingHandshake(Handshaker ongoingHandshake) {
		this.ongoingHandshake.set(ongoingHandshake);
	}

	/**
	 * Stops an ongoing handshake with the peer and removes all state information
	 * about the handshake.
	 * 
	 * Cancels any pending flight and sets <em>ongoingHandshake</em> property to
	 * <code>null</code>. 
	 */
	public void terminateOngoingHandshake() {
		cancelPendingFlight();
		setOngoingHandshake(null);
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

	@Override
	public void handshakeStarted(Handshaker handshaker)	throws HandshakeException {
		this.ongoingHandshake.set(handshaker);
		LOGGER.log(Level.FINE, "Handshake with [{0}] has been started", handshaker.getPeerAddress());
	}

	@Override
	public void sessionEstablished(Handshaker handshaker, DTLSSession session) throws HandshakeException {
		this.establishedSession = session;
		LOGGER.log(Level.FINE, "Session with [{0}] has been established", session.getPeer());
	}

	@Override
	public void handshakeCompleted(InetSocketAddress peer) {
		Handshaker handshaker = ongoingHandshake.getAndSet(null);
		if (handshaker != null) {
			cancelPendingFlight();
			LOGGER.log(Level.FINE, "Handshake with [{0}] has been completed", peer);
		}
	}

	/**
	 * @return true if an abbreviated handshake should be done next time a data will be sent on this connection.
	 */
	public boolean isResumptionRequired() {
		return resumptionRequired;
	}

	/**
	 * Use to force an abbreviated handshake next time a data will be sent on this connection.
	 * @param resumptionRequired true to force abbreviated handshake.
	 */
	public void setResumptionRequired(boolean resumptionRequired) {
		this.resumptionRequired = resumptionRequired;
	}
}
