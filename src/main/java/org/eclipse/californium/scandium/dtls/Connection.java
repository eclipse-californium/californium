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
	private DTLSSession establishedSession;
	private Handshaker ongoingHandshake;
	private DTLSFlight pendingFlight;
	
	/**
	 * Creates a new new connection to a given peer.
	 * 
	 * @param peerAddress the IP address and port of the peer the connection exists with
	 * @throws NullPointerException if the peer address is <code>null</code>
	 */
	public Connection(InetSocketAddress peerAddress) {
		this(peerAddress, null);
	}
	
	/**
	 * Creates a new new connection to a given peer.
	 * 
	 * @param peerAddress the IP address and port of the peer the connection exists with
	 * @param ongoingHandshake the object responsible for managing the already ongoing
	 *                   handshake with the peer 
	 * @throws NullPointerException if the peer address is <code>null</code>
	 */
	public Connection(InetSocketAddress peerAddress, Handshaker ongoingHandshake) {
		if (peerAddress == null) {
			throw new NullPointerException("Peer address must not be null");
		} else {
			this.peerAddress = peerAddress;
			this.ongoingHandshake = ongoingHandshake;
		}
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
	 * Gets the handshaker managing the currently ongoing handshake with the peer.
	 * 
	 * @return the handshaker or <code>null</code> if no handshake is going on
	 */
	public Handshaker getOngoingHandshake() {
		return ongoingHandshake;
	}
	
	/**
	 * Sets the handshaker managing the currently ongoing handshake with the peer.
	 * 
	 * @param ongoingHandshake the handshaker
	 */
	public void setOngoingHandshake(Handshaker ongoingHandshake) {
		this.ongoingHandshake = ongoingHandshake;
	}
	
	/**
	 * Registers an outbound flight that has not been acknowledged by the peer yet in order
	 * to be able to cancel its re-transmission later once it has been acknowledged.
	 * 
	 * @param pendingFlight the flight
	 * @see #cancelPendingFlight()
	 */
	public void setPendingFlight(DTLSFlight pendingFlight) {
		this.pendingFlight = pendingFlight;
	}
	
	/**
	 * Cancels any pending re-transmission of an outbound flight that has been registered
	 * previously using the {@link #setPendingFlight(DTLSFlight)} method.
	 * 
	 * This method is usually invoked once an flight has been acknowledged by the peer. 
	 */
	public void cancelPendingFlight() {
		if (pendingFlight != null) {
			pendingFlight.getRetransmitTask().cancel();
			pendingFlight.setRetransmitTask(null);
			pendingFlight = null;
		}
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
		if (establishedSession != null) {
			return establishedSession;
		} else if (ongoingHandshake != null) {
			return ongoingHandshake.getSession();
		} else {
			return null;
		}
	}

	@Override
	public void handshakeStarted(Handshaker handshaker)	throws HandshakeException {
		this.ongoingHandshake = handshaker;
		LOGGER.log(Level.FINE, "Handshake with [{0}] has been started", handshaker.getPeerAddress());
	}

	@Override
	public void sessionEstablished(Handshaker handshaker, DTLSSession establishedSession) throws HandshakeException {
		this.establishedSession = establishedSession;
		LOGGER.log(Level.FINE, "Session with [{0}] has been established", establishedSession.getPeer());
	}

	@Override
	public void handshakeCompleted(InetSocketAddress peer) {
		if (this.ongoingHandshake != null) {
			this.ongoingHandshake = null;
			LOGGER.log(Level.FINE, "Handshake with [{0}] has been completed", peer);
		}
	}
	
	/**
	 * Checks whether this connection currently has an established and <em>active</em>
	 * session with the peer.
	 * 
	 * An active session is one that can be used to exchange (application) data with the peer.
	 * 
	 * @return <code>true</code> if an active session is established with the client
	 */
	public boolean hasActiveEstablishedSession() {
		return establishedSession != null && establishedSession.isActive();
	}
}
