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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 464383
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add support for stale
 *                                                    session expiration (466554)
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add support for start and completion
 *                                                    of handshake
 *    Achim Kraus (Bosch Software Innovations GmbH) - add handshakeFailed to report
 *                                                    handshake errors.
 *    Achim Kraus (Bosch Software Innovations GmbH) - issue 744: use handshaker as
 *                                                    parameter for session listener.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add handshakeFlightRetransmitted
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

/**
 * A listener for life-cycle events of <code>DTLSSession</code>s.
 * 
 */
public interface SessionListener {

	/**
	 * Indicates that a handshake for establishing a session with a peer has been started.
	 * 
	 * @param handshaker the handshaker used to establish the session
	 * @throws HandshakeException if the handshake cannot proceed due to e.g. system resource
	 *              limitations
	 */
	void handshakeStarted(Handshaker handshaker) throws HandshakeException;

	/**
	 * Indicates that a session has successfully been established.
	 * 
	 * In particular this means that the session negotiated by the
	 * handshaker can now be used to exchange application layer data.
	 * 
	 * @param handshaker the handshaker used to establish the session
	 * @param establishedSession the session that has been negotiated by
	 *          the handshaker
	 * @throws NullPointerException if any of the parameters is <code>null</code>
	 * @throws HandshakeException if the listener cannot process the newly
	 *          established session
	 */
	void sessionEstablished(Handshaker handshaker, DTLSSession establishedSession)
		throws HandshakeException;
	
	/**
	 * Indicates that a handshake with a given peer has been completed.
	 * 
	 * In particular, this means that both peers have received the other
	 * peer's <em>FINISHED</em> messages.
	 * 
	 * @param handshaker the handshaker that has been completed
	 */
	void handshakeCompleted(Handshaker handshaker);

	/**
	 * Indicates that a handshake with a given peer has failed.
	 * 
	 * @param handshaker the handshaker that has failed
	 * @param error the error occurred during the handshake
	 */
	void handshakeFailed(Handshaker handshaker, Throwable error);

	/**
	 * Indicates that a handshake flight is retransmitted.
	 * 
	 * @param handshaker the handshaker that retransmits a flight
	 * @param flight number of flight, which is retransmitted
	 */
	void handshakeFlightRetransmitted(Handshaker handshaker, int flight);
}
