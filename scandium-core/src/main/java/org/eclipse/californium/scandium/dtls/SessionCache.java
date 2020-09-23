/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - Initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add javadoc about required
 *                                                    thread-safe implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.scandium.config.DtlsConnectorConfig;

/**
 * A second level cache for current state of DTLS sessions.
 * <p>
 * Session state can be put to the cache and later retrieved by the DTLS
 * session's ID for resumption handshakes. The provided cache is required to be
 * thread-safe because it will be accessed concurrently.
 * </p>
 * Note: {@link #get(SessionId)} is called to validate session ids, if
 * {@link DtlsConnectorConfig#getVerifyPeersOnResumptionThreshold()} is larger
 * than {@code 0}. If the implementation is expensive, please ensure, that the
 * value is configured with {@code 0}. Otherwise, CLIENT_HELLOs with invalid
 * session ids may be spoofed and gets too expensive.
 */
public interface SessionCache {

	/**
	 * Adds an established session to the cache.
	 * 
	 * If the session doesn't support resumption (session id is empty), it's not
	 * added to the cache
	 * 
	 * @param session The session to add.
	 */
	void put(DTLSSession session);

	/**
	 * Gets a session from the cache.
	 * 
	 * Note: This method is called to validate session ids, if
	 * {@link DtlsConnectorConfig#getVerifyPeersOnResumptionThreshold()} is
	 * larger than {@code 0}. If this implementation is expensive, please
	 * ensure, that the value is configured with {@code 0}. Otherwise,
	 * CLIENT_HELLOs with invalid session ids may be spoofed and gets too
	 * expensive.
	 * 
	 * @param id The session identifier to look up.
	 * @return a session ticker for the session with the given ID, or
	 *         {@code null}, if the cache does not contain a session with the
	 *         given ID. A returned ticket is to be destroyed after usage. The
	 *         session ticket can only be used for resumption handshakes.
	 */
	SessionTicket get(SessionId id);

	/**
	 * Removes a session from the cache.
	 * 
	 * @param id The identifier of the session to remove.
	 */
	void remove(SessionId id);
}
