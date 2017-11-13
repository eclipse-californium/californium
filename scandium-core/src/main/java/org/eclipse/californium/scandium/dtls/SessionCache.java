/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - Initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add javadoc about required
 *                                                    thread-safe implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

/**
 * A second level cache for current connection state of DTLS sessions.
 * <p>
 * Connection state can be put to the cache and later retrieved by the DTLS
 * session's ID. The provided cache is required to be thread-safe because it
 * will be accessed concurrently.
 * </p>
 */
public interface SessionCache {

	/**
	 * Adds an established session to the cache.
	 * 
	 * @param session The session to add.
	 */
	void put(DTLSSession session);

	/**
	 * Gets a session from the cache.
	 * 
	 * @param id The session identifier to look up.
	 * @return The session with the given ID or {@code null} if the cache does not contain
	 *         a session with the given ID.
	 */
	SessionTicket get(SessionId id);

	/**
	 * Removes a session from the cache.
	 * 
	 * @param id The identifier of the session to remove.
	 */
	void remove(SessionId id);
}
