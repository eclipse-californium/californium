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
 *    Achim Kraus (Bosch.IO GmbH)                   - renamed SessionCache
 *                                                    all functions are intended to
 *                                                    return immediately.
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

/**
 * A second level store for current state of DTLS sessions.
 * <p>
 * Used for {@link InMemoryConnectionStore}. Session state can be put to the
 * store and later retrieved by the DTLS session's ID for resumption handshakes.
 * The provided store is required to be thread-safe because it will be accessed
 * concurrently. If used, the sessions are weakly consistent with the
 * connections, if not used, the session are strictly consistent with the
 * connections.
 * </p>
 * 
 * Note: since 3.0 {@link #get(SessionId)} is intended to return immediately! If
 * that takes longer, it blocks the connection store and results in down-graded
 * performance.
 * 
 * Note: using this interface for the {@link InMemoryConnectionStore} is not
 * well tested! If used and causing trouble, don't hesitate to create an issue.
 */
public interface SessionStore {

	/**
	 * Adds an established session to the session store.
	 * 
	 * If the session doesn't support resumption (session id is empty), it's not
	 * added to the session store
	 * 
	 * @param session The session to add.
	 */
	void put(DTLSSession session);

	/**
	 * Gets a session from the session store.
	 * 
	 * Note: since 3.0 {@link #get(SessionId)} is intended to return
	 * immediately! If that takes longer, it blocks the connection store and
	 * results in down-graded performance.
	 * 
	 * @param id The session identifier to look up.
	 * @return a session ticker for the session with the given ID, or
	 *         {@code null}, if the session store does not contain a session
	 *         with the given ID. A returned ticket is to be destroyed after
	 *         usage. The session ticket can only be used for resumption
	 *         handshakes.
	 */
	SessionTicket get(SessionId id);

	/**
	 * Removes a session from the session store.
	 * 
	 * @param id The identifier of the session to remove.
	 */
	void remove(SessionId id);
}
