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
 * Note: since 3.0 this interface clarifies, that it is intended to return
 * immediately! If calls takes longer, that results in down-graded performance.
 * That was mainly also the situation before 3.0.
 * 
 * Note: using this interface for the {@link InMemoryConnectionStore} is not
 * well tested! If used and causing trouble, don't hesitate to create an issue.
 * 
 * @since 3.0 (renamed SessionCache)
 */
public interface SessionStore {

	/**
	 * Adds an established session to the session store.
	 * 
	 * The session is identified by its session id, which is returned by
	 * {@link DTLSSession#getSessionIdentifier()}. If the session doesn't
	 * support resumption (session id is empty), it's not added to the session
	 * store. Later access in {@link #get(SessionId)} or
	 * {@link #remove(SessionId)} must use then use the value of the contained
	 * session id as parameter.
	 * 
	 * Note: since 3.0 this interface intended to return immediately! If calls
	 * takes longer, that results in down-graded performance.
	 * 
	 * @param session The session to add. The value of
	 *            {@link DTLSSession#getSessionIdentifier()} is used in
	 *            {@link #get(SessionId)} and {@link #remove(SessionId)}.
	 */
	void put(DTLSSession session);

	/**
	 * Gets a session from the session store.
	 * 
	 * Note: since 3.0 this interface intended to return immediately! If calls
	 * takes longer, that results in down-graded performance.
	 * 
	 * @param id The session identifier to look up. See
	 *            {@link DTLSSession#getSessionIdentifier()}.
	 * @return a session with the given ID, or {@code null}, if the session
	 *         store does not contain a session with the given ID. A returned
	 *         session is to be destroyed after usage.
	 * @since 3.0 (return type changed to DTLSSession)
	 */
	DTLSSession get(SessionId id);

	/**
	 * Removes a session from the session store.
	 * 
	 * Note: since 3.0 this interface intended to return immediately! If calls
	 * takes longer, that results in down-graded performance.
	 * 
	 * @param id The identifier of the session to remove. See
	 *            {@link DTLSSession#getSessionIdentifier()}.
	 */
	void remove(SessionId id);
}
