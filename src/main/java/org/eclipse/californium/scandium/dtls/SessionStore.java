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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add support for stale
 *                                                    session expiration (466554)
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;

/**
 * A strategy for keeping track of DTLS session information.
 * 
 * Implementations might choose to keep the data in-memory
 * or use a separate persistence store in order to share state
 * with other server instances.
 * 
 * The methods of this strategy interface are designed to support
 * usage of a session's peer address as key. However, implementations
 * may chose to use other properties of a session as well.
 */
public interface SessionStore {

	/**
	 * Puts a session into the store.
	 * 
	 * @param session the session to store
	 * @return <code>true</code> if the session could be stored, <code>false</code>
	 *       otherwise (e.g. because the store's capacity is exhausted)
	 */
	boolean put(DTLSSession session);

	/**
	 * Gets the number of additional sessions this store can manage.
	 * 
	 * @return the remaining capacity
	 */
	int remainingCapacity();
	
	/**
	 * Updates a session's state in the store.
	 * 
	 * This method may not be relevant for all implementations,
	 * e.g. an in-memory implementation may relay on Java's
	 * pass-by-reference mechanism to keep object state up-to-date.
	 * 
	 * However, implementations using a separate persistence store
	 * may want to make sure that the new state is persisted.
	 * 
	 * @param session the updated session
	 */
	void update(DTLSSession session);
	
	/**
	 * Gets a session by its peer address.
	 * 
	 * @param peerAddress the peer address
	 * @return the matching session or <code>null</code> if
	 *     no session exists for the given address
	 */
	DTLSSession get(InetSocketAddress peerAddress);
	
	/**
	 * Finds a session by its ID.
	 * 
	 * @param id the session ID
	 * @return the matching session or <code>null</code> if
	 *     no session exists with the given ID
	 */
	DTLSSession find(SessionId id);

	/**
	 * Removes a session from the store.
	 * 
	 * @param peerAddress the peer address of the session to remove
	 * @return the removed session of <code>null</code> if
	 *     no session exists for the given address
	 */
	DTLSSession remove(InetSocketAddress peerAddress);
}
