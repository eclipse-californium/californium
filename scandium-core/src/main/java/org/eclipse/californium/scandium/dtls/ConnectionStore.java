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

/**
 * A strategy for keeping track of DTLS connection information.
 * 
 * The methods of this strategy interface are designed to support
 * usage of a connection's peer address as key. However, implementations
 * may chose to use other properties of a session as well.
 * 
 * It is also assumed that the sessions are kept in memory. Thus, no
 * explicit <code>update</code> method is provided since all instances
 * are expected to be passed-in and stored by reference.
 */
public interface ConnectionStore {

	/**
	 * Puts a connection into the store.
	 * 
	 * @param connection the connection to store
	 * @return <code>true</code> if the connection could be stored, <code>false</code>
	 *       otherwise (e.g. because the store's capacity is exhausted)
	 */
	boolean put(Connection connection);

	/**
	 * Gets the number of additional connection this store can manage.
	 * 
	 * @return the remaining capacity
	 */
	int remainingCapacity();
	
	/**
	 * Gets a connection by its peer address.
	 * 
	 * @param peerAddress the peer address
	 * @return the matching connection or <code>null</code> if
	 *     no connection exists for the given address
	 */
	Connection get(InetSocketAddress peerAddress);
	
	/**
	 * Finds a connection by its session ID.
	 * 
	 * @param id the session ID
	 * @return the matching connection or <code>null</code> if
	 *     no connection with an established session with the given ID exists
	 */
	Connection find(SessionId id);

	/**
	 * Removes a connection from the store.
	 * 
	 * @param peerAddress the peer address of the connection to remove
	 * @return the removed connection or <code>null</code> if
	 *     no connection exists for the given address
	 */
	Connection remove(InetSocketAddress peerAddress);

	/**
	 * Removes all connections from the store.
	 */
	void clear();
}
