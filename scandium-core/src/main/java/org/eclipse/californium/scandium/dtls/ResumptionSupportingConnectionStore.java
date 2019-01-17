/*******************************************************************************
 * Copyright (c) 2015 Sierra Wireless
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
 *    Simon Bernard (Sierra Wireless) - Initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix session resumption with 
 *                                                    session cache. issue #712
 *    Achim Kraus (Bosch Software Innovations GmbH) - add putEstablishedSession
 *                                                    for faster find
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.util.List;

/**
 * A connection store which adds support of connection resumption.
 * 
 * @since 1.1
 */
public interface ResumptionSupportingConnectionStore {

	/**
	 * Puts a connection into the store.
	 * 
	 * @param connection the connection to store
	 * @return <code>true</code> if the connection could be stored, <code>false</code>
	 *       otherwise (e.g. because the store's capacity is exhausted)
	 */
	boolean put(Connection connection);

	/**
	 * Update a connection in the store.
	 * 
	 * Update the last-access time to prevent connection from being evicted.
	 * 
	 * @param connection the connection to update.
	 * @return <code>true</code>, if updated, <code>false</code>, otherwise.
	 */
	boolean update(Connection connection);

	/**
	 * Put connection associated with the session id into the store.
	 * 
	 * @param session established session.
	 * @param connection connection of established session
	 */
	void putEstablishedSession(final DTLSSession session, final Connection connection);

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
	 * Removes a connection from the store and session cache.
	 * 
	 * @param peerAddress the peer address of the connection to remove
	 * @return the removed connection or <code>null</code> if
	 *     no connection exists for the given address
	 */
	Connection remove(InetSocketAddress peerAddress);

	/**
	 * Removes a connection from the store and optional from the session cache.
	 * 
	 * @param peerAddress the peer address of the connection to remove
	 * @param removeFromSessionCache <code>true</code> if the session of the
	 *            connection should be removed from the session cache,
	 *            <code>false</code>, otherwise
	 * @return the removed connection or <code>null</code> if no connection
	 *         exists for the given address
	 */
	Connection remove(InetSocketAddress peerAddress, boolean removeFromSessionCache);

	/**
	 * Removes a connection from the store and session cache.
	 * 
	 * @param connection the connection to remove
	 * @return <code>true</code> if the connection was removed,
	 *            <code>false</code>, otherwise
	 */
	boolean remove(Connection connection);

	/**
	 * Removes a connection from the store and optional from the session cache.
	 * 
	 * @param connection the connection to remove
	 * @param removeFromSessionCache <code>true</code> if the session of the
	 *            connection should be removed from the session cache,
	 *            <code>false</code>, otherwise
	 * @return <code>true</code> if the connection was removed,
	 *            <code>false</code>, otherwise
	 */
	boolean remove(Connection connection, boolean removeFromSessionCache);

	/**
	 * Removes all connections from the store.
	 */
	void clear();

	/**
	 * Stop all serial executors of connections from the store.
	 * 
	 * Add pending jobs to provided list.
	 * 
	 * @param pending list to add pending jobs
	 */
	void stop(List<Runnable> pending);

	/**
	 * Mark all connections as resumption required.
	 */
	void markAllAsResumptionRequired();

}
