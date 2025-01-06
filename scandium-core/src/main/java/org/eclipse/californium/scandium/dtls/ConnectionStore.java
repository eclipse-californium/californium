/*******************************************************************************
 * Copyright (c) 2015 Sierra Wireless
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
 *    Simon Bernard (Sierra Wireless) - Initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix session resumption with 
 *                                                    session cache. issue #712
 *    Achim Kraus (Bosch Software Innovations GmbH) - add putEstablishedSession
 *                                                    for faster find
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantReadWriteLock.ReadLock;
import java.util.concurrent.locks.ReentrantReadWriteLock.WriteLock;

import org.eclipse.californium.scandium.ConnectionListener;

/**
 * A connection.
 * 
 * @since 4.0 (Rename ResumptionSupportingConnectionStore into ConnectionStore)
 */
public interface ConnectionStore extends Iterable<Connection> {

	/**
	 * Set connection listener.
	 * 
	 * @param listener connection listener
	 */
	void setConnectionListener(ConnectionListener listener);

	/**
	 * Attach connection id generator.
	 * <p>
	 * Must be called before {@link #put(Connection)}.
	 * 
	 * @param connectionIdGenerator connection id generator. If {@code null} a
	 *            default connection id generator is created.
	 * @throws IllegalStateException if {@link #attach(ConnectionIdGenerator)}
	 *             was already called before.
	 */
	void attach(ConnectionIdGenerator connectionIdGenerator);

	/**
	 * Save connections.
	 * <p>
	 * Connector must be stopped before saving connections. The connections are
	 * removed after saving.
	 * <p>
	 * <b>Note:</b> the stream will contain not encrypted critical credentials.
	 * It is required to protect this data before exporting it.
	 * 
	 * @param out output stream to save connections
	 * @param maxQuietPeriodInSeconds maximum quiet period of the connections in
	 *            seconds. Connections without traffic for that time are skipped
	 *            during serialization.
	 * @return number of save connections.
	 * @throws IOException if an io-error occurred
	 * @throws IllegalStateException if connector is running
	 * @since 3.4
	 */
	int saveConnections(OutputStream out, long maxQuietPeriodInSeconds) throws IOException;

	/**
	 * Load connections.
	 * <p>
	 * <b>Note:</b> the stream contain not encrypted critical credentials. It is
	 * required to protect this data.
	 * 
	 * @param in input stream to load connections
	 * @param delta adjust-delta for nano-uptime. In nanoseconds. The stream
	 *            contains timestamps based on nano-uptime. On loading, this
	 *            requires to adjust these timestamps according the current nano
	 *            uptime and the passed real time.
	 * @return number of loaded connections.
	 * @throws IOException if an io-error occurred. Indicates, that further
	 *             loading should be aborted.
	 * @throws IllegalArgumentException if an reading error occurred. Continue
	 *             to load other connection-stores may work, that may be not
	 *             affected by this error.
	 * @since 3.4
	 */
	int loadConnections(InputStream in, long delta) throws IOException;

	/**
	 * Restore connection.
	 * 
	 * @param connection connection to restore.
	 * @return {@code true}, on success, {@code false}, otherwise.
	 * @since 3.0
	 */
	boolean restore(Connection connection);

	/**
	 * Puts a connection into the store.
	 * <p>
	 * The connection is primary associated with its connection id
	 * {@link Connection#getConnectionId()}. If the connection doesn't have a
	 * connection id, a unique connection id created with the
	 * {@link #attach(ConnectionIdGenerator)} is assigned. If the connection has
	 * also a peer address and/or a established session, it get's associated
	 * with that as well. It removes also an other connection from these
	 * associations.
	 * <p>
	 * <b>Note:</b> {@link #attach(ConnectionIdGenerator)} must be called
	 * before!
	 * 
	 * @param connection the connection to store
	 * @return {@code true} if the connection could be stored, {@code false},
	 *         otherwise (e.g. because the store's capacity is exhausted)
	 * @throws IllegalStateException if the connection is not executing, the
	 *             connection ids are exhausted, or the connection id is empty
	 *             or in use, or the connection id generator is not
	 *             {@link #attach(ConnectionIdGenerator)} before!
	 * @see #get(ConnectionId)
	 * @see #get(InetSocketAddress)
	 * @see #find(SessionId)
	 */
	boolean put(Connection connection);

	/**
	 * Update a connection in the store.
	 * <p>
	 * Update the last-access time to prevent connection from being evicted.
	 * Associate a new peer address with this connection, and removes other
	 * connections from that association.
	 * 
	 * @param connection the connection to update.
	 * @param newPeerAddress the (new) peer address. If {@code null}, don't
	 *            update the connection's address.
	 * @return {@code true}, if updated, {@code false}, otherwise.
	 */
	boolean update(Connection connection, InetSocketAddress newPeerAddress);

	/**
	 * Associates the connection with the session id.
	 * <p>
	 * Removes previous associated connection from store, if no second level
	 * session store is used.
	 * 
	 * @param connection connection of established session
	 * @throws IllegalArgumentException if connection has no established session
	 * @since 3.0 (the parameter session is removed)
	 */
	void putEstablishedSession(Connection connection);

	/**
	 * Remove the association of the connection with the session id.
	 * <p>
	 * Removes associated connection from store, if no second level session
	 * store is used.
	 * 
	 * @param connection connection of established session
	 * @throws IllegalArgumentException if connection has no established session
	 * @since 3.0 (the parameter session is removed)
	 */
	void removeFromEstablishedSessions(Connection connection);

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
	 * @return the matching connection or {@code null}, if no connection exists
	 *         for the given address
	 */
	Connection get(InetSocketAddress peerAddress);

	/**
	 * Gets a connection by its connection id.
	 * 
	 * @param cid connection id
	 * @return the matching connection or {@code null}, if no connection exists
	 *         for the given connection id
	 */
	Connection get(ConnectionId cid);

	/**
	 * Finds a connection by its session ID.
	 * 
	 * @param id the session ID
	 * @return the matching connection or {@code null}, if no connection with an
	 *         established session with the given ID exists
	 */
	DTLSSession find(SessionId id);

	/**
	 * Removes a connection from the store and optional from the session store.
	 * 
	 * @param connection the connection to remove
	 * @param removeFromSessionStore {@code true} if the session of the
	 *            connection should be removed from the session store,
	 *            {@code false}, otherwise
	 * @return {@code true}, if the connection was removed, {@code false},
	 *         otherwise
	 */
	boolean remove(Connection connection, boolean removeFromSessionStore);

	/**
	 * Removes all connections from the store.
	 */
	void clear();

	/**
	 * Stop all serial executors of connections from the store.
	 * <p>
	 * Add pending jobs to provided list.
	 * 
	 * @param pending list to add pending jobs
	 */
	void stop(List<Runnable> pending);

	/**
	 * Mark all connections as resumption required.
	 */
	void markAllAsResumptionRequired();

	/**
	 * Get "weakly consistent" iterator over all connections.
	 * <p>
	 * The iterator is a "weakly consistent" iterator that will never throw
	 * {@link ConcurrentModificationException}, and guarantees to traverse
	 * elements as they existed upon construction of the iterator, and may (but
	 * is not guaranteed to) reflect any modifications subsequent to
	 * construction.
	 * 
	 * @return "weakly consistent" iterator
	 */
	Iterator<Connection> iterator();

	/**
	 * Shrinks the connection store.
	 * 
	 * @param calls number of calls
	 * @param running {@code true}, if the related connector is running,
	 *            {@code false}, if the connector has stopped and the shrinking
	 *            may be abandoned.
	 * @since 4.0 (moved from obsolete ReadWriteLockConnectionStore)
	 */
	void shrink(int calls, AtomicBoolean running);

	/**
	 * Set executor to pass to new connections.
	 * 
	 * @param executor executor to pass to new connections. May be {@code null}.
	 * @since 4.0 (moved from obsolete ReadWriteLockConnectionStore)
	 */
	void setExecutor(ExecutorService executor);

	/**
	 * Get read lock.
	 * 
	 * @return read lock
	 * @since 4.0 (moved from obsolete ReadWriteLockConnectionStore)
	 */
	ReadLock readLock();

	/**
	 * Get write lock.
	 * 
	 * @return write lock
	 * @since 4.0 (moved from obsolete ReadWriteLockConnectionStore)
	 */
	WriteLock writeLock();

}
