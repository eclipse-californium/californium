package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;

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

	/**
	 * Mark all connections as resumption required.
	 * 
	 */
	void markAllAsResumptionRequired();
	
}
