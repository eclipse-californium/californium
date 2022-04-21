/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 ******************************************************************************/
package org.eclipse.californium.scandium;

import org.eclipse.californium.scandium.dtls.Connection;

/**
 * Listener for Connections life cycle.
 * 
 * The callbacks are execution within the serial execution of the provided
 * connection. Therefore it's important to not block, otherwise the performance
 * will be downgraded. Though access to the connection must generally be done
 * within that execution, copy the data you need and forward that to an other
 * executer.
 * 
 * <pre>
 * &#64;Override
 * public void onConnectionEstablished(Connection connection) {
 *    // access the data 
 *    // get immutable data 
 *    final ConnectionId id = connection.getConnectionId();
 *    // copy mutable data 
 *    final DatagramWriter writer = new DatagramWriter(1024);
 *    connection.write(writer);
 *    // delegate processing
 *    myAppExecuter.execute(new Runnable() {
 *       &#64;Override
 *       public void run() {
 *          // process the data asynchronous
 *          ... id.getBytes() ...
 *          ... writer.toByteArray() ...
 *       }
 *    });
 * }
 * </pre>
 */
public interface ConnectionListener {

	/**
	 * Callback, when DTLS session is established by a successful handshake.
	 * 
	 * @param connection connection, which's session gets established
	 */
	void onConnectionEstablished(Connection connection);

	/**
	 * Callback, when connection gets removed from the connection store.
	 * 
	 * Note: since 3.0, the {@link Connection} is now always cleaned up before
	 * it is used in this callback. {@link Connection#getPeerAddress()},
	 * {@link Connection#getOngoingHandshake()}, and
	 * {@link Connection#getDtlsContext()} (including the other variants) will
	 * return {@code null}.
	 * 
	 * @param connection connection, which gets removed from the connection
	 *            store
	 */
	void onConnectionRemoved(Connection connection);

	/**
	 * Callback, when the record sequence number have been updated.
	 * 
	 * @param connection connection
	 * @param writeSequenceNumber {@code true}, on updating the write sequence
	 *            number, {@code false}, on updating the receive sequence number
	 *            window.
	 * @return {@code true}, when maximum number of records is reached and the
	 *         connection is to be closed, {@code false}, otherwise.
	 * @since 3.0
	 */
	boolean onConnectionUpdatesSequenceNumbers(Connection connection, boolean writeSequenceNumber);

	/**
	 * Callback, when the record could not be decrypted caused by an error.
	 * 
	 * @param connection connection
	 * @return {@code true}, when maximum number of MAC errors is reached and the
	 *         connection is to be closed, {@code false}, otherwise.
	 * @since 3.0
	 */
	boolean onConnectionMacError(Connection connection);

	/**
	 * Callback, when a executor begin processing a connection.
	 * 
	 * @param connection connection
	 * @since 3.0
	 */
	void beforeExecution(Connection connection);

	/**
	 * Callback, when a connection changed its state.
	 * 
	 * @param connection connection
	 * @since 3.0
	 */
	void updateExecution(Connection connection);

	/**
	 * Callback, after a executor processed a connection.
	 * 
	 * @param connection connection
	 * @since 3.0
	 */
	void afterExecution(Connection connection);

}
