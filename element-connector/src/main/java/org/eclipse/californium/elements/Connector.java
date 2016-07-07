/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.io.IOException;
import java.net.InetSocketAddress;

/**
 * A managed interface for exchanging messages between networked clients and a
 * server application.
 * 
 * An implementation usually binds to a socket on a local network interface in order
 * to communicate with clients. After the {@link #start()} method has been invoked,
 * applications can use the {@link #send(RawData)} method to send messages
 * (wrapped in a {@link RawData} object) to a client via the network. Processing of
 * messages received from clients is delegated to the handler registered via the
 * {@link #setRawDataReceiver(RawDataChannel)} method.
 * 
 * Implementations of the {@link #send(RawData)} method should be non-blocking
 * to allow the server application to continue working on other tasks. This could
 * be achieved by buffering outbound messages in a queue and off-loading the sending
 * of messages via the network to a separate <code>Thread</code>.
 */
public interface Connector {

	/**
	 * Starts the connector.
	 * 
	 * The connector might bind to a socket for instance.
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public void start() throws IOException;

	/**
	 * Stops the connector.
	 * 
	 * All resources such as threads or bound sockets on network
	 * interfaces should be stopped and released. A connector that has
	 * been stopped using this method can be started again using the
	 * {@link #start()} method.
	 */
	public void stop();

	/**
	 * Stops the connector and cleans up any leftovers.
	 * 
	 * A destroyed connector cannot be expected to be able to start again.
	 */
	public void destroy();

	/**
	 * Sends a raw message to a client via the network.
	 * 
	 * This should be a non-blocking operation.
	 * 
	 * @param msg the message to be sent
	 */
	public void send(RawData msg);

	/**
	 * Sets the handler for incoming messages.
	 * 
	 * The handler's {@link RawDataChannel#receiveData(RawData)} method
	 * will be called whenever a new message from a client has been received
	 * via the network.
	 * 
	 * @param messageHandler the message handler
	 */
	public void setRawDataReceiver(RawDataChannel messageHandler);
	
	
	/**
	 * Gets the address of the socket this connector is bound to.
	 *
	 * @return the address
	 */
	public InetSocketAddress getAddress();
}
