/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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
 * A connector connects a server to the network. A connector might listen on a
 * port on a network interface for instance. Only primitive data wrapped in a
 * {@link RawData} flows through the send and receive methods of a connector.
 * <p>
 * The send method of a connector should be non-blocking to allow the server to
 * continue with another task. Usually this can be achieved by using separate
 * thread for sending and receiving data, e.g., to a socket.
 */
public interface Connector {

	/**
	 * Starts the connector. The connector might bind to a network interface and
	 * a port for instance.
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public void start() throws IOException;

	/**
	 * Stops the connector. All resources such as threads or ports on network
	 * interfaces should be stopped and released. A stopped connector should be
	 * able to be started again.
	 */
	public void stop();

	/**
	 * Stops the connector and cleans up any leftovers. A destroyed connector
	 * cannot be expected to be able to start again.
	 */
	public void destroy();

	/**
	 * Send the specified data over the connector. This should be a non-blocking
	 * function.
	 * 
	 * @param msg the msg
	 */
	public void send(RawData msg);

	/**
	 * Sets the raw data receiver. This receiver will be called whenever a new
	 * message has arrived.
	 * 
	 * @param receiver the new raw data receiver
	 */
	public void setRawDataReceiver(RawDataChannel receiver);
	
	
	/**
	 * Gets the address of this connector.
	 *
	 * @return the address
	 */
	public InetSocketAddress getAddress();
}
