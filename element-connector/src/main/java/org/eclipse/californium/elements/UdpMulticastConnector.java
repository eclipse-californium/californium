/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.SocketException;

/**
 * {@link Connector} which inherits functionality of {@link UDPConnector}
 * replacing DatagramSocket with a MulticastSocket to receive multicast requests
 * in compliance to RFC7390 Group Communication for the Constrained Application
 * Protocol (CoAP) to the registered multicast group.
 */
public class UdpMulticastConnector extends UDPConnector {

	/**
	 * Multicast socket used by the connector.
	 */
	private MulticastSocket socket;

	/**
	 * Multicast groups to join.
	 */
	private InetAddress[] multicastGroups;

	/**
	 * Creates a connector bound to given multicast group and IP Port
	 *
	 * @param localAddress local socket address
	 * @param multicastGroups multicast groups to join
	 * @throws IOException if an I/O exception occurs while creating the MulticastSocket
	 */
	public UdpMulticastConnector(InetSocketAddress localAddress, InetAddress... multicastGroups) throws IOException {
		super(localAddress);
		this.socket = new MulticastSocket(localAddress);
		this.multicastGroups = multicastGroups;
	}

	/**
	 * Start the connector
	 *
	 * Note: You may need to set the interface used for multicast manually before calling this
	 * (see https://github.com/eclipse/californium/issues/872).
	 *
	 * @throws IOException if an I/O exception occurs while joining the multicast group or while
	 * initialising the UDP connector with the multicast socket
	 */
	public synchronized void start() throws IOException {
		if (this.running)
			return;

		// add the multicast socket to the specified multicast group for
		// listening to multicast requests
		for (InetAddress group : multicastGroups) {
			this.socket.joinGroup(group);
		}
		init(this.socket);
	}

	/**
	 * Retrieve the address of the network interface used for multicast packets.
	 *
	 * @return the address of the network interface used for multicast as an InetAddress object
	 * @throws SocketException if the socket is already closed
	 */
	public InetAddress getMulticastInterface() throws SocketException {
		return this.socket.getInterface();
	}

	/**
	 * Update the address of the network interface used for multicast packets.
	 *
	 * @param inf the address of the new network interface as a InetAddress object
	 * @throws SocketException if the socket is already closed
	 */
	public void setMulticastInterface(InetAddress inf) throws SocketException {
		this.socket.setInterface(inf);
	}
}
