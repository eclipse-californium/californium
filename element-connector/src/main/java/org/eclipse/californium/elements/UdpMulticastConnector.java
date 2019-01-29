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

/**
 * {@link Connector} which inherits functionality of {@link UDPConnector}
 * replacing DatagramSocket with a MulticastSocket to receive multicast requests
 * in compliance to RFC7390 Group Communication for the Constrained Application
 * Protocol (CoAP) to the registered multicast group.
 */
public class UdpMulticastConnector extends UDPConnector {

	/**
	 * Multicast groups to join.
	 */
	private InetAddress[] multicastGroups;

	/**
	 * Creates a connector bound to given multicast group and IP Port
	 * 
	 * @param socketAddress local socket address
	 * @param multicastGroups multicast groups to join
	 */
	public UdpMulticastConnector(InetSocketAddress localAddress, InetAddress... multicastGroups) {
		super(localAddress);
		this.multicastGroups = multicastGroups;
	}

	public synchronized void start() throws IOException {
		if (this.running)
			return;

		// creates a multicast socket with the given port number
		MulticastSocket socket = new MulticastSocket(localAddr);

		// add the multicast socket to the specified multicast group for
		// listening to multicast requests
		for (InetAddress group : multicastGroups) {
			socket.joinGroup(group);
		}
		init(socket);
	}

}
