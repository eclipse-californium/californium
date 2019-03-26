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
	 * Address of network interface to be used to receive multicast packets
	 */
	private InetAddress intfAddress;

	/**
	 * Multicast groups to join.
	 */
	private InetAddress[] multicastGroups;

	/**
	 * Creates a connector bound to given multicast group and IP Port, using the specified network interface for
	 * receiving multicast packets
	 *
	 * Note: This constructor that allows you to specify a network interface was added to mitigate the issue described
	 * at https://github.com/eclipse/californium/issues/872. If you run into trouble using this approach, a own
	 * {@link UdpMulticastConnector} implementation may be used with a proper initialisation of the {@link MulticastSocket}
	 * in an overriden {@link #start()} method for that case.
	 *
	 * @param intfAddress address of interface to use to receive multicast packets
	 * @param localAddress local socket address
	 * @param multicastGroups multicast groups to join
	 */
	public UdpMulticastConnector(InetAddress intfAddress, InetSocketAddress localAddress, InetAddress... multicastGroups) {
		super(localAddress);
		this.intfAddress = intfAddress;
		this.multicastGroups = multicastGroups;
	}

	/**
	 * Creates a connector bound to given multicast group and IP Port, using the default (any) network interface for
	 * receiving multicast packets
	 *
	 * Note: You might run into issues described at https://bugs.java.com/bugdatabase/view_bug.do?bug_id=4701650 if you
	 * do not specify a network interface. See also https://github.com/eclipse/californium/issues/872.
	 *
	 * @param localAddress local socket address
	 * @param multicastGroups multicast groups to join
	 */
	public UdpMulticastConnector(InetSocketAddress localAddress, InetAddress... multicastGroups) {
		this(null, localAddress, multicastGroups);
	}

	public synchronized void start() throws IOException {
		if (this.running)
			return;

		// creates a multicast socket with the given port number
		MulticastSocket socket = new MulticastSocket(localAddr);

		// if an interface specified by a non-wildcard address was supplied we set it on the socket
		if (intfAddress != null && !intfAddress.isAnyLocalAddress()) {
			socket.setInterface(intfAddress);
		}

		// add the multicast socket to the specified multicast group for
		// listening to multicast requests
		for (InetAddress group : multicastGroups) {
			socket.joinGroup(group);
		}
		init(socket);
	}

}
