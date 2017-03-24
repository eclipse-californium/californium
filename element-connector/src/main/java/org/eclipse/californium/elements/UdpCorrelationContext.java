/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.net.InetAddress;
import java.net.InetSocketAddress;

/**
 * A correlation context using the IP address and port as identifying properties.
 *
 */
public class UdpCorrelationContext extends MapBasedCorrelationContext {

	/**
	 * Key for socket address.
	 * 
	 */
	public static final String KEY_SOCKET_ADDRESS = "SOCKET_ADDRESS";

	/**
	 * Creates a new correlation context for a socket address.
	 * 
	 * @param address The socket address.
	 * @throws NullPointerException if address is <code>null</code>.
	 */
	public UdpCorrelationContext(InetSocketAddress address) {

		if (address == null) {
			throw new NullPointerException("Address must not be null");
		} else {
			put(KEY_SOCKET_ADDRESS, address);
		}
	}

	/**
	 * Creates a new correlation context for an IP address and port.
	 * 
	 * @param address The IP address.
	 * @param port The port.
	 * @throws NullPointerException if address is <code>null</code>.
	 * @throws IllegalArgumentException if the port is out of the allowed range.
	 */
	public UdpCorrelationContext(InetAddress address, int port) {

		if (address == null) {
			throw new NullPointerException("Address must not be null");
		} else {
			InetSocketAddress socketAddress = new InetSocketAddress(address, port);
			put(KEY_SOCKET_ADDRESS, socketAddress);
		}
	}

	/**
	 * Gets the socket address.
	 * 
	 * @return The address.
	 */
	public InetSocketAddress getAddress() {
		return get(KEY_SOCKET_ADDRESS, InetSocketAddress.class);
	}

	@Override
	public String toString() {
		return String.format("UDP(%s)", getAddress());
	}
}
