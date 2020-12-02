/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation.
 *    Achim Kraus (Bosch Software Innovations GmbH) - move "peekData" into actual
 *                                                    DatagramSocketImpl implementation
 *                                                    to prevent the DatagramSocket to
 *                                                    use the erroneous internal
 *                                                    "old implementation mode".
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix deprecation of setTTL and getTTL
 *    Achim Kraus (Bosch Software Innovations GmbH) - implement multicast support
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.DatagramSocketImpl;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Implementation for simple basic methods.
 * 
 * Intended to be extended by an implementation for "in process message
 * exchange". Throws IOException with message containing "not supported" on
 * {@link #peek(InetAddress)}, {@link #setTTL(byte)}, {@link #getTTL()},
 * {@link #joinGroup(SocketAddress, NetworkInterface)}, and
 * {@link #leaveGroup(SocketAddress, NetworkInterface)}.
 * 
 * The method {@link DatagramSocketImpl#peekData(DatagramPacket)} is not
 * overridden here, because this method must be declared in the actual
 * implementation of {@link DatagramSocketImpl}. Otherwise the
 * {@code DatagramSocket} would use the internal "old implementation mode",
 * which has an error in {@link DatagramSocket#getReuseAddress()}
 * (ClassCastException).
 */
public abstract class AbstractDatagramSocketImpl extends DatagramSocketImpl {

	/**
	 * Map for socket options.
	 * 
	 * @see #setOption(int, Object)
	 * @see #getOption(int)
	 */
	private Map<Integer, Object> options = new ConcurrentHashMap<Integer, Object>();
	/**
	 * Time to live of socket.
	 * 
	 * @see #setTimeToLive(int)
	 * @see #getTimeToLive()
	 */
	private volatile int ttl;

	@Override
	public void setOption(int optID, Object value) throws SocketException {
		options.put(optID, value);
	}

	@Override
	public Object getOption(int optID) throws SocketException {
		return options.get(optID);
	}

	@Override
	protected void create() throws SocketException {
	}

	@Override
	protected int peek(InetAddress i) throws IOException {
		throw new IOException("peek(InetAddress) not supported!");
	}

	/**
	 * @deprecated already deprecated by {@link DatagramSocketImpl}.
	 */
	@Override
	@Deprecated
	protected void setTTL(byte ttl) throws IOException {
		throw new IOException("setTTL(byte) not supported!");
	}

	/**
	 * @deprecated already deprecated by {@link DatagramSocketImpl}.
	 */
	@Override
	@Deprecated
	protected byte getTTL() throws IOException {
		throw new IOException("getTTL() not supported!");
	}

	@Override
	protected void setTimeToLive(int ttl) throws IOException {
		this.ttl = ttl;
	}

	@Override
	protected int getTimeToLive() throws IOException {
		return ttl;
	}

	@Override
	protected void joinGroup(SocketAddress mcastaddr, NetworkInterface netIf) throws IOException {
		throw new IOException("joinGroup(SocketAddress, NetworkInterface) not supported!");
	}

	@Override
	protected void leaveGroup(SocketAddress mcastaddr, NetworkInterface netIf) throws IOException {
		throw new IOException("leaveGroup(SocketAddress, NetworkInterface) not supported!");
	}
}
