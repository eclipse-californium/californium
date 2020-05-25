/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.io.IOException;
import java.net.BindException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.SocketException;

import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link Connector} which inherits functionality of {@link UDPConnector}
 * replacing DatagramSocket with a MulticastSocket to receive multicast requests
 * in compliance to RFC7390 Group Communication for the Constrained Application
 * Protocol (CoAP) to the registered multicast group.
 * <p>
 * Note: since 2.3, a connector joining only one multicast group, maybe used as
 * "multicast receiver". In that case the {@link #getAddress()} will return this
 * multicast group. If configured as broadcast receiver, it could also be used
 * as "multicast receiver".
 * 
 * This enables to setup systems, which listen on different ports for multicast
 * than respond on unicast. It allows to host multiple coap-multicast-server to
 * be hosted on the same peer.
 * </p>
 * <p>
 * <a href=
 * "https://mailarchive.ietf.org/arch/msg/core/7P8wrsahiuCriozrYc_fVyS6mzg/">
 * Core - mailinglist - Klaus Hartke: Multicast CoAP</a>
 *
 * <pre>
 * +---------------+                +-----------------+
 * |               |    request    _|_                |
 * |               |        .---> /   \   224.0.1.187 |
 * |              _|_      /      \___/ --.   :9999   |
 * | 192.168.0.1 /   \ ---´         |      \          |
 * |   :54321    \___/ <---.       _|_     /  rewrite |
 * |               |        \     /   \ <-´           |
 * |               |         `--- \___/ 192.168.0.100 |
 * |               |    response    |         :5683   |
 * +---------------+                +-----------------+
 *       Client                           Server
 * </pre>
 * </p>
 * <p>
 * To setup a system, which listens on the same port for unicast and multicast,
 * and reliable distinguishs between them, seems to be not too easy with java.
 * Generally try to omit to use the "any" address at any place. Neither for the
 * unicast socket nor the multicast bind-address. For IPv6 - multicast with
 * link-scope, this may fail caused by
 * <a href="https://bugs.openjdk.java.net/browse/JDK-8210493">Bind to node- or
 * linklocal ipv6 multicast address fails</a>. Please always check your server
 * logs for messages of the pattern "received request {} via different multicast
 * groups ({} != {})!". That indicates, that the multicast request is accidently
 * received by multiple sockets and so unicast request may not be reliable
 * distinguished.
 * </p>
 * <p>
 * <a href=
 * "https://stackoverflow.com/questions/19392173/multicastsocket-constructors-and-binding-to-port-or-socketaddress">
 * Stackoverflow - MulticastSocket - Constructors binding to port or
 * socketaddress</a>
 * </p>
 * <p>
 * Note: using the multicast address as bind address may work as mention in the
 * above article, or not :-). If intended to be used, please verify that it
 * works on your environment.
 * </p>
 * 
 * @since 2.3 {@link #getAddress()} will return the multicast group, if exactly
 *        one multicast group is provided.
 */
public class UdpMulticastConnector extends UDPConnector {

	public static final Logger LOGGER = LoggerFactory.getLogger(UdpMulticastConnector.class);

	/**
	 * Address of network interface to be used to receive multicast packets
	 */
	private InetAddress intfAddress;

	/**
	 * Multicast groups to join.
	 */
	private InetAddress[] multicastGroups;

	/**
	 * {@code true}, to disable loopback mode, {@false}, otherwise.
	 * 
	 * @since 2.3
	 */
	private boolean loopbackDisable;

	/**
	 * Creates a connector bound to given multicast group and IP Port, using the
	 * specified network interface for receiving multicast packets
	 *
	 * Note: This constructor that allows you to specify a network interface was
	 * added to mitigate the issue described at
	 * https://github.com/eclipse/californium/issues/872. If you run into
	 * trouble using this approach, a own {@link UdpMulticastConnector}
	 * implementation may be used with a proper initialisation of the
	 * {@link MulticastSocket} in an overriden {@link #start()} method for that
	 * case.
	 *
	 * @param intfAddress address of interface to use to receive multicast
	 *            packets
	 * @param localAddress local socket address. If a broadcast is used, and the
	 *            multicastGroups are empty or {@code null}, this connector
	 *            maybe used as "multicast receiver". If a multicast address is
	 *            used and the multicastGroups are empty or {@code null}, the
	 *            local address is also used as multicast griou to join.
	 * @param multicastGroups multicast groups to join. If no broadcast nor
	 *            multicast address is used as local address, this list must not
	 *            be empty.
	 * @throws IllegalArgumentException if local address is not a broadcast nor
	 *             multicast address and the multicast groups are empty or
	 *             {@code null}.
	 */
	public UdpMulticastConnector(InetAddress intfAddress, InetSocketAddress localAddress,
			InetAddress... multicastGroups) {
		super(localAddress);
		setReuseAddress(true);
		this.intfAddress = intfAddress;
		this.multicastGroups = multicastGroups;
		boolean noGroups = multicastGroups == null || multicastGroups.length == 0;
		if (NetworkInterfacesUtil.isBroadcastAddress(localAddress.getAddress())) {
			this.multicast = noGroups;
		} else {
			if (noGroups && localAddress.getAddress().isMulticastAddress()) {
				this.multicastGroups = new InetAddress[] { localAddress.getAddress() };
				noGroups = false;
			}
			if (noGroups) {
				if (localAddress.getAddress().isMulticastAddress()) {
					this.multicastGroups = new InetAddress[] { localAddress.getAddress() };
				} else {
					throw new IllegalArgumentException("missing multicast address to join!");
				}
			}
			this.multicast = this.multicastGroups.length == 1;
			if (multicast) {
				this.effectiveAddr = new InetSocketAddress(this.multicastGroups[0],
						localAddress != null ? localAddress.getPort() : 0);
			}
		}
	}

	/**
	 * Creates a connector bound to given multicast group and IP Port, using the
	 * default (any) network interface for receiving multicast packets
	 *
	 * Note: You might run into issues described at
	 * https://bugs.java.com/bugdatabase/view_bug.do?bug_id=4701650 if you do
	 * not specify a network interface. See also
	 * https://github.com/eclipse/californium/issues/872.
	 *
	 * @param localAddress local socket address. If a broadcast is used, and the
	 *            multicastGroups are empty or {@code null}, this connector
	 *            maybe used as "multicast receiver". If a multicast address is
	 *            used and the multicastGroups are empty or {@code null}, the
	 *            local address is also used as multicast griou to join.
	 * @param multicastGroups multicast groups to join. If no broadcast nor
	 *            multicast address is used as local address, this list must not
	 *            be empty.
	 * @throws IllegalArgumentException if local address is not a broadcast nor
	 *             multicast address and the multicast groups are empty or
	 *             {@code null}.
	 */
	public UdpMulticastConnector(InetSocketAddress localAddress, InetAddress... multicastGroups) {
		this(null, localAddress, multicastGroups);
	}

	/**
	 * Set loopback mode.
	 * 
	 * Applied on executing {@link #start()}.
	 * 
	 * @param disable passed to {@link MulticastSocket#setLoopbackMode(boolean)}
	 *            on executing {@link #start()}.
	 */
	public void setLoopbackMode(boolean disable) {
		this.loopbackDisable = disable;
	}

	@Override
	public synchronized void start() throws IOException {
		if (this.running)
			return;

		InetAddress effectiveInterface = localAddr.getAddress();
		// creates a multicast socket with the given port number
		MulticastSocket socket = new MulticastSocket(null);
		socket.setLoopbackMode(loopbackDisable);
		try {
			socket.bind(localAddr);
			LOGGER.info("socket {}, loopback mode {}",
					StringUtil.toString((InetSocketAddress) socket.getLocalSocketAddress()), socket.getLoopbackMode());
		} catch (BindException ex) {
			socket.close();
			LOGGER.error("can't bind to {}", StringUtil.toString(localAddr));
			throw ex;
		} catch (SocketException ex) {
			socket.close();
			LOGGER.error("can't bind to {}", StringUtil.toString(localAddr));
			throw ex;
		}

		// if an interface specified by a non-wildcard address was supplied we
		// set it on the socket
		if (intfAddress != null && !intfAddress.isAnyLocalAddress()) {
			try {
				socket.setInterface(intfAddress);
				effectiveInterface = intfAddress;
				LOGGER.info("interface {}", StringUtil.toString(intfAddress));
			} catch (SocketException ex) {
				LOGGER.error("error: multicast set interface", ex);
			}
		}

		// add the multicast socket to the specified multicast group for
		// listening to multicast requests
		if (multicastGroups != null) {
			for (InetAddress group : multicastGroups) {
				try {
					socket.joinGroup(group);
					LOGGER.info("joined group {}", StringUtil.toString(group));
				} catch (SocketException ex) {
					socket.close();
					if (group instanceof Inet4Address) {
						if ((effectiveInterface.isAnyLocalAddress() && !NetworkInterfacesUtil.isAnyIpv4())
								|| (effectiveInterface instanceof Inet6Address)) {
							throw new SocketException("IPv6 only interface doesn't support IPv4 multicast!");
						}
					} else if (group instanceof Inet6Address) {
						if ((effectiveInterface.isAnyLocalAddress() && !NetworkInterfacesUtil.isAnyIpv6())
								|| (effectiveInterface instanceof Inet4Address)) {
							throw new SocketException("IPv4 only interface doesn't support IPv6 multicast!");
						}
					}
					throw ex;
				}
			}
		}
		init(socket);
		if (multicast && multicastGroups != null && multicastGroups.length == 1) {
			this.effectiveAddr = new InetSocketAddress(multicastGroups[0], socket.getLocalPort());
		}
	}
}
