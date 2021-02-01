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
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.List;

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
 * multicast group. If configured as broadcast receiver without additional
 * multicast groups, it could also be used as "multicast receiver".
 * 
 * This enables to setup systems, which listen on ports for multicast requests
 * different from the port to respond on unicast. It allows to host multiple
 * coap-multicast-server to be hosted on the same peer.
 * 
 * To use a {@link UdpMulticastConnector} as multicast receiver,
 * {@link Builder#setMulticastReceiver(boolean)} must be set to {@code true},
 * and the {@link UdpMulticastConnector} must be added to the related unicast
 * {@link UDPConnector} using
 * {@link UDPConnector#addMulticastReceiver(UdpMulticastConnector)}.
 * 
 * A multicast-receiver is not intended to send messages, it only receives them.
 * Therefore it can only be added as multicast-receiver to an
 * {@link UDPConnector}. It can not be used as connector for an
 * {@code CoapEndpoint}, nor can other multicast-receiver be added to a
 * multicast-receiver.
 * </p>
 * <p>
 * <a href=
 * "https://mailarchive.ietf.org/arch/msg/core/7P8wrsahiuCriozrYc_fVyS6mzg/">
 * Core - mailinglist - Klaus Hartke: Multicast CoAP</a>
 * </p>
 * 
 * <pre>
 * +---------------+                +-----------------+
 * |               |    request    _|_                |
 * |               |        .---&gt; /   \   224.0.1.187 |
 * |              _|_      /      \___/ --.   :9999   |
 * | 192.168.0.1 /   \ ---´         |      \          |
 * |   :54321    \___/ &lt;---.       _|_     /  rewrite |
 * |               |        \     /   \ &lt;|
 * |               |         `--- \___/ 192.168.0.100 |
 * |               |    response    |         :5683   |
 * +---------------+                +-----------------+
 *       Client                           Server
 * </pre>
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
	 * Network interface of socket for outgoing multicast traffic. May be
	 * {@code null}. Alternative to {@link #outgoingAddress}.
	 * 
	 * @since 2.4
	 */
	private NetworkInterface outgoingInterface;

	/**
	 * Address of network interface for outgoing multicast traffic. May be
	 * {@code null}. Alternative to {@link #outgoingInterface}.
	 * 
	 * @since 2.4
	 */
	private InetAddress outgoingAddress;

	/**
	 * List of multicast groups and network interfaces to join.
	 * 
	 * @since 2.4
	 */
	private List<Join> groups = new ArrayList<Join>();

	/**
	 * {@code true}, to disable loopback mode, {@false}, otherwise.
	 * 
	 * @since 2.3
	 */
	private boolean loopbackDisable;

	/**
	 * Creates a connector bound to given multicast group and IP Port.
	 *
	 * Note: You might run into issues described at
	 * https://bugs.java.com/bugdatabase/view_bug.do?bug_id=4701650 if you do
	 * not specify a network interface. See also
	 * https://github.com/eclipse/californium/issues/872.
	 * 
	 * @param localSocketAddress local socket address. If a broadcast is used,
	 *            and the groups are empty, this connector maybe used as
	 *            "multicast receiver". If a multicast address is used and the
	 *            multicastGroups are empty or {@code null}, the local address
	 *            is also used as multicast group to join.
	 * @param outgoingAddress address for outgoing multicast traffic, may be
	 *            {@code null}. Alternative to outgoing interface.
	 * @param outgoingInterface interface for outgoing multicast traffic, may be
	 *            {@code null}. Alternative to outgoing address.
	 * @param groups list of multicast groups and network interfaces to join. If
	 *            no broadcast nor multicast address is used as local address,
	 *            this list must not be empty.
	 * @throws IllegalArgumentException if multicastReceiver is requested but
	 *             not exactly one broadcast or multicast address is provided.
	 */
	private UdpMulticastConnector(InetSocketAddress localSocketAddress, InetAddress outgoingAddress,
			NetworkInterface outgoingInterface, List<Join> groups, boolean multicastReceiver) {
		super(localSocketAddress);
		setReuseAddress(true);
		this.outgoingInterface = outgoingInterface;
		this.outgoingAddress = outgoingAddress;
		this.groups.addAll(groups);
		InetAddress localAddress = localSocketAddress.getAddress();
		boolean noGroups = this.groups.isEmpty();
		if (NetworkInterfacesUtil.isBroadcastAddress(localAddress)) {
			if (multicastReceiver) {
				if (noGroups) {
					this.multicast = true;
				} else {
					throw new IllegalArgumentException(
							"Broadcast and additional multicast addresses are nor supported for multicast receiver function!");
				}
			}
		} else {
			if (noGroups) {
				if (localAddress.isMulticastAddress()) {
					this.groups.add(new Join(localAddress));
					noGroups = false;
				} else {
					throw new IllegalArgumentException("missing multicast address to join!");
				}
			}
			if (multicastReceiver) {
				if (this.groups.size() == 1) {
					multicast = true;
					this.effectiveAddr = new InetSocketAddress(this.groups.get(0).multicastGroup,
							localSocketAddress != null ? localSocketAddress.getPort() : 0);
				} else {
					throw new IllegalArgumentException(
							"Multiple multicast addresses are nor supported for multicast receiver function!");
				}
			}
		}
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

	/**
	 * Checks, if connection is multicast receiver.
	 * 
	 * @return {@code true}, if connector is multicast receiver, {@code false},
	 *         otherwise.
	 * @since 3.0
	 */
	public boolean isMutlicastReceiver() {
		return multicast;
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

		// if an interface specified by a non-wildcard address was supplied
		// we set it on the socket
		if (outgoingAddress != null && !outgoingAddress.isAnyLocalAddress()) {
			try {
				socket.setInterface(outgoingAddress);
				effectiveInterface = outgoingAddress;
				LOGGER.info("interface {}", StringUtil.toString(outgoingAddress));
			} catch (SocketException ex) {
				LOGGER.error("error: multicast set interface", ex);
			}
		} else if (outgoingInterface != null) {
			try {
				socket.setNetworkInterface(outgoingInterface);
				LOGGER.info("interface {}", outgoingInterface.getDisplayName());
			} catch (SocketException ex) {
				LOGGER.error("error: multicast set interface", ex);
			}
		}

		// add the multicast socket to the specified multicast group for
		// listening to multicast requests
		for (Join join : groups) {
			try {
				boolean supportJoinWithInterface = true;
				if (join.networkInterface != null) {
					try {
						socket.joinGroup(new InetSocketAddress(join.multicastGroup, 0), join.networkInterface);
						LOGGER.info("joined group {} with {}", StringUtil.toString(join.multicastGroup),
								join.networkInterface.getDisplayName());
					} catch (UnsupportedOperationException ex) {
						supportJoinWithInterface = false;
					}
				}
				if (!supportJoinWithInterface || join.networkInterface == null) {
					socket.joinGroup(join.multicastGroup);
					LOGGER.info("joined group {}", StringUtil.toString(join.multicastGroup));
				}
			} catch (SocketException ex) {
				socket.close();
				if (join.multicastGroup instanceof Inet4Address) {
					if ((effectiveInterface.isAnyLocalAddress() && !NetworkInterfacesUtil.isAnyIpv4())
							|| (effectiveInterface instanceof Inet6Address)) {
						throw new SocketException("IPv6 only interface doesn't support IPv4 multicast!");
					}
				} else if (join.multicastGroup instanceof Inet6Address) {
					if ((effectiveInterface.isAnyLocalAddress() && !NetworkInterfacesUtil.isAnyIpv6())
							|| (effectiveInterface instanceof Inet4Address)) {
						throw new SocketException("IPv4 only interface doesn't support IPv6 multicast!");
					}
				}
				throw ex;
			}
		}
		init(socket);
		if (multicast && groups.size() == 1) {
			this.effectiveAddr = new InetSocketAddress(groups.get(0).multicastGroup, socket.getLocalPort());
		}
	}

	private static class Join {

		private final InetAddress multicastGroup;
		private final NetworkInterface networkInterface;

		private Join(InetAddress multicastGroup) {
			this.multicastGroup = multicastGroup;
			this.networkInterface = null;
		}

		private Join(InetAddress multicastGroup, NetworkInterface networkInterface) {
			this.multicastGroup = multicastGroup;
			this.networkInterface = networkInterface;
		}
	}

	/**
	 * Builder for {@link UdpMulticastConnector}.
	 * 
	 * @since 2.4
	 */
	public static class Builder {

		private InetSocketAddress localSocketAddress;
		private InetAddress outgoingAddress;
		private NetworkInterface outgoingInterface;
		private List<Join> groups = new ArrayList<Join>();
		private boolean multicastReceiver;

		/**
		 * Create Builder.
		 */
		public Builder() {

		}

		/**
		 * Get local socket address.
		 * 
		 * @return local socket address.
		 */
		public InetSocketAddress getLocalAddress() {
			return localSocketAddress;
		}

		/**
		 * Set port and any-address to bind the connector.
		 * 
		 * @param port port to bind
		 * @return this builder for command chaining
		 */
		public Builder setLocalPort(int port) {
			this.localSocketAddress = new InetSocketAddress(port);
			return this;
		}

		/**
		 * Set address and port to bind the connector.
		 * 
		 * @param localAddress address and port ot bind. If a broadcast address
		 *            is used without adding multicast group, this connector may
		 *            be used as multicast receiver. if a multicast address is
		 *            used without adding multicast group, the connector joins
		 *            this group of the local address and may be used as
		 *            multicast receiver.
		 * @param port port to bind
		 * @return this builder for command chaining
		 * @throws NullPointerException if local socket address is {@code null}
		 */
		public Builder setLocalAddress(InetAddress localAddress, int port) {
			if (localAddress == null) {
				throw new NullPointerException("local address must not be null!");
			}
			this.localSocketAddress = new InetSocketAddress(localAddress, port);
			return this;
		}

		/**
		 * Set socket address to bind the connector.
		 * 
		 * @param localSocketAddress address and port ot bind. If a broadcast
		 *            address is used without adding multicast group, this
		 *            connector may be used as multicast receiver. if a
		 *            multicast address is used without adding multicast group,
		 *            the connector joins this group of the local address and
		 *            may be used as multicast receiver.
		 * @return this builder for command chaining
		 * @throws NullPointerException if local socket address is {@code null}
		 */
		public Builder setLocalAddress(InetSocketAddress localSocketAddress) {
			if (localSocketAddress == null) {
				throw new NullPointerException("local socket address must not be null!");
			}
			this.localSocketAddress = localSocketAddress;
			return this;
		}

		/**
		 * Set address for outgoing multicast traffic.
		 * 
		 * Resets {@link #outgoingInterface} to {@code null}.
		 * 
		 * @param outgoingAddress outgoing address for multicast traffic.
		 * @return this builder for command chaining
		 */
		public Builder setOutgoingMulticastInterface(InetAddress outgoingAddress) {
			this.outgoingAddress = outgoingAddress;
			this.outgoingInterface = null;
			return this;
		}

		/**
		 * Set address for outgoing multicast traffic.
		 * 
		 * Resets {@link #outgoingAddress} to {@code null}.
		 * 
		 * @param outgoingInterface outgoing interface for multicast traffic.
		 * @return this builder for command chaining
		 */
		public Builder setOutgoingMulticastInterface(NetworkInterface outgoingInterface) {
			this.outgoingAddress = null;
			this.outgoingInterface = outgoingInterface;
			return this;
		}

		/**
		 * Add multicast group to join.
		 * 
		 * If only one multicast group is joined, the connector may be used as
		 * multicast receiver.
		 * 
		 * @param multicastGroup multicast group to join.
		 * @return this builder for command chaining
		 */
		public Builder addMulticastGroup(InetAddress multicastGroup) {
			groups.add(new Join(multicastGroup));
			return this;
		}

		/**
		 * Add multicast group to join with provided network interface..
		 * 
		 * If only one multicast group is joined, the connector may be used as
		 * multicast receiver.
		 * 
		 * @param multicastGroup multicast group to join.
		 * @param networkInterface network interface to join. If no supported by
		 *            the platform, the multicast group is joined without
		 *            specific the network interface.
		 * @return this builder for command chaining
		 */
		public Builder addMulticastGroup(InetAddress multicastGroup, NetworkInterface networkInterface) {
			groups.add(new Join(multicastGroup, networkInterface));
			return this;
		}

		/**
		 * Enable specific multicast receiver function.
		 * 
		 * Requires either exactly one multicast group to be joined, or a
		 * broadcast address and no additional multicast groups.
		 * 
		 * @param enable {@code true}, enable specific multicast receiver
		 *            function, {@code false}, otherwise.
		 * @return this builder for command chaining
		 * @since 3.0
		 */
		public Builder setMulticastReceiver(boolean enable) {
			multicastReceiver = enable;
			return this;
		}

		/**
		 * Create connector from parameters.
		 * 
		 * @return created connector
		 * @throws IllegalArgumentException if multicastReceiver is configured
		 *             but not exactly one broadcast or multicast address is
		 *             provided.
		 */
		public UdpMulticastConnector build() {
			return new UdpMulticastConnector(localSocketAddress, outgoingAddress, outgoingInterface, groups,
					multicastReceiver);
		}
	}
}
