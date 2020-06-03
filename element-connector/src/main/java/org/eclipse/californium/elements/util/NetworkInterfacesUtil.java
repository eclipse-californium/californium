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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for NetworkInterfaces. Determine MTU, IPv4, IPv6 support.
 * 
 * @since 2.1
 * @since 2.3 use only "up" NetworkInterfaces (see
 *        {@link NetworkInterface#isUp()}.
 */
public class NetworkInterfacesUtil {

	private static final Logger LOGGER = LoggerFactory.getLogger(NetworkInterfacesUtil.class);

	/**
	 * Maximum UDP MTU.
	 */
	public static final int MAX_MTU = 65535;

	/**
	 * MTU for any interface.
	 */
	private static int anyMtu;

	/**
	 * One of any interfaces supports IPv4.
	 */
	private static boolean anyIpv4;

	/**
	 * One of any interfaces supports IPv6.
	 */
	private static boolean anyIpv6;

	/**
	 * A IPv4 broadcast address on a multicast supporting network interface, if available.
	 * 
	 * @since 2.3
	 */
	private static Inet4Address broadcastIpv4;
	/**
	 * A IPv4 address of a multicast supporting network interface, if available.
	 * 
	 * @since 2.3
	 */
	private static Inet4Address multicastInterfaceIpv4;
	/**
	 * A Pv6 address of a multicast supporting network interface, if available.
	 * 
	 * @since 2.3
	 */
	private static Inet6Address multicastInterfaceIpv6;
	/**
	 * A multicast supporting NetworkInterfaces.
	 * 
	 * @since 2.3
	 */
	private static NetworkInterface multicastInterface;
	/**
	 * Set of detected broadcast addresses.
	 * 
	 * @since 2.3
	 */
	private static final Set<InetAddress> broadcastAddresses = new HashSet<InetAddress>();

	private synchronized static void initialize() {
		if (anyMtu == 0) {
			broadcastAddresses.clear();
			broadcastIpv4 = null;
			multicastInterfaceIpv4 = null;
			multicastInterfaceIpv6 = null;
			multicastInterface = null;
			Inet4Address link4 = null;
			Inet4Address site4 = null;
			Inet6Address link6 = null;
			Inet6Address site6 = null;
			int mtu = MAX_MTU;
			Pattern filter = null;
			String regex = StringUtil.getConfiguration("COAP_NETWORK_INTERFACES");
			if (regex != null && !regex.isEmpty()) {
				filter = Pattern.compile(regex);
			}
			try {
				Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
				while (interfaces.hasMoreElements()) {
					NetworkInterface iface = interfaces.nextElement();
					if (iface.isUp() && !iface.isLoopback() && 
							(filter == null || filter.matcher(iface.getName()).matches())) {
						int ifaceMtu = iface.getMTU();
						if (ifaceMtu > 0 && ifaceMtu < mtu) {
							mtu = ifaceMtu;
						}
						if (multicastInterface == null && iface.supportsMulticast()) {
							multicastInterface = iface;
						}
						Enumeration<InetAddress> inetAddresses = iface.getInetAddresses();
						while (inetAddresses.hasMoreElements()) {
							InetAddress address = inetAddresses.nextElement();
							if (address instanceof Inet4Address) {
								anyIpv4 = true;
								if (site4 == null && iface.supportsMulticast()) {
									if (address.isSiteLocalAddress()) {
										site4 = (Inet4Address) address;
									} else if (link4 == null && address.isLinkLocalAddress()) {
										link4 = (Inet4Address) address;
									}
								}
							} else if (address instanceof Inet6Address) {
								anyIpv6 = true;
								if (site6 == null && iface.supportsMulticast()) {
									if (address.isSiteLocalAddress()) {
										site6 = (Inet6Address) address;
									} else if (link4 == null && address.isLinkLocalAddress()) {
										link6 = (Inet6Address) address;
									}
								}
							}
						}
						for (InterfaceAddress interfaceAddress : iface.getInterfaceAddresses()) {
							InetAddress broadcast = interfaceAddress.getBroadcast();
							if (broadcast != null && !broadcast.isAnyLocalAddress()) {
								broadcastAddresses.add(broadcast);
								LOGGER.debug("Found broadcast address {} - {}.", broadcast, iface.getName());
								if (broadcastIpv4 == null) {
									broadcastIpv4 = (Inet4Address) broadcast;
								}
							}
						}
					}
				}
			} catch (SocketException ex) {
				LOGGER.warn("discover the <any> interface failed!", ex);
				anyIpv4 = true;
				anyIpv6 = true;
			}
			if (broadcastAddresses.isEmpty()) {
				LOGGER.info("no broadcast address found!");
			}
			multicastInterfaceIpv4 = site4 == null ? link4 : site4;
			multicastInterfaceIpv6 = site6 == null ? link6 : site6;
			anyMtu = mtu;
		}
	}

	/**
	 * Get MTU for any interface.
	 * 
	 * Determine the smallest MTU of all network interfaces.
	 * 
	 * @return MTU in bytes
	 */
	public static int getAnyMtu() {
		initialize();
		return anyMtu;
	}

	/**
	 * Reports, if any interface support IPv4.
	 * 
	 * @return {@code true}, if any interface supports IPv4, {@code false},
	 *         otherwise.
	 */
	public static boolean isAnyIpv4() {
		initialize();
		return anyIpv4;
	}

	/**
	 * Reports, if any interface support IPv6.
	 * 
	 * @return {@code true}, if any interface supports IPv6, {@code false},
	 *         otherwise.
	 */
	public static boolean isAnyIpv6() {
		initialize();
		return anyIpv6;
	}

	/**
	 * Gets a IPv4 broadcast address.
	 * 
	 * @return IPv4 broadcast address, or {@code null}, if not available
	 * @since 2.3
	 */
	public static Inet4Address getBroadcastIpv4() {
		initialize();
		return broadcastIpv4;
	}

	/**
	 * Gets a IPv4 address on a multicast supporting network interface.
	 * 
	 * @return IPv4 address, or {@code null}, if not available
	 * @since 2.3
	 */
	public static Inet4Address getMulticastInterfaceIpv4() {
		initialize();
		return multicastInterfaceIpv4;
	}

	/**
	 * Gets a IPv6 address on a multicast supporting network interface.
	 * 
	 * @return IPv6 address, or {@code null}, if not available
	 * @since 2.3
	 */
	public static Inet6Address getMulticastInterfaceIpv6() {
		initialize();
		return multicastInterfaceIpv6;
	}

	/**
	 * Gets a multicast supporting network interface.
	 * 
	 * @return multicast supporting network interface, or {@code null}, if not
	 *         available
	 * @since 2.3
	 */
	public static NetworkInterface getMulticastInterface() {
		initialize();
		return multicastInterface;
	}

	/**
	 * Get collection of available local inet addresses of network interfaces.
	 * 
	 * @return collection of local inet addresses.
	 */
	public static Collection<InetAddress> getNetworkInterfaces() {
		Collection<InetAddress> interfaces = new LinkedList<InetAddress>();
		try {
			Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
			while (nets.hasMoreElements()) {
				NetworkInterface networkInterface = nets.nextElement();
				if (networkInterface.isUp()) {
					Enumeration<InetAddress> inetAddresses = networkInterface.getInetAddresses();
					while (inetAddresses.hasMoreElements()) {
						interfaces.add(inetAddresses.nextElement());
					}
				}
			}
		} catch (SocketException e) {
			LOGGER.error("could not fetch all interface addresses", e);
		}
		return interfaces;
	}

	/**
	 * Check, if address is broadcast address of one of the network interfaces.
	 * 
	 * @param address address to check
	 * @return {@code true}, if address is broadcast address of one of the
	 *         network interfaces, {@code false}, otherwise.
	 * @since 2.3
	 */
	public static boolean isBroadcastAddress(InetAddress address) {
		initialize();
		return broadcastAddresses.contains(address);
	}

	/**
	 * Check, if address is a multicast or a broadcast address of one of the
	 * network interfaces.
	 * 
	 * @param address address to check. May be {@code null}.
	 * @return {@code true}, if address is a multicast or a broadcast address of
	 *         one of the network interfaces, {@code false}, otherwise.
	 * @since 2.3
	 */
	public static boolean isMultiAddress(InetAddress address) {
		initialize();
		return address != null && (address.isMulticastAddress() || broadcastAddresses.contains(address));
	}
}
