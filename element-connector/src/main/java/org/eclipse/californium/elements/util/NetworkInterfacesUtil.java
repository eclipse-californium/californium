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
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.Collection;
import java.util.Collections;
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
 * Use environment "COAP_NETWORK_INTERFACES" to define a regular expression for
 * network interfaces to use, defaults to all. Use environment
 * "COAP_NETWORK_INTERFACES_EXCLUDES" to define a regular expression for network
 * interfaces to exclude from usage, defaults to common virtual networks.
 * 
 * @since 2.1
 * @since 2.3 use only "up" NetworkInterfaces (see
 *        {@link NetworkInterface#isUp()}.
 * @since 3.1 supports environment "COAP_NETWORK_INTERFACES_EXCLUDE" and
 *        excludes common virtual networks from being used.
 */
public class NetworkInterfacesUtil {

	private static final Logger LOGGER = LoggerFactory.getLogger(NetworkInterfacesUtil.class);

	/**
	 * Maximum UDP MTU.
	 */
	public static final int MAX_MTU = 65535;

	public static final int DEFAULT_IPV6_MTU = 1280;
	public static final int DEFAULT_IPV4_MTU = 576;

	public static final String COAP_NETWORK_INTERFACES = "COAP_NETWORK_INTERFACES";
	public static final String COAP_NETWORK_INTERFACES_EXCLUDE = "COAP_NETWORK_INTERFACES_EXCLUDE";
	/**
	 * Default pattern to exclude common virtual networks.
	 * 
	 * Excludes "docker\d+", "virbr\d+", "vxlan.calico", "calixxxxxxxxxx",
	 * "cilium_\w+", and "lxcxxxxxxxxxxxx".
	 * 
	 * @since 3.1
	 */
	public static final String DEFAULT_COAP_NETWORK_INTERFACES_EXCLUDE = "(vxlan\\.calico|cali[0123456789abcdef]{10,}|cilium_\\w+|lxc[0123456789abcdef]{12,}|virbr\\d+|docker\\d+)";

	private static final Pattern DEFAULT_EXCLUDE = Pattern.compile(DEFAULT_COAP_NETWORK_INTERFACES_EXCLUDE);

	/**
	 * MTU for any interface.
	 */
	private static int anyMtu;
	/**
	 * MTU for IPv4 interface.
	 * 
	 * @since 2.4
	 */
	private static int ipv4Mtu;
	/**
	 * MTU for IPv6 interface.
	 * 
	 * @since 2.4
	 */
	private static int ipv6Mtu;

	/**
	 * One of any interfaces supports IPv4.
	 */
	private static boolean anyIpv4;

	/**
	 * One of any interfaces supports IPv6.
	 */
	private static boolean anyIpv6;

	/**
	 * A IPv4 broadcast address on a multicast supporting network interface, if
	 * available.
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
	private static final Set<InetAddress> broadcastAddresses = new HashSet<>();
	/**
	 * Set of available IPv6 scopes.
	 */
	private static final Set<String> ipv6Scopes = new HashSet<>();

	private static class Filter implements Enumeration<NetworkInterface> {

		private NetworkInterface nextInterface;
		private final Enumeration<NetworkInterface> source;
		private final Pattern filter;
		private final Pattern excludeFilter;

		private Filter(Enumeration<NetworkInterface> source) {
			this.source = source;
			Pattern filter = null;
			Pattern excludeFilter = null;
			String regex = StringUtil.getConfiguration(COAP_NETWORK_INTERFACES);
			String excludeRegex = StringUtil.getConfiguration(COAP_NETWORK_INTERFACES_EXCLUDE);
			if (regex != null && !regex.isEmpty()) {
				filter = Pattern.compile(regex);
			} else if (excludeRegex == null || excludeRegex.isEmpty()) {
				excludeFilter = DEFAULT_EXCLUDE;
			}
			if (excludeRegex != null && !excludeRegex.isEmpty()) {
				excludeFilter = Pattern.compile(excludeRegex);
			}
			this.filter = filter;
			this.excludeFilter = excludeFilter;
			next();
		}

		@Override
		public boolean hasMoreElements() {
			return nextInterface != null;
		}

		@Override
		public NetworkInterface nextElement() {
			NetworkInterface result = nextInterface;
			next();
			return result;
		}

		private void next() {
			nextInterface = null;
			while (source.hasMoreElements()) {
				NetworkInterface iface = source.nextElement();
				String name = iface.getName();
				try {
					if (iface.isUp() && (filter == null || filter.matcher(name).matches())) {
						if (excludeFilter == null || !excludeFilter.matcher(name).matches()) {
							nextInterface = iface;
							break;
						}
					}
				} catch (SocketException e) {
				}
				LOGGER.debug("skip {}", name);
			}
		}
	}

	private synchronized static void initialize() {
		if (anyMtu == 0) {
			clear();
			int mtu = MAX_MTU;
			int ipv4mtu = MAX_MTU;
			int ipv6mtu = MAX_MTU;

			try {
				Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
				if (interfaces == null) {
					throw new SocketException("Network interfaces not available!");
				}
				interfaces = new Filter(interfaces);
				while (interfaces.hasMoreElements()) {
					NetworkInterface iface = interfaces.nextElement();
					if (!iface.isLoopback()) {
						int ifaceMtu = iface.getMTU();
						if (ifaceMtu > 0 && ifaceMtu < mtu) {
							mtu = ifaceMtu;
						}
						if (iface.supportsMulticast()) {
							Enumeration<InetAddress> inetAddresses = iface.getInetAddresses();
							while (inetAddresses.hasMoreElements()) {
								InetAddress address = inetAddresses.nextElement();
								if (address instanceof Inet6Address) {
									if (((Inet6Address) address).getScopeId() > 0) {
										ipv6Scopes.add(iface.getName());
									}
								}
							}
						}
						if (iface.supportsMulticast() && (multicastInterfaceIpv4 == null
								|| multicastInterfaceIpv6 == null || broadcastIpv4 == null)) {
							Inet4Address broad4 = null;
							Inet4Address link4 = null;
							Inet4Address site4 = null;
							Inet6Address link6 = null;
							Inet6Address site6 = null;
							// find the network interface with the most
							// multicast/broadcast possibilities
							int countMultiFeatures = 0;
							if (broadcastIpv4 != null) {
								--countMultiFeatures;
							}
							if (multicastInterfaceIpv4 != null) {
								--countMultiFeatures;
							}
							if (multicastInterfaceIpv6 != null) {
								--countMultiFeatures;
							}
							Enumeration<InetAddress> inetAddresses = iface.getInetAddresses();
							while (inetAddresses.hasMoreElements()) {
								InetAddress address = inetAddresses.nextElement();
								if (address instanceof Inet4Address) {
									anyIpv4 = true;
									if (ifaceMtu > 0 && ifaceMtu < ipv4mtu) {
										ipv4mtu = ifaceMtu;
									}
									if (site4 == null) {
										if (address.isSiteLocalAddress()) {
											site4 = (Inet4Address) address;
										} else if (link4 == null && address.isLinkLocalAddress()) {
											link4 = (Inet4Address) address;
										}
									}
								} else if (address instanceof Inet6Address) {
									Inet6Address address6 = (Inet6Address) address;
									anyIpv6 = true;
									if (ifaceMtu > 0 && ifaceMtu < ipv6mtu) {
										ipv6mtu = ifaceMtu;
									}
									if (site6 == null) {
										if (address.isSiteLocalAddress()) {
											site6 = address6;
										} else if (link4 == null && address.isLinkLocalAddress()) {
											link6 = address6;
										}
									}
								}
							}
							for (InterfaceAddress interfaceAddress : iface.getInterfaceAddresses()) {
								InetAddress broadcast = interfaceAddress.getBroadcast();
								if (broadcast != null && !broadcast.isAnyLocalAddress()) {
									InetAddress address = interfaceAddress.getAddress();
									if (address != null && !address.equals(broadcast)) {
										broadcastAddresses.add(broadcast);
										LOGGER.debug("Found broadcast address {} - {}.", broadcast, iface.getName());
										if (broad4 == null) {
											broad4 = (Inet4Address) broadcast;
											++countMultiFeatures;
										}
									}
								}
							}
							if (link4 != null || site4 != null) {
								++countMultiFeatures;
							}
							if (link6 != null || site6 != null) {
								++countMultiFeatures;
							}
							if (countMultiFeatures > 0) {
								// more multicast/broadcast possibilities as
								// before
								multicastInterface = iface;
								broadcastIpv4 = broad4;
								multicastInterfaceIpv4 = site4 == null ? link4 : site4;
								multicastInterfaceIpv6 = site6 == null ? link6 : site6;
							}
						} else {
							Enumeration<InetAddress> inetAddresses = iface.getInetAddresses();
							while (inetAddresses.hasMoreElements()) {
								InetAddress address = inetAddresses.nextElement();
								if (address instanceof Inet4Address) {
									anyIpv4 = true;
									if (ifaceMtu > 0 && ifaceMtu < ipv4mtu) {
										ipv4mtu = ifaceMtu;
									}
								} else if (address instanceof Inet6Address) {
									anyIpv6 = true;
									if (ifaceMtu > 0 && ifaceMtu < ipv6mtu) {
										ipv6mtu = ifaceMtu;
									}
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
			if (ipv4mtu == MAX_MTU) {
				ipv4mtu = DEFAULT_IPV4_MTU;
			}
			if (ipv6mtu == MAX_MTU) {
				ipv6mtu = DEFAULT_IPV6_MTU;
			}
			if (mtu == MAX_MTU) {
				mtu = Math.min(ipv4mtu, ipv6mtu);
			}
			NetworkInterfacesUtil.ipv4Mtu = ipv4mtu;
			NetworkInterfacesUtil.ipv6Mtu = ipv6mtu;
			NetworkInterfacesUtil.anyMtu = mtu;
		}
	}

	/**
	 * Clear discovered network parameters.
	 * 
	 * Intended to be called in changing network environments to (re-)discover
	 * the netowrk's parameters.
	 * 
	 * @since 3.0
	 */
	public synchronized static void clear() {
		anyMtu = 0;
		ipv4Mtu = 0;
		ipv6Mtu = 0;
		anyIpv4 = false;
		anyIpv6 = false;
		ipv6Scopes.clear();
		broadcastAddresses.clear();
		broadcastIpv4 = null;
		multicastInterfaceIpv4 = null;
		multicastInterfaceIpv6 = null;
		multicastInterface = null;
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
	 * Get MTU for IPv4 interface.
	 * 
	 * Determine the smallest MTU of all IPv4 network interfaces.
	 * 
	 * @return MTU in bytes
	 * @since 2.4
	 */
	public static int getIPv4Mtu() {
		initialize();
		return ipv4Mtu;
	}

	/**
	 * Get MTU for IPv6 interface.
	 * 
	 * Determine the smallest MTU of all IPv6 network interfaces.
	 * 
	 * @return MTU in bytes
	 * @since 2.4
	 */
	public static int getIPv6Mtu() {
		initialize();
		return ipv6Mtu;
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
	 * Applies environment "COAP_NETWORK_INTERFACES" to define a regular
	 * expression for network interfaces to use, defaults to all. And
	 * environment "COAP_NETWORK_INTERFACES_EXCLUDES" to define a regular
	 * expression for network interfaces to exclude from usage, defaults to
	 * common virtual networks.
	 * 
	 * @return collection of local inet addresses.
	 */
	public static Collection<InetAddress> getNetworkInterfaces() {
		Collection<InetAddress> interfaces = new LinkedList<InetAddress>();
		try {
			Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
			if (nets == null) {
				throw new SocketException("Network interfaces not available!");
			}
			nets = new Filter(nets);
			while (nets.hasMoreElements()) {
				NetworkInterface networkInterface = nets.nextElement();
				Enumeration<InetAddress> inetAddresses = networkInterface.getInetAddresses();
				while (inetAddresses.hasMoreElements()) {
					InetAddress address = inetAddresses.nextElement();
					interfaces.add(address);
				}
			}
		} catch (SocketException e) {
			LOGGER.error("could not fetch all interface addresses", e);
		}
		return interfaces;
	}

	/**
	 * Gets available IPv6 scopes.
	 * 
	 * Only scopes with multicast support are included.
	 * 
	 * @return available IPv6 scopes
	 * @since 3.0
	 */
	public static Set<String> getIpv6Scopes() {
		initialize();
		return Collections.unmodifiableSet(ipv6Scopes);
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

	/**
	 * Check, if both provided addresses are equal.
	 * 
	 * @param address1 address 1. May be {@code null}, if not available.
	 * @param address2 address 2. May be {@code null}, if not available.
	 * @return {@code true}, if both addresses are equal, {@code false}, if not.
	 * @since 3.0
	 */
	public static boolean equals(InetAddress address1, InetAddress address2) {
		return address1 == address2 || (address1 != null && address1.equals(address2));
	}

	/**
	 * Check, if both provided socket addresses are equal.
	 * 
	 * @param address1 address 1. May be {@code null}, if not available.
	 * @param address2 address 2. May be {@code null}, if not available.
	 * @return {@code true}, if both addresses are equal, {@code false}, if not.
	 * @since 3.0
	 */
	public static boolean equals(SocketAddress address1, SocketAddress address2) {
		return address1 == address2 || (address1 != null && address1.equals(address2));
	}
}
