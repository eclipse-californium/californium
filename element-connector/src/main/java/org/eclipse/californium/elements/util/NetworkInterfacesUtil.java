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
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.LinkedList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for NetworkInterfaces. Determine MTU, IPv4, IPv6 support.
 * @since 2.1
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
	 * One of the any interfaces supports IPv4.
	 */
	private static boolean anyIpv4;

	/**
	 * One of the any interfaces supports IPv6.
	 */
	private static boolean anyIpv6;

	private synchronized static void initialize() {
		if (anyMtu == 0) {
			int mtu = MAX_MTU;
			try {
				Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
				while (interfaces.hasMoreElements()) {
					NetworkInterface iface = interfaces.nextElement();
					int ifaceMtu = iface.getMTU();
					if (ifaceMtu > 0 && ifaceMtu < mtu) {
						mtu = ifaceMtu;
					}
					Enumeration<InetAddress> inetAddresses = iface.getInetAddresses();
					while (inetAddresses.hasMoreElements()) {
						InetAddress address = inetAddresses.nextElement();
						if (address instanceof Inet4Address) {
							anyIpv4 = true;
						} else if (address instanceof Inet6Address) {
							anyIpv6 = true;
						}
					}
				}
			} catch (SocketException ex) {
				LOGGER.warn("discover any interface failed!", ex);
				anyIpv4 = true;
				anyIpv6 = true;
			}
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
	 * Get collection of available local inet addresses of network interfaces.
	 * 
	 * @return collection of local inet addresses.
	 */
	public static Collection<InetAddress> getNetworkInterfaces() {
		Collection<InetAddress> interfaces = new LinkedList<InetAddress>();
		try {
			Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
			while (nets.hasMoreElements()) {
				Enumeration<InetAddress> inetAddresses = nets.nextElement().getInetAddresses();
				while (inetAddresses.hasMoreElements()) {
					interfaces.add(inetAddresses.nextElement());
				}
			}
		} catch (SocketException e) {
			LOGGER.error("could not fetch all interface addresses", e);
		}
		return interfaces;
	}
}
