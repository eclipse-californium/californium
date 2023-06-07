/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import static org.eclipse.californium.elements.util.TestConditionTools.inRange;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assume.assumeThat;
import static org.junit.Assume.assumeTrue;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collection;
import java.util.HashSet;

import org.eclipse.californium.elements.category.Small;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class NetworkInterfacesUtilTest {

	private static final InetAddress[] ARRAY_TYPE = new InetAddress[0];

	@Before
	public void init() {
		System.setProperty(NetworkInterfacesUtil.COAP_NETWORK_INTERFACES, "");
		System.setProperty(NetworkInterfacesUtil.COAP_NETWORK_INTERFACES_EXCLUDE, "");
	}

	@Test
	public void testGetMtu() {
		int mtu = NetworkInterfacesUtil.getAnyMtu();
		int mtu4 = NetworkInterfacesUtil.getIPv4Mtu();
		int mtu6 = NetworkInterfacesUtil.getIPv6Mtu();
		if (mtu4 < mtu6) {
			assertThat(mtu, is(inRange(mtu4, mtu6 + 1)));
		} else {
			assertThat(mtu, is(inRange(mtu6, mtu4 + 1)));
		}
	}

	@Test
	public void testIsAny() {
		boolean any4 = NetworkInterfacesUtil.isAnyIpv4();
		boolean any6 = NetworkInterfacesUtil.isAnyIpv6();
		assertThat(any4 || any6, is(true));
	}

	@Test
	public void testGetNetworkInterfaces() throws SocketException {
		Collection<InetAddress> networkInterfaces = NetworkInterfacesUtil.getNetworkInterfaces();
		assertThat(networkInterfaces.isEmpty(), is(false));
		assumeThat("same address of different interfaces", networkInterfaces.size(),
				is(new HashSet<>(networkInterfaces).size()));

		InetAddress first = networkInterfaces.iterator().next();
		String firstInterface = NetworkInterface.getByInetAddress(first).getName().replace(".", "\\.");

		// filter networks by the name of the first interface
		System.setProperty(NetworkInterfacesUtil.COAP_NETWORK_INTERFACES, firstInterface);
		Collection<InetAddress> networkInterfaces2 = NetworkInterfacesUtil.getNetworkInterfaces();
		assertThat(networkInterfaces2.isEmpty(), is(false));
		assertThat(networkInterfaces, hasItems((InetAddress[]) networkInterfaces2.toArray(ARRAY_TYPE)));
		assertThat(networkInterfaces2, hasItem(first));

		// filter networks excluding the name of the first interface
		System.setProperty(NetworkInterfacesUtil.COAP_NETWORK_INTERFACES, "");
		String exclude = NetworkInterfacesUtil.DEFAULT_COAP_NETWORK_INTERFACES_EXCLUDE;
		exclude = exclude.substring(0, exclude.length() - 1);
		exclude += "|" + firstInterface + ")";
		System.setProperty(NetworkInterfacesUtil.COAP_NETWORK_INTERFACES_EXCLUDE, exclude);
		Collection<InetAddress> networkInterfaces3 = NetworkInterfacesUtil.getNetworkInterfaces();
		assertThat(networkInterfaces3.isEmpty(), is(false));
		assertThat(networkInterfaces, hasItems((InetAddress[]) networkInterfaces3.toArray(ARRAY_TYPE)));
		assertThat(networkInterfaces3, not(hasItem(first)));

		// total set of both filtered results
		Collection<InetAddress> all = new HashSet<>(networkInterfaces2);
		all.addAll(networkInterfaces3);
		assertThat(networkInterfaces.size(), is(all.size()));
		assertThat(networkInterfaces, hasItems(all.toArray(ARRAY_TYPE)));
		assertThat(all, hasItems((InetAddress[]) networkInterfaces.toArray(ARRAY_TYPE)));
	}

	@Test
	public void testGetIpv6Scopes() throws SocketException {
		assumeTrue("No IPv6", NetworkInterfacesUtil.isAnyIpv6());
		Collection<InetAddress> networkInterfaces = NetworkInterfacesUtil.getNetworkInterfaces();
		assertThat(networkInterfaces.isEmpty(), is(false));
		Collection<String> scopes = NetworkInterfacesUtil.getIpv6Scopes();
		assertThat(scopes.isEmpty(), is(false));
		NetworkInterface multicastInterface = NetworkInterfacesUtil.getMulticastInterface();
		assertThat(scopes, hasItem(multicastInterface.getName()));
	}

	@Test
	public void testGetBroadcastIpv4() throws SocketException {
		assumeTrue("No IPv4", NetworkInterfacesUtil.isAnyIpv4());
		InetAddress broadcast = NetworkInterfacesUtil.getBroadcastIpv4();
		assertThat(broadcast, is(notNullValue()));
		assertThat(NetworkInterfacesUtil.isBroadcastAddress(broadcast), is(true));
	}

	@Test
	public void testGetMulticastInterface() throws SocketException {
		InetAddress multicast = NetworkInterfacesUtil.getMulticastInterfaceIpv4();
		if (multicast == null) {
			multicast = NetworkInterfacesUtil.getMulticastInterfaceIpv6();
		}
		NetworkInterface multicastByAddress = NetworkInterface.getByInetAddress(multicast);
		NetworkInterface multicastInterface = NetworkInterfacesUtil.getMulticastInterface();
		assertThat(multicastInterface, is(multicastByAddress));
	}
}
