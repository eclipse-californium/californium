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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.io.IOException;
import java.net.BindException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.util.Random;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.MulticastReceivers;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.UdpMulticastConnector;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Test server using {@link UdpMulticastConnector}.
 */
public class MulticastTestServer {

	private static final Logger LOGGER = LoggerFactory.getLogger(MulticastTestServer.class);
	private static final boolean LOOPBACK = false;

	public static void main(String[] args) throws UnknownHostException {
		NetworkConfig config = NetworkConfig.getStandard();
		int unicastPort = config.getInt(Keys.COAP_PORT);
		int multicastPort = unicastPort;
		switch (args.length) {
		default:
			System.out.println("usage: MulticastTestServer [unicast-port [multicast-port]]");
		case 2:
			multicastPort = Integer.parseInt(args[1]);
		case 1:
			unicastPort = Integer.parseInt(args[0]);
		case 0:
		}
		CoapServer server = new CoapServer(config);
		createEndpoints(server, unicastPort, multicastPort, config);
		server.add(new HelloWorldResource());
		server.start();
	}

	private static void createEndpoints(CoapServer server, int unicastPort, int multicastPort, NetworkConfig config) {
		// UDPConnector udpConnector = new UDPConnector(new
		// InetSocketAddress(unicastPort));
		// udpConnector.setReuseAddress(true);
		// CoapEndpoint coapEndpoint = new
		// CoapEndpoint.Builder().setNetworkConfig(config).setConnector(udpConnector).build();

		NetworkInterface networkInterface = NetworkInterfacesUtil.getMulticastInterface();
		if (networkInterface == null) {
			LOGGER.warn("No multicast network-interface found!");
			throw new Error("No multicast network-interface found!");
		}
		LOGGER.info("Multicast Network Interface: {}", networkInterface.getDisplayName());

		UdpMulticastConnector.Builder builder = new UdpMulticastConnector.Builder();

		if (NetworkInterfacesUtil.isAnyIpv6()) {
			Inet6Address ipv6 = NetworkInterfacesUtil.getMulticastInterfaceIpv6();
			LOGGER.info("Multicast: IPv6 Network Address: {}", StringUtil.toString(ipv6));
			UDPConnector udpConnector = new UDPConnector(new InetSocketAddress(ipv6, unicastPort));
			udpConnector.setReuseAddress(true);
			CoapEndpoint coapEndpoint = new CoapEndpoint.Builder().setNetworkConfig(config).setConnector(udpConnector)
					.build();

			builder = new UdpMulticastConnector.Builder().setLocalAddress(CoAP.MULTICAST_IPV6_SITELOCAL, multicastPort)
					.addMulticastGroup(CoAP.MULTICAST_IPV6_SITELOCAL, networkInterface);
			createReceiver(builder, (MulticastReceivers) coapEndpoint);

			/*
			 * https://bugs.openjdk.java.net/browse/JDK-8210493 link-local
			 * multicast is broken
			 */
			builder = new UdpMulticastConnector.Builder().setLocalAddress(CoAP.MULTICAST_IPV6_LINKLOCAL, multicastPort)
					.addMulticastGroup(CoAP.MULTICAST_IPV6_LINKLOCAL, networkInterface);
			createReceiver(builder, (MulticastReceivers) coapEndpoint);

			server.addEndpoint(coapEndpoint);
			LOGGER.info("IPv6 - multicast");
		}

		if (NetworkInterfacesUtil.isAnyIpv4()) {
			Inet4Address ipv4 = NetworkInterfacesUtil.getMulticastInterfaceIpv4();
			LOGGER.info("Multicast: IPv4 Network Address: {}", StringUtil.toString(ipv4));
			UDPConnector udpConnector = new UDPConnector(new InetSocketAddress(ipv4, unicastPort));
			udpConnector.setReuseAddress(true);
			CoapEndpoint coapEndpoint = new CoapEndpoint.Builder().setNetworkConfig(config).setConnector(udpConnector)
					.build();

			builder = new UdpMulticastConnector.Builder().setLocalAddress(CoAP.MULTICAST_IPV4, multicastPort)
					.addMulticastGroup(CoAP.MULTICAST_IPV4, networkInterface);
			createReceiver(builder, (MulticastReceivers) coapEndpoint);

			Inet4Address broadcast = NetworkInterfacesUtil.getBroadcastIpv4();
			if (broadcast != null) {
				// windows seems to fail to open a broadcast receiver
				builder = new UdpMulticastConnector.Builder().setLocalAddress(broadcast, multicastPort);
				createReceiver(builder, (MulticastReceivers) coapEndpoint);
			}
			server.addEndpoint(coapEndpoint);
			LOGGER.info("IPv4 - multicast");
		}
		UDPConnector udpConnector = new UDPConnector(
				new InetSocketAddress(InetAddress.getLoopbackAddress(), unicastPort));
		udpConnector.setReuseAddress(true);
		CoapEndpoint coapEndpoint = new CoapEndpoint.Builder().setNetworkConfig(config).setConnector(udpConnector)
				.build();
		server.addEndpoint(coapEndpoint);
		LOGGER.info("loopback");
	}

	private static void createReceiver(UdpMulticastConnector.Builder builder, MulticastReceivers endpoint) {
		UdpMulticastConnector connector = builder.build();
		connector.setLoopbackMode(LOOPBACK);
		try {
			connector.start();
		} catch (BindException ex) {
			// binding to multicast seems to fail on windows
			if (builder.getLocalAddress().getAddress().isMulticastAddress()) {
				int port = builder.getLocalAddress().getPort();
				builder.setLocalPort(port);
				connector = builder.build();
				connector.setLoopbackMode(LOOPBACK);
				try {
					connector.start();
				} catch (IOException e) {
					e.printStackTrace();
					connector = null;
				}
			} else {
				ex.printStackTrace();
				connector = null;
			}
		} catch (IOException e) {
			e.printStackTrace();
			connector = null;
		}
		if (connector != null && endpoint != null) {
			endpoint.addMulticastReceiver(connector);
		}
	}

	private static class HelloWorldResource extends CoapResource {

		private int id;

		private HelloWorldResource() {
			// set resource identifier
			super("helloWorld");
			// set display name
			getAttributes().setTitle("Hello-World Resource");
			id = new Random(System.currentTimeMillis()).nextInt(100);
			System.out.println("coap server: " + id);
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			// respond to the request
			if (exchange.isMulticastRequest()) {
				exchange.respond("Hello Multicast-World! " + id);
			} else {
				exchange.respond("Hello Unicast-World! " + id);
			}
		}
	}
}
