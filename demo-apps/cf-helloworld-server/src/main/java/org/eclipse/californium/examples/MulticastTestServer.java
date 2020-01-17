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

import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Random;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.UdpMulticastConnector;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Test server using {@link UdpMulticastConnector}.
 */
public class MulticastTestServer {
	private static final Logger LOGGER = LoggerFactory.getLogger(MulticastTestServer.class);

	public static void main(String[] args) throws UnknownHostException {

		NetworkConfig config = NetworkConfig.getStandard();
		CoapEndpoint endpoint = createEndpoints(config);
		CoapServer server = new CoapServer(config);
		server.addEndpoint(endpoint);
		server.add(new HelloWorldResource());
		server.start();
	}

	private static CoapEndpoint createEndpoints(NetworkConfig config) throws UnknownHostException {
		int port = config.getInt(Keys.COAP_PORT);
		InetSocketAddress localAddress = new InetSocketAddress(port);
		Connector connector;
		if (NetworkInterfacesUtil.isAnyIpv6() && NetworkInterfacesUtil.isAnyIpv4()) {
			connector = new UdpMulticastConnector(localAddress, CoAP.MULTICAST_IPV4, CoAP.MULTICAST_IPV6_LINKLOCAL,
					CoAP.MULTICAST_IPV6_SITELOCAL);
			LOGGER.debug("IPv4 & IPv6");
		} else if (NetworkInterfacesUtil.isAnyIpv6()) {
			connector = new UdpMulticastConnector(localAddress, CoAP.MULTICAST_IPV6_LINKLOCAL,
					CoAP.MULTICAST_IPV6_SITELOCAL);
			LOGGER.debug("IPv6");
		} else {
			connector = new UdpMulticastConnector(localAddress, CoAP.MULTICAST_IPV4);
			LOGGER.debug("IPv4");
		}
		return new CoapEndpoint.Builder().setNetworkConfig(config).setConnector(connector).build();
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
			exchange.respond("Hello World! " + id);
		}
	}
}
