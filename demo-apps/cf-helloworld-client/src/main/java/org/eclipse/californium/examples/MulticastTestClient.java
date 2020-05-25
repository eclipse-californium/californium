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

import java.io.File;
import java.io.IOException;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.core.network.interceptors.HealthStatisticLogger;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * Test client configured to support multicast requests.
 */
public class MulticastTestClient {

	private enum MulticastMode {
		IPv4, IPv4_BROADCAST, IPv6_LINK, Ipv6_SITE
	}

	/**
	 * File name for network configuration.
	 */
	private static final File CONFIG_FILE = new File("CaliforniumMulticast.properties");
	/**
	 * Header for network configuration.
	 */
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Multicast Client";
	/**
	 * Special network configuration defaults handler.
	 */
	private static NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			config.setInt(Keys.MULTICAST_BASE_MID, 65000);
		}

	};

	private static void get(CoapClient client, int port, String resourcePath) throws ConnectorException, IOException {
		String uri = "coap://localhost:" + port + "/" + resourcePath;
		System.out.println("GET " + uri);
		client.setURI(uri);

		Request request = Request.newGet();
		request.setType(Type.CON);

		// sends an uni-cast request
		CoapResponse response = client.advanced(request);
		if (response != null) {
			System.out.println(StringUtil.toString(response.advanced().getSourceContext().getPeerAddress()));
			System.out.println(Utils.prettyPrint(response));
		} else {
			System.out.println("No response received.");
		}
	}

	private static void mget(CoapClient client, int port, String resourcePath, MulticastMode mode)
			throws ConnectorException, IOException {
		String uri;
		switch (mode) {
		default:
		case IPv4:
			if (NetworkInterfacesUtil.isAnyIpv4()) {
				uri = "coap://" + CoAP.MULTICAST_IPV4.getHostAddress() + ":" + port + "/" + resourcePath;
				break;
			} else {
				System.err.print("IPv4 not supported!");
				return;
			}
		case IPv4_BROADCAST:
			if (NetworkInterfacesUtil.isAnyIpv4() && NetworkInterfacesUtil.getBroadcastIpv4() != null) {
				uri = "coap://" + NetworkInterfacesUtil.getBroadcastIpv4().getHostAddress() + ":" + port + "/"
						+ resourcePath + "?B";
				break;
			} else {
				System.err.print("IPv4 broadcast not supported!");
				return;
			}
		case IPv6_LINK:
			if (NetworkInterfacesUtil.isAnyIpv6()) {
				uri = "coap://[" + CoAP.MULTICAST_IPV6_LINKLOCAL.getHostAddress() + "]:" + port + "/" + resourcePath
						+ "?6L";
				break;
			} else {
				System.err.print("IPv6 not supported!");
				return;
			}
		case Ipv6_SITE:
			if (NetworkInterfacesUtil.isAnyIpv6()) {
				uri = "coap://[" + CoAP.MULTICAST_IPV6_SITELOCAL.getHostAddress() + "]:" + port + "/" + resourcePath
						+ "?6SL";
				break;
			} else {
				System.err.print("IPv6 not supported!");
				return;
			}
		}
		client.setURI(uri);
		System.out.println("GET " + uri);
		Request multicastRequest = Request.newGet();
		multicastRequest.setType(Type.NON);
		// sends a multicast request
		client.advanced(handler, multicastRequest);
		while (handler.waitOn(2000))
			;
	}

	public static void main(String args[]) {

		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		int unicastPort = config.getInt(Keys.COAP_PORT);
		int multicastPort = unicastPort;
		switch (args.length) {
		default:
			System.out.println("usage: MulticastTestClient [unicast-port [multicast-port]]");
		case 2:
			multicastPort = Integer.parseInt(args[1]);
		case 1:
			unicastPort = Integer.parseInt(args[0]);
		case 0:
		}

		HealthStatisticLogger health = new HealthStatisticLogger("multicast-client", true);
		CoapEndpoint endpoint = new CoapEndpoint.Builder().setNetworkConfig(config).build();
		endpoint.addPostProcessInterceptor(health);
		CoapClient client = new CoapClient();
		client.setEndpoint(endpoint);
		String resourcePath = "helloWorld";
		try {
			// sends an uni-cast request
			get(client, unicastPort, resourcePath);
			// sends a multicast IPv4 request
			mget(client, multicastPort, resourcePath, MulticastMode.IPv4);
			// sends a broadcast IPv4 request
			mget(client, multicastPort, resourcePath, MulticastMode.IPv4_BROADCAST);
			// https://bugs.openjdk.java.net/browse/JDK-8210493
			// link-local multicast is broken
			// sends a link-multicast IPv6 request
			mget(client, multicastPort, resourcePath, MulticastMode.IPv6_LINK);
			// sends a site-multicast IPv6 request
			mget(client, multicastPort, resourcePath, MulticastMode.Ipv6_SITE);
		} catch (ConnectorException | IOException e) {
			System.err.println("Error occurred while sending request: " + e);
		}
		health.dump();
		client.shutdown();
	}

	private static final MultiCoapHandler handler = new MultiCoapHandler();

	private static class MultiCoapHandler implements CoapHandler {

		private boolean on;

		public synchronized boolean waitOn(long timeout) {
			on = false;
			try {
				wait(timeout);
			} catch (InterruptedException e) {
			}
			return on;
		}

		private synchronized void on() {
			on = true;
			notifyAll();
		}

		@Override
		public void onLoad(CoapResponse response) {
			on();
			System.out.println(StringUtil.toString(response.advanced().getSourceContext().getPeerAddress()));
			System.out.println(Utils.prettyPrint(response));
		}

		@Override
		public void onError() {
			System.err.println("error");
		}
	};
}
