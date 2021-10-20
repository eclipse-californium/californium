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
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.interceptors.HealthStatisticLogger;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
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
	 * File name for configuration.
	 */
	private static final File CONFIG_FILE = new File("CaliforniumMulticast3.properties");
	/**
	 * Header for configuration.
	 */
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Multicast Client";
	/**
	 * Header for configuration.
	 */
	private static final SimpleDateFormat FORMAT = new SimpleDateFormat("s:SSS - ");
	/**
	 * Special configuration defaults handler.
	 */
	private static DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(CoapConfig.MULTICAST_BASE_MID, 65000);
			config.set(CoapConfig.LEISURE, 2, TimeUnit.SECONDS);
		}

	};

	static {
		CoapConfig.register();
		UdpConfig.register();
	}

	private static void get(CoapClient client, int port, String resourcePath) throws ConnectorException, IOException {
		String uri = "coap://localhost:" + port + "/" + resourcePath;
		System.out.println(FORMAT.format(new Date()) + "GET " + uri);
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

	private static void mget(CoapClient client, int port, String resourcePath, MulticastMode mode, long leisureMillis)
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
		System.out.println(FORMAT.format(new Date()) + "GET " + uri);
		Request multicastRequest = Request.newGet();
		multicastRequest.setType(Type.NON);
		// sends a multicast request
		MultiCoapHandler handler = new MultiCoapHandler();
		client.advanced(handler, multicastRequest);
		while (handler.waitOn(leisureMillis + 2000))
			;
	}

	public static void main(String args[]) {

		Configuration config = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		int unicastPort = config.get(CoapConfig.COAP_PORT);
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
		CoapEndpoint endpoint = new CoapEndpoint.Builder().setConfiguration(config).build();
		endpoint.addPostProcessInterceptor(health);
		CoapClient client = new CoapClient();
		client.setEndpoint(endpoint);
		long leisureMillis = config.get(CoapConfig.LEISURE, TimeUnit.MILLISECONDS);
		String resourcePath = "helloWorld";
		try {
			// sends an uni-cast request
			get(client, unicastPort, resourcePath);
			// sends a multicast IPv4 request
			mget(client, multicastPort, resourcePath, MulticastMode.IPv4, leisureMillis);
			// sends a broadcast IPv4 request
			mget(client, multicastPort, resourcePath, MulticastMode.IPv4_BROADCAST, leisureMillis);
			// https://bugs.openjdk.java.net/browse/JDK-8210493
			// link-local multicast is broken
			// sends a link-multicast IPv6 request
			mget(client, multicastPort, resourcePath, MulticastMode.IPv6_LINK, leisureMillis);
			// sends a site-multicast IPv6 request
			mget(client, multicastPort, resourcePath, MulticastMode.Ipv6_SITE, leisureMillis);
		} catch (ConnectorException | IOException e) {
			System.err.println("Error occurred while sending request: " + e);
		}
		health.dump();
		client.shutdown();
	}

	private static class MultiCoapHandler implements CoapHandler {

		private boolean on;

		public synchronized boolean waitOn(long timeout) {
			on = false;
			if (timeout > 0) {
				try {
					wait(timeout);
				} catch (InterruptedException e) {
				}
			}
			return on;
		}

		private synchronized void on() {
			on = true;
			notifyAll();
		}

		@Override
		public void onLoad(CoapResponse response) {
			System.out.println(StringUtil.toString(response.advanced().getSourceContext().getPeerAddress()));
			System.out.println(Utils.prettyPrint(response));
			on();
		}

		@Override
		public void onError() {
			System.err.println("error");
		}
	};
}
