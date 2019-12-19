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
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * Test client configured to support multicast requests.
 */
public class MulticastTestClient {

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

	private static void get(CoapClient client) throws ConnectorException, IOException {
		client.setURI("coap://localhost:5683/helloWorld");

		Request request = Request.newGet();
		request.setType(Type.CON);

		// sends an uni-cast request
		CoapResponse response = client.advanced(request);
		if (response != null) {
			System.out.println(Utils.prettyPrint(response));
		} else {
			System.out.println("No response received.");
		}
	}

	private static void mget(CoapClient client, boolean ipv6) throws ConnectorException, IOException {
		if (ipv6) {
			if (NetworkInterfacesUtil.isAnyIpv6()) {
				client.setURI("coap://[" + CoAP.MULTICAST_IPV6_SITELOCAL.getHostAddress() + "]/helloWorld");
			} else {
				System.err.print("IPv6 not supported!");
				return;
			}
		} else {
			if (NetworkInterfacesUtil.isAnyIpv4()) {
				client.setURI("coap://" + CoAP.MULTICAST_IPV4.getHostAddress() + "/helloWorld");
			} else {
				System.err.print("IPv4 not supported!");
				return;
			}
		}
		Request multicastRequest = Request.newGet();
		multicastRequest.setType(Type.NON);
		// sends a multicast request
		client.advanced(handler, multicastRequest);
		while (handler.waitOn(2000))
			;
	}

	public static void main(String args[]) {

		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		CoapEndpoint endpoint = new CoapEndpoint.Builder().setNetworkConfig(config).build();
		CoapClient client = new CoapClient();
		client.setEndpoint(endpoint);

		try {
			// sends an uni-cast request
			get(client);
			// sends a multicast IPv4 request
			mget(client, false);
			// sends a multicast IPv6 request
			mget(client, true);
		} catch (ConnectorException | IOException e) {
			System.err.println("Error occurred while sending request: " + e);
		}

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
