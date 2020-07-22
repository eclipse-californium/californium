/*******************************************************************************
 * Copyright (c) 2020 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.io.File;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.server.resources.CoapExchange;

/**
 * Example CoAP server for proxy demonstration.
 * 
 * {@link coap://localhost:5683/coap-target}
 */
public class ExampleCoapServer {
	/**
	 * File name for network configuration.
	 */
	private static final File CONFIG_FILE = new File("CaliforniumDemo.properties");
	/**
	 * Header for network configuration.
	 */
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Proxy Demo-Server";

	public static final String RESOURCE = "/coap-target";

	public static final int DEFAULT_COAP_PORT = 5685;

	/**
	 * Special network configuration defaults handler.
	 */
	private static final NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			config.setInt(Keys.COAP_PORT, DEFAULT_COAP_PORT);
		}
	};

	private CoapServer coapServer;

	public ExampleCoapServer(NetworkConfig config, final int port) throws IOException {
		String path = RESOURCE;
		if (path.startsWith("/")) {
			path = path.substring(1);
		}
		// Create CoAP Server on PORT with a target resource
		coapServer = new CoapServer(config, port);
		coapServer.add(new CoapResource(path) {

			private final AtomicInteger counter = new AtomicInteger();

			@Override
			public void handleGET(CoapExchange exchange) {
				exchange.setMaxAge(15);
				exchange.respond(ResponseCode.CONTENT,
						"Hi! I am the coap server on port " + port + ". Request " + counter.incrementAndGet() + ".",
						MediaTypeRegistry.TEXT_PLAIN);
			}

		});
		coapServer.start();
		System.out.println("Started CoAP server on port " + port);
		System.out.println("Request: coap://localhost:" + port + RESOURCE);
	}

	public static NetworkConfig init() {
		return NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
	}

	public static void main(String arg[]) throws IOException {
		NetworkConfig config = init();
		int port;
		if (arg.length > 0) {
			port = Integer.parseInt(arg[0]);
		} else {
			port = config.getInt(NetworkConfig.Keys.COAP_PORT);
		}
		new ExampleCoapServer(config, port);
	}
}
