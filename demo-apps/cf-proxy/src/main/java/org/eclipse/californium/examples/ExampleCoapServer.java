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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.io.IOException;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;

/**
 * Example CoAP server for proxy demonstration.
 * 
 * {@link coap://localhost:5683/coap-target}
 */
public class ExampleCoapServer {

	public static final String RESOURCE = "/coap-target";

	public static final int DEFAULT_PORT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.COAP_PORT);

	private CoapServer coapServer;

	public ExampleCoapServer(NetworkConfig config, final int port) throws IOException {
		String path = RESOURCE;
		if (path.startsWith("/")) {
			path = path.substring(1);
		}
		// Create CoAP Server on PORT with a target resource
		coapServer = new CoapServer(config, port);
		coapServer.add(new CoapResource(path) {

			@Override
			public void handleGET(CoapExchange exchange) {
				exchange.setMaxAge(0);
				exchange.respond(ResponseCode.CONTENT, "Hi! I am the Coap Server on port " + port + ".",
						MediaTypeRegistry.TEXT_PLAIN);
			}

		});
		coapServer.start();
		System.out.println("Started CoAP server on port " + port);
		System.out.println("Request: coap://localhost:" + port + RESOURCE);
	}

	public static void main(String arg[]) throws IOException {
		NetworkConfig config = NetworkConfig.getStandard();
		int port = DEFAULT_PORT;
		if (arg.length > 0) {
			port = Integer.parseInt(arg[0]);
		} else {
			port = config.getInt(NetworkConfig.Keys.COAP_PORT, port);
		}
		new ExampleCoapServer(config, port);
	}
}
