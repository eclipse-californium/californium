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

import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.proxy.HttpServer;

/**
 * Example HTTP server for proxy demonstration.
 * 
 * {@link http://localhost:8000/http-target}
 */
public class ExampleHttpServer {

	public static final int DEFAULT_PORT = 8000;
	public static final String RESOURCE = "/http-target";

	public ExampleHttpServer(NetworkConfig config, final int httpPort) throws IOException {
		HttpServer server = new HttpServer(config, httpPort);
		server.setSimpleResource(RESOURCE, "Hi! I am the Http Server on port %d. Request: %d", null);
		server.start();
	}

	public static void main(String arg[]) throws IOException {
		// NetworkConfig HTTP_PORT is used for proxy
		NetworkConfig config = NetworkConfig.getStandard();
		int port = DEFAULT_PORT;
		if (arg.length > 0) {
			port = Integer.parseInt(arg[0]);
		}
		new ExampleHttpServer(config, port);
	}
}
