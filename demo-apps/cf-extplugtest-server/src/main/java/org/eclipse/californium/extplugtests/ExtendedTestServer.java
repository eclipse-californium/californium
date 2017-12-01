/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.extplugtests;

import java.net.SocketException;
import java.util.Arrays;

import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.OriginTracer;
import org.eclipse.californium.extplugtests.resources.RequestStatistic;
import org.eclipse.californium.plugtests.AbstractTestServer;
import org.eclipse.californium.plugtests.PlugtestServer;

/**
 * Extended test server.
 * 
 * Setup for larger blocks than the plugtest server and provides the request
 * statistic resource.
 */
public class ExtendedTestServer extends AbstractTestServer {

	public static void main(String[] args) {
		// start standard plugtest server
		PlugtestServer.main(args);

		// allows port configuration in Californium.properties
		NetworkConfig config = (NetworkConfig) NetworkConfig.getStandard().clone();
		config.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 1200).setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 1024);
		// start on alternative port, 5783 and 5784
		config.setInt(NetworkConfig.Keys.COAP_PORT, config.getInt(NetworkConfig.Keys.COAP_PORT) + 100);
		config.setInt(NetworkConfig.Keys.COAP_SECURE_PORT, config.getInt(NetworkConfig.Keys.COAP_SECURE_PORT) + 100);

		// create server
		try {
			boolean noLoopback = args.length > 0 ? args[0].equalsIgnoreCase("-noLoopback") : false;
			ExtendedTestServer server = new ExtendedTestServer();
			server.addEndpoints(config, !noLoopback,
					Arrays.asList(Protocol.UDP, Protocol.DTLS, Protocol.TCP, Protocol.TLS));
			server.start();

			// add special interceptor for message traces
			for (Endpoint ep : server.getEndpoints()) {
				System.out.println("listen on " + ep.getUri());
				// Eclipse IoT metrics
				ep.addInterceptor(new OriginTracer());
			}

			System.out.println(ExtendedTestServer.class.getSimpleName() + " started ...");

		} catch (Exception e) {

			System.err.printf("Failed to create " + ExtendedTestServer.class.getSimpleName() + ": %s\n",
					e.getMessage());
			e.printStackTrace(System.err);
			System.err.println("Exiting");
			System.exit(PlugtestServer.ERR_INIT_FAILED);
		}

	}

	public ExtendedTestServer() throws SocketException {

		// add resources to the server
		add(new RequestStatistic());
	}
}
