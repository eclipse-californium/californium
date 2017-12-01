/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Achim Kraus (Bosch Software Innovations GmbH) - add TCP and encryption support.
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - split creating connectors into
 *                                                    AbstractTestServer.
 ******************************************************************************/
package org.eclipse.californium.plugtests;

import java.net.SocketException;
import java.util.Arrays;

import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.network.interceptors.OriginTracer;
import org.eclipse.californium.plugtests.resources.Create;
import org.eclipse.californium.plugtests.resources.DefaultTest;
import org.eclipse.californium.plugtests.resources.Large;
import org.eclipse.californium.plugtests.resources.LargeCreate;
import org.eclipse.californium.plugtests.resources.LargePost;
import org.eclipse.californium.plugtests.resources.LargeSeparate;
import org.eclipse.californium.plugtests.resources.LargeUpdate;
import org.eclipse.californium.plugtests.resources.Link1;
import org.eclipse.californium.plugtests.resources.Link2;
import org.eclipse.californium.plugtests.resources.Link3;
import org.eclipse.californium.plugtests.resources.LocationQuery;
import org.eclipse.californium.plugtests.resources.LongPath;
import org.eclipse.californium.plugtests.resources.MultiFormat;
import org.eclipse.californium.plugtests.resources.Observe;
import org.eclipse.californium.plugtests.resources.ObserveLarge;
import org.eclipse.californium.plugtests.resources.ObserveNon;
import org.eclipse.californium.plugtests.resources.ObservePumping;
import org.eclipse.californium.plugtests.resources.ObserveReset;
import org.eclipse.californium.plugtests.resources.Path;
import org.eclipse.californium.plugtests.resources.Query;
import org.eclipse.californium.plugtests.resources.Separate;
import org.eclipse.californium.plugtests.resources.Shutdown;
import org.eclipse.californium.plugtests.resources.Validate;

// ETSI Plugtest environment
//import java.net.InetSocketAddress;
//import org.eclipse.californium.core.network.CoAPEndpoint;

/**
 * The class PlugtestServer implements the test specification for the ETSI IoT
 * CoAP Plugtests, London, UK, 7--9 Mar 2014.
 */
public class PlugtestServer extends AbstractTestServer {

	// exit codes for runtime errors
	public static final int ERR_INIT_FAILED = 1;
	private static final int MAX_RESOURCE_SIZE = 8192;

	public static void main(String[] args) {
		// allows port configuration in Californium.properties
		NetworkConfig config = NetworkConfig.getStandard();
		config // used for plugtest
		.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 64).setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 64)
		.setInt(NetworkConfig.Keys.NOTIFICATION_CHECK_INTERVAL_COUNT, 4)
		.setInt(NetworkConfig.Keys.NOTIFICATION_CHECK_INTERVAL_TIME, 30000)
		.setInt(NetworkConfig.Keys.HEALTH_STATUS_INTERVAL, 300);

		if (config.getInt(NetworkConfig.Keys.MAX_RESOURCE_BODY_SIZE) < MAX_RESOURCE_SIZE) {
			config.setInt(NetworkConfig.Keys.MAX_RESOURCE_BODY_SIZE, MAX_RESOURCE_SIZE);
		}

		// create server
		try {
			boolean noLoopback = args.length > 0 ? args[0].equalsIgnoreCase("-noLoopback") : false;
			PlugtestServer server = new PlugtestServer();
			// ETSI Plugtest environment
//			server.addEndpoint(new CoAPEndpoint(new InetSocketAddress("::1", port)));
//			server.addEndpoint(new CoAPEndpoint(new InetSocketAddress("127.0.0.1", port)));
//			server.addEndpoint(new CoAPEndpoint(new InetSocketAddress("2a01:c911:0:2010::10", port)));
//			server.addEndpoint(new CoAPEndpoint(new InetSocketAddress("10.200.1.2", port)));
			server.addEndpoints(config, !noLoopback, Arrays.asList(Protocol.UDP, Protocol.DTLS, Protocol.TCP, Protocol.TLS));
			server.start();

			// add special interceptor for message traces
			for (Endpoint ep : server.getEndpoints()) {
				System.out.println("listen on " + ep.getUri());
				ep.addInterceptor(new MessageTracer());
				// Eclipse IoT metrics
				ep.addInterceptor(new OriginTracer());
			}

			System.out.println(PlugtestServer.class.getSimpleName() + " started ...");

		} catch (Exception e) {

			System.err.printf("Failed to create " + PlugtestServer.class.getSimpleName() + ": %s\n", e.getMessage());
			e.printStackTrace(System.err);
			System.err.println("Exiting");
			System.exit(ERR_INIT_FAILED);
		}

	}

	public PlugtestServer() throws SocketException {

		// add resources to the server
		add(new DefaultTest());
		add(new LongPath());
		add(new Query());
		add(new Separate());
		add(new Large());
		add(new LargeUpdate());
		add(new LargeCreate());
		add(new LargePost());
		add(new LargeSeparate());
		add(new Observe());
		add(new ObserveNon());
		add(new ObserveReset());
		add(new ObserveLarge());
		add(new ObservePumping());
		add(new ObservePumping(Type.NON));
		add(new LocationQuery());
		add(new MultiFormat());
		add(new Link1());
		add(new Link2());
		add(new Link3());
		add(new Path());
		add(new Validate());
		add(new Create());
		add(new Shutdown());
	}
}
