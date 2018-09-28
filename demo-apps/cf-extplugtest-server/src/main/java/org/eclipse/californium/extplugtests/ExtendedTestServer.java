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
 *    Achim Kraus (Bosch Software Innovations GmbH) - use special properties file
 *                                                    for configuration
 *    Achim Kraus (Bosch Software Innovations GmbH) - add benchmark
 *    Achim Kraus (Bosch Software Innovations GmbH) - use executors util.
 ******************************************************************************/
package org.eclipse.californium.extplugtests;

import java.io.File;
import java.net.SocketException;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.core.network.interceptors.AnonymizedOriginTracer;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.extplugtests.resources.Benchmark;
import org.eclipse.californium.extplugtests.resources.RequestStatistic;
import org.eclipse.californium.extplugtests.resources.ReverseObserve;
import org.eclipse.californium.extplugtests.resources.ReverseRequest;
import org.eclipse.californium.plugtests.AbstractTestServer;
import org.eclipse.californium.plugtests.PlugtestServer;

/**
 * Extended test server.
 * 
 * Setup for larger blocks than the plugtest server and provides the request
 * statistic resource.
 */
public class ExtendedTestServer extends AbstractTestServer {

	private static final File CONFIG_FILE = new File("CaliforniumReceivetest.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Receivetest Server";
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 8192;
	private static final int DEFAULT_BLOCK_SIZE = 1024;

	private static NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			// start on alternative port, 5783 and 5784
			config.setInt(Keys.COAP_PORT, config.getInt(Keys.COAP_PORT) + 100);
			config.setInt(Keys.COAP_SECURE_PORT, config.getInt(Keys.COAP_SECURE_PORT) + 100);
			config.setInt(Keys.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.EXCHANGE_LIFETIME, 24700); // 24.7s instead of 247s
			config.setInt(Keys.MAX_ACTIVE_PEERS, 20000);
			config.setInt(Keys.MAX_PEER_INACTIVITY_PERIOD, 60 * 60 * 24); // 24h
			config.setInt(Keys.TCP_CONNECTION_IDLE_TIMEOUT, 60 * 60 * 12); // 12h
			config.setInt(Keys.SECURE_SESSION_TIMEOUT, 60 * 60 * 24); // 24h
			config.setInt(Keys.HEALTH_STATUS_INTERVAL, 60); // 60s
			int processors = Runtime.getRuntime().availableProcessors();
			config.setInt(Keys.NETWORK_STAGE_RECEIVER_THREAD_COUNT, processors/2);
			config.setInt(Keys.NETWORK_STAGE_SENDER_THREAD_COUNT, processors);
		}

	};

	public static void main(String[] args) {
		System.out.println("\nCalifornium (Cf) Extended Plugtest Server");
		System.out.println("(c) 2017, Bosch Software Innovations GmbH and others");
		System.out.println();
		System.out.println(
				"Usage: " + ExtendedTestServer.class.getSimpleName() + " [-noLoopback|-onlyLoopback|-onlyDtlsLoopback [-noBenchmark|noPlugtest]]");
		System.out.println("  -noLoopback  : no endpoints for loopback/localhost interfaces");
		System.out.println("  -onlyLoopback: endpoints only for loopback/localhost interfaces");
		System.out.println("  -onlyDtlsLoopback: endpoint only for loopback with DTLS");
		System.out.println("  -noBenchmark : disable benchmark resource");
		System.out.println("  -noPlugtest  : disable plugtest server");

		boolean noPlugtest = args.length > 1 ? args[1].equalsIgnoreCase("-noPlugTest") : false;
		if (!noPlugtest) {
			// start standard plugtest server
			PlugtestServer.start(args);
		}

		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		// create server
		try {
			boolean onlyLoopback = args.length > 0 ? args[0].equalsIgnoreCase("-onlyLoopback") : false;
			boolean noLoopback = args.length > 0 ? args[0].equalsIgnoreCase("-noLoopback") : false;
			boolean onlyDtlsLoopback = args.length > 0 ? args[0].equalsIgnoreCase("-onlyDtlsLoopback") : false;
			boolean noBenchmark = args.length > 1 ? args[1].equalsIgnoreCase("-noBenchmark") : false;
			List<Protocol> protocols = Arrays.asList(Protocol.UDP, Protocol.DTLS, Protocol.TCP, Protocol.TLS);
			List<InterfaceType> types = null;
			if (noLoopback) {
				types = Arrays.asList(InterfaceType.EXTERNAL, InterfaceType.IPV4, InterfaceType.IPV6);
			} else if (onlyLoopback) {
				types = Arrays.asList(InterfaceType.LOCAL, InterfaceType.IPV4);
			} else if (onlyDtlsLoopback) {
				types = Arrays.asList(InterfaceType.LOCAL, InterfaceType.IPV4);
				protocols = Arrays.asList(Protocol.DTLS);
			}

			ScheduledExecutorService executor = ExecutorsUtil.newScheduledThreadPool(//
					config.getInt(NetworkConfig.Keys.PROTOCOL_STAGE_THREAD_COUNT), //
					new NamedThreadFactory("CoapServer#")); //$NON-NLS-1$

			ExtendedTestServer server = new ExtendedTestServer(config, noBenchmark);
			server.setExecutor(executor);
			ReverseObserve reverseObserver = new ReverseObserve(config, executor);
			server.add(reverseObserver);
			server.addEndpoints(null, types, protocols);
			for (Endpoint ep : server.getEndpoints()) {
				ep.addNotificationListener(reverseObserver);
			}
			server.start();

			// add special interceptor for message traces
			for (Endpoint ep : server.getEndpoints()) {
				System.out.println("listen on " + ep.getUri());
				if (noBenchmark) {
					// Anonymized IoT metrics for validation. On success, remove the OriginTracer. 
					URI uri = ep.getUri();
					ep.addInterceptor(new AnonymizedOriginTracer(uri.getPort() + "-" + uri.getScheme()));
					ep.addInterceptor(new MessageTracer());
				}
			}

			if (noBenchmark) {
				System.out.println(ExtendedTestServer.class.getSimpleName() + " without benchmark started ...");
			} else {
				Runtime runtime = Runtime.getRuntime();
				long max = runtime.maxMemory();
				System.out.println(
						ExtendedTestServer.class.getSimpleName() + " started (" + max / (1024 * 1024) + "MB heap) ...");
				for (;;) {
					try {
						Thread.sleep(15000);
					} catch (InterruptedException e) {
						break;
					}
					long used = runtime.totalMemory() - runtime.freeMemory();
					int fill = (int) ((used * 100L) / max);
					if (fill > 80) {
						System.out.println("Maxium heap size: " + max / (1024 * 1024) + "M " + fill + "% used.");
						System.out.println("Heap may exceed! Enlarge the maxium heap size.");
						System.out.println("Or consider to reduce the value of " + Keys.EXCHANGE_LIFETIME);
						System.out.println("in \"" + CONFIG_FILE + "\" or set");
						System.out.println(Keys.DEDUPLICATOR + " to " + Keys.NO_DEDUPLICATOR + " there.");
						break;
					}
				}
			}

		} catch (Exception e) {

			System.err.printf("Failed to create " + ExtendedTestServer.class.getSimpleName() + ": %s\n",
					e.getMessage());
			e.printStackTrace(System.err);
			System.err.println("Exiting");
			System.exit(PlugtestServer.ERR_INIT_FAILED);
		}

	}

	public ExtendedTestServer(NetworkConfig config, boolean noBenchmark) throws SocketException {
		super(config);
		int maxResourceSize = config.getInt(Keys.MAX_RESOURCE_BODY_SIZE);
		// add resources to the server
		add(new RequestStatistic());
		add(new ReverseRequest(config));
		add(new Benchmark(noBenchmark, maxResourceSize));
	}
}
