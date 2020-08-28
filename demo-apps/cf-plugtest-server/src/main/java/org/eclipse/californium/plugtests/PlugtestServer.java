/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Achim Kraus (Bosch Software Innovations GmbH) - add TCP and encryption support.
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - split creating connectors into
 *                                                    AbstractTestServer.
 *    Achim Kraus (Bosch Software Innovations GmbH) - use special properties file
 *                                                    for configuration
 ******************************************************************************/
package org.eclipse.californium.plugtests;

import java.io.File;
import java.net.SocketException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ScheduledThreadPoolExecutor;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointObserver;
import org.eclipse.californium.core.network.MessagePostProcessInterceptors;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.core.network.interceptors.AnonymizedOriginTracer;
import org.eclipse.californium.core.network.interceptors.HealthStatisticLogger;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.elements.tcp.netty.TlsServerConnector.ClientAuthMode;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.plugtests.resources.Create;
import org.eclipse.californium.plugtests.resources.DefaultTest;
import org.eclipse.californium.plugtests.resources.Hono;
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
import org.eclipse.californium.plugtests.resources.MyIp;
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

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.ParseResult;

// ETSI Plugtest environment
//import java.net.InetSocketAddress;
//import org.eclipse.californium.core.network.CoAPEndpoint;

/**
 * The class PlugtestServer implements the test specification for the ETSI IoT
 * CoAP Plugtests, London, UK, 7--9 Mar 2014.
 */
public class PlugtestServer extends AbstractTestServer {
	private static final File CONFIG_FILE = new File("CaliforniumPlugtest.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Plugtest Server";
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 8192;
	private static final int DEFAULT_BLOCK_SIZE = 64;

	// exit codes for runtime errors
	public static final int ERR_INIT_FAILED = 1;

	private static NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			config.setInt(Keys.DTLS_AUTO_RESUME_TIMEOUT, 0);
			config.setInt(Keys.DTLS_CONNECTION_ID_LENGTH, 6);
			config.setInt(Keys.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.NOTIFICATION_CHECK_INTERVAL_COUNT, 4);
			config.setInt(Keys.NOTIFICATION_CHECK_INTERVAL_TIME, 30000);
			config.setInt(Keys.HEALTH_STATUS_INTERVAL, 300);
			config.setInt(Keys.UDP_CONNECTOR_RECEIVE_BUFFER, 0);
			config.setInt(Keys.UDP_CONNECTOR_SEND_BUFFER, 0);
		}
	};

	public static class BaseConfig {

		@Option(names = "--no-loopback", negatable = true, description = "enable endpoints on loopback network.")
		public boolean loopback = true;

		@Option(names = "--no-external", negatable = true, description = "enable endpoints on external network.")
		public boolean external = true;

		@Option(names = "--no-ipv4", negatable = true, description = "enable endpoints for ipv4.")
		public boolean ipv4 = true;

		@Option(names = "--no-ipv6", negatable = true, description = "enable endpoints for ipv6.")
		public boolean ipv6 = true;

		@Option(names = "--no-tcp", negatable = true, description = "enable endpoints for tcp.")
		public boolean tcp = true;

		@Option(names = "--dtls-only", description = "only dtls endpoints.")
		public boolean onlyDtls;

		@Option(names = "--trust-all", description = "trust all valid certificates.")
		public boolean trustall;

		@Option(names = "--client-auth", description = "client authentication.")
		public ClientAuthMode clientAuth = ClientAuthMode.NEEDED;

		@Option(names = "--interfaces", split = ",", description = "interfaces for endpoints.")
		public List<String> interfaceNames;

		@Option(names = "--interfaces-pattern", split = ",", description = "interface patterns for endpoints.")
		public List<String> interfacePatterns;

	}

	@Command(name = "PlugtestServer", version = "(c) 2014, Institute for Pervasive Computing, ETH Zurich.")
	public static class Config extends BaseConfig {

	}

	private static final Config config = new Config();

	public static void main(String[] args) {
		CommandLine cmd = new CommandLine(config);
		try {
			ParseResult result = cmd.parseArgs(args);
			if (result.isVersionHelpRequested()) {
				String version = StringUtil.CALIFORNIUM_VERSION == null ? "" : StringUtil.CALIFORNIUM_VERSION;
				System.out.println("\nCalifornium (Cf) " + cmd.getCommandName() + " " + version);
				cmd.printVersionHelp(System.out);
				System.out.println();
			}
			if (result.isUsageHelpRequested()) {
				cmd.usage(System.out);
				return;
			}
		} catch (ParameterException ex) {
			System.err.println(ex.getMessage());
			System.err.println();
			cmd.usage(System.err);
			System.exit(-1);
		}
		start(config);
	}

	public static void start(BaseConfig config) {

		NetworkConfig netconfig = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);

		// create server
		try {
			List<Protocol> protocols;
			
			if (config.onlyDtls) {
				protocols = Arrays.asList(Protocol.DTLS);
			} else if (config.tcp) {
				protocols = Arrays.asList(Protocol.UDP, Protocol.DTLS, Protocol.TCP, Protocol.TLS);
			} else {
				protocols = Arrays.asList(Protocol.UDP, Protocol.DTLS);
			}

			List<InterfaceType> types = new ArrayList<InterfaceType>();
			if (config.external) {
				types.add(InterfaceType.EXTERNAL);
			}
			if (config.loopback) {
				types.add(InterfaceType.LOCAL);
			}
			int s = types.size();
			if (s == 0) {
				System.err.println("Either --loopback or --external must be enabled!");
				System.exit(1);
			}
			if (config.ipv6) {
				types.add(InterfaceType.IPV6);
			}
			if (config.ipv4) {
				types.add(InterfaceType.IPV4);
			}
			if (s == types.size()) {
				System.err.println("Either --ipv4 or --ipv6 must be enabled!");
			}
			String pattern = config.interfacePatterns != null && !config.interfacePatterns.isEmpty()
					? config.interfacePatterns.get(0)
					: null;

			PlugtestServer server = new PlugtestServer(netconfig);
			// ETSI Plugtest environment
//			server.addEndpoint(new CoAPEndpoint(new InetSocketAddress("::1", port)));
//			server.addEndpoint(new CoAPEndpoint(new InetSocketAddress("127.0.0.1", port)));
//			server.addEndpoint(new CoAPEndpoint(new InetSocketAddress("2a01:c911:0:2010::10", port)));
//			server.addEndpoint(new CoAPEndpoint(new InetSocketAddress("10.200.1.2", port)));
			server.addEndpoints(pattern, types, protocols, config);
			server.start();

			ScheduledThreadPoolExecutor executor = ExecutorsUtil.newDefaultSecondaryScheduler("Health#");

			// add special interceptor for message traces
			for (Endpoint ep : server.getEndpoints()) {
				URI uri = ep.getUri();
				ep.addInterceptor(new MessageTracer());
				// Anonymized IoT metrics for validation. On success, remove the OriginTracer.
				ep.addInterceptor(new AnonymizedOriginTracer(uri.getPort() + "-" + uri.getScheme()));
				if (ep instanceof MessagePostProcessInterceptors) {
					int interval = ep.getConfig().getInt(NetworkConfig.Keys.HEALTH_STATUS_INTERVAL);
					final HealthStatisticLogger healthLogger = new HealthStatisticLogger(uri.getScheme(),
							!CoAP.isTcpScheme(uri.getScheme()), interval, executor);
					if (healthLogger.isEnabled()) {
						((MessagePostProcessInterceptors) ep).addPostProcessInterceptor(healthLogger);
						ep.addObserver(new EndpointObserver() {

							@Override
							public void stopped(Endpoint endpoint) {
								healthLogger.stop();
							}

							@Override
							public void started(Endpoint endpoint) {
								healthLogger.start();
							}

							@Override
							public void destroyed(Endpoint endpoint) {
								healthLogger.stop();
							}
						});
						healthLogger.start();
					}
				}
			}

			System.out.println(PlugtestServer.class.getSimpleName() + " started ...");

		} catch (Exception e) {

			System.err.printf("Failed to create " + PlugtestServer.class.getSimpleName() + ": %s\n", e.getMessage());
			e.printStackTrace(System.err);
			System.err.println("Exiting");
			System.exit(ERR_INIT_FAILED);
		}

	}

	public PlugtestServer(NetworkConfig config) throws SocketException {
		super(config, null);

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
		add(new Hono("telemetry"));
		add(new Hono("event"));
		add(new MyIp(MyIp.RESOURCE_NAME, false));
	}
}
