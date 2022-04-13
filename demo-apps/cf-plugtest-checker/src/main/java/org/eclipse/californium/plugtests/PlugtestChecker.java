/*******************************************************************************
 * Copyright (c) 2015, 2018 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 *    Achim Kraus (Bosch Software Innovations GmbH) - apply source formatter
 *    Achim Kraus (Bosch Software Innovations GmbH) - add TCP and encryption support.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add notification processing and
 *                                                    adjust tests.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add block2 backward-compatibility
 *    Achim Kraus (Bosch Software Innovations GmbH) - add tcp compatibility
 *                                                    add hasNoObserver
 *                                                    wait for response, when cancel
 *                                                    observe relation
 ******************************************************************************/

package org.eclipse.californium.plugtests;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.cli.ClientBaseConfig;
import org.eclipse.californium.cli.ClientInitializer;
import org.eclipse.californium.cli.ConnectorConfig;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.config.CoapConfig.MatcherMode;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.ContextRederivation.PHASE;
import org.eclipse.californium.elements.config.SystemConfig;
import org.eclipse.californium.scandium.config.DtlsConfig;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * The PlugtestChecker is a client to verify the server behavior.
 * 
 * It uses Cf's internal API for "deep message inspection."
 */
public class PlugtestChecker {
	private static final File CONFIG_FILE = new File("CaliforniumPlugtest3.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Plugtest Client";
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 8192;
	private static final int DEFAULT_BLOCK_SIZE = 64;
	public static final int PLUGTEST_BLOCK_SZX = 2; // 64 bytes

	private static DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			// adjust defaults for plugtest
			config.set(SystemConfig.HEALTH_STATUS_INTERVAL, 300, TimeUnit.SECONDS);
			config.set(CoapConfig.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.set(CoapConfig.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.NOTIFICATION_CHECK_INTERVAL_COUNT, 4);
			config.set(CoapConfig.NOTIFICATION_CHECK_INTERVAL_TIME, 30, TimeUnit.SECONDS);
			config.set(CoapConfig.MAX_ACTIVE_PEERS, 10);
			config.set(CoapConfig.TCP_NUMBER_OF_BULK_BLOCKS, 1);
			config.set(DtlsConfig.DTLS_AUTO_HANDSHAKE_TIMEOUT, null, TimeUnit.SECONDS);
			config.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 0); // support it, but don't use it
			config.set(DtlsConfig.DTLS_MAX_CONNECTIONS, 10);
		}

	};

	static volatile boolean verbose;

	/** The server uri. */
	private String serverURI = null;

	/**
	 * Default constructor. Loads with reflection each nested class that is a
	 * derived type of TestClientAbstract.
	 * 
	 * @param serverURI the server uri
	 */
	public PlugtestChecker(String serverURI) {
		if (serverURI == null || serverURI.isEmpty()) {
			throw new IllegalArgumentException("No server URI given");
		}

		this.serverURI = serverURI;
	}

	/**
	 * Instantiates the given testNames, or if {@code null} all tests
	 * implemented.
	 * 
	 * @param testNames the test names
	 * @param oscore {@code true} support OSCORE, {@code false}, otherwise.
	 */
	public void instantiateTests(List<String> testNames, boolean oscore) {

		Catalog catalog = new Catalog();

		try {
			List<Class<?>> tests = catalog.getTestsClasses(testNames);
			if (tests.isEmpty()) {
				System.out.println("No matching TESTs found!"); // DEBUG
				return;
			}
			if (testNames != null && !testNames.isEmpty()) {
				// print tests only, if some are passed in
				System.out.println("Tests:");
				List<String> names = new ArrayList<String>(tests.size());
				for (Class<?> test : tests) {
					names.add(test.getSimpleName());
				}
				ClientInitializer.print("   ", ConnectorConfig.MAX_WIDTH, names, System.out);
			}

			List<Report> reports = new ArrayList<Report>();
			// iterate for each chosen test
			for (Class<?> testClass : tests) {
				if (!oscore && OscoreTest.class.isAssignableFrom(testClass)) {
					System.out.println("Drop OSCORE test " + testClass.getSimpleName()); // DEBUG
					continue;
				}
				System.out.println("Initialize test " + testClass); // DEBUG

				Constructor<?> cons = testClass.getConstructor(String.class);

				TestClientAbstract testClient = (TestClientAbstract) cons.newInstance(serverURI);
				try {
					testClient.waitForUntilTestHasTerminated();
				} catch (Throwable e) {
					System.err.println("Error: " + e.getMessage());
					break;
				}
				reports.add(testClient.getReport());
			}

			if (!reports.isEmpty()) {
				System.out.println("\n==== SUMMARY ====");
				for (Report report : reports) {
					report.print();
				}
			}

		} catch (InstantiationException e) {
			System.err.println("Reflection error");
			e.printStackTrace();
		} catch (IllegalAccessException e) {
			System.err.println("Reflection error");
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			System.err.println("Reflection error");
			e.printStackTrace();
		} catch (SecurityException e) {
			System.err.println("Reflection error");
			e.printStackTrace();
		} catch (NoSuchMethodException e) {
			System.err.println("Reflection error");
			e.printStackTrace();
		} catch (InvocationTargetException e) {
			System.err.println("Reflection error");
			e.printStackTrace();
		}
	}

	public synchronized void tickOffTest() {
		notify();
	}

	/**
	 * Main entry point.
	 * 
	 * Start the program with arguments {@code coap://localhost:5683 .*} to
	 * start all tests.
	 * 
	 * @param args the arguments
	 * @throws IOException if an i/o error starting the coap-endpoint occurred
	 */
	public static void main(String[] args) throws IOException {

		Config clientConfig = new Config();
		clientConfig.configurationHeader = CONFIG_HEADER;
		clientConfig.customConfigurationDefaultsProvider = DEFAULTS;
		clientConfig.configurationFile = CONFIG_FILE;
		ClientInitializer.init(args, clientConfig, false);
		if (clientConfig.helpRequested) {
			Catalog catalog = new Catalog();
			System.out.println("Available tests:");
			ClientInitializer.print("   ", ConnectorConfig.MAX_WIDTH, catalog.getAllTestNames(), System.out);
			System.exit(0);
		}
		if (clientConfig.oscore) {
			HashMapCtxDB db = new HashMapCtxDB();
			initOscore(clientConfig, db);
			OSCoreCoapStackFactory.useAsDefault(db);
		}
		ClientInitializer.registerEndpoint(clientConfig, null);

		verbose = clientConfig.verbose;

		if (clientConfig.tcp) {
			clientConfig.ping = false;
		} else if (clientConfig.secure
				&& clientConfig.configuration.get(CoapConfig.RESPONSE_MATCHING) == MatcherMode.PRINCIPAL_IDENTITY) {
			clientConfig.ping = true;
		}

		if (clientConfig.ping) {
			System.out.println("===============\nCC31\n---------------");
			try {
				if (ping(clientConfig.uri)) {
					System.out.println("PASS: " + clientConfig.uri + " responds to ping");
				} else {
					System.out.println("FAIL:" + clientConfig.uri + " does not respond to ping, exiting...");
					System.exit(-1);
				}
			} catch (Throwable ex) {
				System.err.println("Error: " + clientConfig.uri + " - " + ex.getMessage());
				System.exit(-1);
			}
		}

		// create the factory with the given server URI
		PlugtestChecker clientFactory = new PlugtestChecker(clientConfig.uri);

		// instantiate the chosen tests
		clientFactory.instantiateTests(clientConfig.tests, clientConfig.oscore);

		System.exit(0);
	}

	private static boolean ping(String address) throws Throwable {
		Request request = new Request(null);
		request.setType(Type.CON);
		request.setToken(Token.EMPTY);
		request.setURI(address);
		TestClientAbstract.addContextObserver(request);
		System.out.println("++++++ Sending Ping ++++++");
		request.send().waitForResponse(5000);
		Throwable sendError = request.getSendError();
		if (sendError != null) {
			throw sendError;
		}
		return request.isRejected();
	}

	public static String getLargeRequestPayload() {
		return new StringBuilder().append("/-------------------------------------------------------------\\\n")
				.append("|                  Request BLOCK NO. 1 OF 5                   |\n")
				.append("|               [each line contains 64 bytes]                 |\n")
				.append("\\-------------------------------------------------------------/\n")
				.append("/-------------------------------------------------------------\\\n")
				.append("|                  Request BLOCK NO. 2 OF 5                   |\n")
				.append("|               [each line contains 64 bytes]                 |\n")
				.append("\\-------------------------------------------------------------/\n")
				.append("/-------------------------------------------------------------\\\n")
				.append("|                  Request BLOCK NO. 3 OF 5                   |\n")
				.append("|               [each line contains 64 bytes]                 |\n")
				.append("\\-------------------------------------------------------------/\n")
				.append("/-------------------------------------------------------------\\\n")
				.append("|                  Request BLOCK NO. 4 OF 5                   |\n")
				.append("|               [each line contains 64 bytes]                 |\n")
				.append("\\-------------------------------------------------------------/\n")
				.append("/-------------------------------------------------------------\\\n")
				.append("|                  Request BLOCK NO. 5 OF 5                   |\n")
				.append("|               [each line contains 64 bytes]                 |\n")
				.append("\\-------------------------------------------------------------/\n").toString();
	}

	/**
	 * Initializes an OSCORE context for the client built on a pre-defined
	 * configuration and adds it to the OSCORE context database. The created
	 * context will support and by default always use the Appendix B.2 context
	 * rederivation procedure. This is to avoid message replay errors that would
	 * otherwise arise for clients.
	 * 
	 * @param config configuration with the URI of the OSCORE resource at the server
	 * @param db the OSCORE context database
	 */
	public static void initOscore(ClientBaseConfig config, HashMapCtxDB db) {
		AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
		AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

		byte[] master_secret = StringUtil.hex2ByteArray("0102030405060708090a0b0c0d0e0f10");
		byte[] master_salt = StringUtil.hex2ByteArray("9e7ca92223786340");
		byte[] sid = StringUtil.hex2ByteArray("01");
		byte[] rid = StringUtil.hex2ByteArray("02");
		byte[] id_context = StringUtil.hex2ByteArray("37cbf3210017a2d3");
		int MAX_UNFRAGMENTED_SIZE = config.configuration.get(CoapConfig.MAX_RESOURCE_BODY_SIZE);

		OSCoreCtx ctx = null;
		try {
			ctx = new OSCoreCtx(master_secret, false, alg, sid, rid, kdf, 32, master_salt, id_context,
					MAX_UNFRAGMENTED_SIZE);
			ctx.setContextRederivationEnabled(true);
			ctx.setContextRederivationPhase(PHASE.CLIENT_INITIATE);
			db.addContext(config.uri, ctx);
		} catch (OSException e) {
			e.printStackTrace();
		}
	}

	@Command(name = "PlugtestChecker", version = "(c) 2014, Institute for Pervasive Computing, ETH Zurich.")
	private static class Config extends ClientBaseConfig {

		@Option(names = "--no-ping", negatable = true, description = "use ping.")
		public boolean ping = true;

		@Option(names = "--no-oscore", negatable = true, description = "use OSCORE.")
		public boolean oscore = true;

		@Option(names = "--tests", paramLabel = "TESTs", split = ",", description = "TESTs")
		public List<String> tests;
	}
}
