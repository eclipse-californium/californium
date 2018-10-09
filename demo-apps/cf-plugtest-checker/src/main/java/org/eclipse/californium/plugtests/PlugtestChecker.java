/*******************************************************************************
 * Copyright (c) 2015, 2018 Institute for Pervasive Computing, ETH Zurich and others.
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
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.LinkFormat;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.core.observe.NotificationListener;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.plugtests.ClientInitializer.Arguments;

/**
 * The PlugtestChecker is a client to verify the server behavior.
 * 
 * It uses Cf's internal API for "deep message inspection."
 */
public class PlugtestChecker {
	private static final File CONFIG_FILE = new File("CaliforniumPlugtest.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Plugtest Client";
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 8192;
	private static final int DEFAULT_BLOCK_SIZE = 64;
	public static final int PLUGTEST_BLOCK_SZX = 2; // 64 bytes

	private static NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			// adjust defaults for plugtest
			config.setInt(Keys.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.NOTIFICATION_CHECK_INTERVAL_COUNT, 4);
			config.setInt(Keys.NOTIFICATION_CHECK_INTERVAL_TIME, 30000);
			config.setInt(Keys.HEALTH_STATUS_INTERVAL, 300);
			config.setInt(Keys.MAX_ACTIVE_PEERS, 10);
		}

	};

	private static volatile boolean verbose;
	
	/** The server uri. */
	private String serverURI = null;

	/** The test map. */
	private final Map<String, Class<?>> testMap = new HashMap<String, Class<?>>();

	/** The test list. */
	protected List<String> testsToRun = new ArrayList<String>();

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

		// fill the map with each nested class not abstract that instantiate
		// TestClientAbstract
		for (Class<?> clientTest : this.getClass().getDeclaredClasses()) {
			if (!Modifier.isAbstract(clientTest.getModifiers())
					&& (clientTest.getSuperclass() == TestClientAbstract.class)) {

				this.testMap.put(clientTest.getSimpleName(), clientTest);
			}
		}
	}

	/**
	 * Instantiates the given testNames, or if {@code null} all tests
	 * implemented.
	 * 
	 * @param testNames the test names
	 */
	public void instantiateTests(String... testNames) {

		Catalog catalog = new Catalog();

		try {
			List<Report> reports = new ArrayList<Report>();

			Arrays.sort(testNames);
			List<Class<?>> tests = catalog.getTestsClasses(testNames);

			// iterate for each chosen test
			for (Class<?> testClass : tests) {
				System.out.println("Initialize test " + testClass); // DEBUG

				Constructor<?> cons = testClass.getConstructor(String.class);

				TestClientAbstract testClient = (TestClientAbstract) cons.newInstance(serverURI);
				testClient.waitForUntilTestHasTerminated();
				reports.add(testClient.getReport());
			}

			System.out.println("\n==== SUMMARY ====");
			for (Report report : reports) {
				report.print();
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
	 */
	public static void main(String[] args) {

		if (args.length == 0) {

			Catalog catalog = new Catalog();

			System.out.println("\nCalifornium (Cf) Plugtest Server Checker");
			System.out.println("(c) 2014, Institute for Pervasive Computing, ETH Zurich");
			System.out.println();
			System.out.println("Usage: " + PlugtestChecker.class.getSimpleName() + " [-s] URI [TESTNAMES...]");
			System.out.println("  -s        : Skip the ping in case the remote does not implement it");
			System.out.println("  -v        : verbose. Enable message tracing.");
			System.out.println("  -r        : use raw public certificate. Default PSK.");
			System.out.println("  -x        : use x.509 certificate");
			System.out.println("  URI       : The CoAP URI of the Plugtest server to test (coap://...)");
			System.out.println("  TESTNAMES : A list of specific tests to run, omit to run all");
			System.out.println();
			System.out.println("Available tests:");
			System.out.print(" ");

			for (String name : catalog.getAllTestNames()) {
				System.out.print(" " + name);
			}
			System.exit(-1);
		}

		// Config used for plugtest
		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		Arguments arguments = ClientInitializer.init(config, args);

		if (arguments.ping) {
			System.out.println("===============\nCC31\n---------------");
			if (ping(arguments.uri)) {
				System.out.println("PASS: " + arguments.uri + " responds to ping");
			} else {
				System.out.println("FAIL:" + arguments.uri + " does not respond to ping, exiting...");
				System.exit(-1);
			}
		}

		// create the factory with the given server URI
		PlugtestChecker clientFactory = new PlugtestChecker(arguments.uri);

		// instantiate the chosen tests
		clientFactory.instantiateTests(arguments.args);

		System.exit(0);
	}

	/**
	 * Abstract class to support various test client implementations.
	 */
	public static abstract class TestClientAbstract {

		protected Report report = new Report();

		protected Semaphore terminated = new Semaphore(0);

		/** The test name. */
		protected String testName = null;

		/** The verbose. */
		protected boolean verbose = true;

		/**
		 * Use synchronous or asynchronous requests. Sync recommended due to
		 * single threaded servers and slow resources.
		 */
		protected boolean sync = true;

		protected boolean useTcp = false;

		/**
		 * Current started observation.
		 */
		protected volatile Request observe;

		/**
		 * Last received notification.
		 * 
		 * Replaces deprecated notification processing with
		 * {@link Request#waitForResponse(long)}.
		 * 
		 * @see #waitForNotification(int)
		 * @see #startObserve(Request)
		 * @see #stopObservation()
		 */
		protected AtomicReference<Response> notification = new AtomicReference<Response>();

		/**
		 * Notification listener forwarding notifications to
		 * {@link #waitForNotification(int)}.
		 */
		protected TestNotificationListener listener;

		/**
		 * Instantiates a new test client abstract.
		 * 
		 * @param testName the test name
		 * @param verbose the verbose
		 */
		public TestClientAbstract(String testName, boolean verbose, boolean synchronous) {
			if (testName == null || testName.isEmpty()) {
				throw new IllegalArgumentException("testName == null || testName.isEmpty()");
			}

			this.testName = testName;
			this.verbose = verbose;
			this.sync = synchronous;
		}

		/**
		 * Instantiates a new test client abstract.
		 * 
		 * @param testName the test name
		 */
		public TestClientAbstract(String testName) {
			this(testName, PlugtestChecker.verbose, true);
		}

		public void setUseTcp(String scheme) {
			useTcp = CoAP.isTcpScheme(scheme);
		}

		/**
		 * Start observe.
		 */
		protected void startObserve(Request request) {
			stopObservation();
			Endpoint outEndpoint = EndpointManager.getEndpointManager().getDefaultEndpoint(request.getScheme());
			listener = new TestNotificationListener(outEndpoint);
			outEndpoint.addNotificationListener(listener);
			observe = request;
			request.send(outEndpoint);
		}

		/**
		 * Wait for notification.
		 * 
		 * @param timeout timeout in milliseconds
		 * @return response, or {@code null}, if no response is received within
		 *         the provided timeout.
		 * @throws IllegalStateException if the observation was not started
		 *             calling {@link #startObserve(Request)}
		 * @throws InterruptedException if thread was interrupted during wait.
		 */
		protected Response waitForNotification(long timeout) throws IllegalStateException, InterruptedException {
			if (listener == null) {
				throw new IllegalStateException("missing startObserve");
			}
			Response notify = null;
			synchronized (notification) {
				notify = notification.get();
				if (notify == null) {
					notification.wait(timeout);
					notify = notification.get();
				}
				notification.set(null);
			}
			return notify;
		}

		/**
		 * Stop observation and free resources.
		 */
		protected void stopObservation() {
			if (listener != null) {
				listener.close();
				listener = null;
				observe = null;
			}
		}

		/**
		 * Execute request.
		 * 
		 * @param request the request
		 * @param serverURI the server uri
		 * @param resourceUri the resource uri
		 */
		protected void executeRequest(Request request, String serverURI, String resourceUri) {

			// defensive check for slash
			if (!serverURI.endsWith("/") && !resourceUri.startsWith("/")) {
				resourceUri = "/" + resourceUri;
			}

			URI uri = null;
			try {
				uri = new URI(serverURI + resourceUri);
				useTcp = CoAP.isTcpScheme(uri.getScheme());
			} catch (URISyntaxException use) {
				System.err.println("Invalid URI: " + use.getMessage());
			}

			request.setURI(uri);

			request.addMessageObserver(new TestResponseHandler(request));

			// print request info
			if (verbose) {
				System.out.println("Request for test " + this.testName + " sent");
				Utils.prettyPrint(request);
			}

			// execute the request
			try {
				request.send();
				if (sync) {
					request.waitForResponse(5000);
				}
			} catch (InterruptedException e) {
				System.err.println("Interupted during receive: " + e.getMessage());
				System.exit(-1);
			}
		}

		public synchronized void addSummaryEntry(String entry) {
			report.addEntry(entry);
		}

		public Report getReport() {
			return report;
		}

		public synchronized void tickOffTest() {
			terminated.release();
		}

		public void waitForUntilTestHasTerminated() {
			try {
				terminated.acquire();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		/**
		 * The Class TestResponseHandler.
		 */
		protected class TestResponseHandler extends MessageObserverAdapter {

			private Request request;
			private final AtomicInteger requestCounter = new AtomicInteger();
			
			public TestResponseHandler(Request request) {
				this.request = request;
			}

			@Override
			public void onRetransmission() {
				requestCounter.decrementAndGet();
			}

			@Override
			public void onSent() {
				requestCounter.incrementAndGet();
			}

			@Override
			public void onResponse(Response response) {
				System.out.println();
				System.out.println("**** TEST: " + testName + " ****");

				// checking the response
				if (response != null) {
					int requests = requestCounter.get();
					// print response info
					if (verbose) {
						System.out.println("Response received");
						System.out.println("Time elapsed (ms): " + response.getRTT());
						if (requests > 1) {
							System.out.println(requests + " blocks");
						}
						Utils.prettyPrint(response);
					}
					if (response.getOptions().hasBlock1()) {
						requests -= response.getOptions().getBlock1().getNum();
					}
					if ((requests > 1) && !response.getOptions().hasBlock2()) {
						// set block2 option from counter
						// backwards compatibility (test only)
						int size = response.getPayloadSize() / requests;
						int bit = Integer.highestOneBit(size);
						if ((size - bit) != 0) {
							bit <<= 1;
						}
						response.getOptions().setBlock2(BlockOption.size2Szx(bit), false, requests - 1);
					}

					System.out.println("**** BEGIN CHECK ****");

					if (checkResponse(request, response)) {
						System.out.println("**** TEST PASSED ****");
						addSummaryEntry(testName + ": PASSED");
					} else {
						System.out.println("**** TEST FAILED ****");
						addSummaryEntry(testName + ": --FAILED--");
					}

					tickOffTest();
				}
			}
		}

		/**
		 * Notification listener forwarding notifies as response. Backwards
		 * compatibility to 1.0.0 notification implementation.
		 */
		protected class TestNotificationListener implements NotificationListener {

			private Endpoint endpoint;

			public TestNotificationListener(Endpoint endpoint) {
				this.endpoint = endpoint;
			}

			@Override
			public void onNotification(Request request, Response response) {
				Request origin = observe;
				if (origin != null && origin.getToken().equals(response.getToken())) {
					synchronized (notification) {
						notification.set(response);
						notification.notify();
					}
				}
			}

			public void close() {
				Request origin = observe;
				if (origin != null && origin.isObserve()) {
					Request cancel = Request.newGet();
					cancel.setDestinationContext(origin.getDestinationContext());
					// use same Token
					cancel.setToken(origin.getToken());
					// copy options
					cancel.setOptions(origin.getOptions());
					// set Observe to cancel
					cancel.setObserveCancel();
					endpoint.sendRequest(cancel);
					try {
						cancel.waitForResponse(2000);
					} catch (InterruptedException e) {
					}
				}
				endpoint.cancelObservation(origin.getToken());
				endpoint.removeNotificationListener(this);
			}

		}

		/**
		 * Check response.
		 * 
		 * @param request the request
		 * @param response the response
		 * @return true, if successful
		 */
		protected abstract boolean checkResponse(Request request, Response response);

		/**
		 * Check int.
		 * 
		 * @param expected the expected
		 * @param actual the actual
		 * @param fieldName the field name
		 * @return true, if successful
		 */
		protected boolean checkInt(int expected, int actual, String fieldName) {
			boolean success = expected == actual;

			if (!success) {
				System.out.println("FAIL: Expected " + fieldName + ": " + expected + ", but was: " + actual);
			} else {
				System.out.println("PASS: Correct " + fieldName + String.format(" (%d)", actual));
			}

			return success;
		}

		/**
		 * Check int.
		 * 
		 * @param expected the expected
		 * @param actual the actual
		 * @param fieldName the field name
		 * @return true, if successful
		 */
		protected boolean checkInts(int[] expected, int actual, String fieldName) {
			boolean success = false;
			for (int i : expected) {
				if (i == actual) {
					success = true;
					break;
				}
			}

			if (!success) {
				System.out.println(
						"FAIL: Expected " + fieldName + ": " + Arrays.toString(expected) + ", but was: " + actual);
			} else {
				System.out.println("PASS: Correct " + fieldName + String.format(" (%d)", actual));
			}

			return success;
		}

		/**
		 * Check code.
		 * 
		 * @param expected the expected code
		 * @param actual the actual code
		 * @return true, if successful
		 */
		protected boolean checkCode(CoAP.ResponseCode expected, CoAP.ResponseCode actual) {
			boolean success = expected.equals(actual);

			if (!success) {
				System.out.println("FAIL: Expected code: " + expected + ", but was: " + actual);
			} else {
				System.out.println("PASS: Correct code: " + actual);
			}

			return success;
		}

		/**
		 * Check codes.
		 * 
		 * @param expected the expected codec
		 * @param actual the actual code
		 * @return true, if successful
		 */
		protected boolean checkCodes(CoAP.ResponseCode[] expected, CoAP.ResponseCode actual) {
			boolean success = false;
			for (CoAP.ResponseCode code : expected) {
				if (code.equals(actual)) {
					success = true;
					break;
				}
			}

			if (!success) {
				System.out.println("FAIL: Expected code: " + Arrays.toString(expected) + ", but was: " + actual);
			} else {
				System.out.println("PASS: Correct code: " + actual);
			}

			return success;
		}


		/**
		 * Check String.
		 * 
		 * @param expected the expected
		 * @param actual the actual
		 * @param fieldName the field name
		 * @return true, if successful
		 */
		protected boolean checkString(String expected, String actual, String fieldName) {
			boolean success = expected.equals(actual);

			if (!success) {
				System.out
						.println("FAIL: Expected " + fieldName + ": \"" + expected + "\", but was: \"" + actual + "\"");
			} else {
				System.out.println("PASS: Correct " + fieldName + " \"" + actual + "\"");
			}

			return success;
		}

		/**
		 * Check type.
		 * 
		 * @param expectedMessageType the expected message type
		 * @param actualMessageType the actual message type
		 * @return true, if successful
		 */
		protected boolean checkType(Type expectedMessageType, Type actualMessageType) {
			if (useTcp) {
				// TCP doesn't sue a message type!
				return true;
			}
			boolean success = expectedMessageType.equals(actualMessageType);

			if (!success) {
				System.out.printf("FAIL: Expected type %s, but was %s\n", expectedMessageType, actualMessageType);
			} else {
				System.out.printf("PASS: Correct type (%s)\n", actualMessageType.toString());
			}

			return success;
		}

		/**
		 * Check types.
		 * 
		 * @param expectedMessageTypes the expected message types
		 * @param actualMessageType the actual message type
		 * @return true, if successful
		 */
		protected boolean checkTypes(Type[] expectedMessageTypes, Type actualMessageType) {
			boolean success = false;
			for (Type messageType : expectedMessageTypes) {
				if (messageType.equals(actualMessageType)) {
					success = true;
					break;
				}
			}

			if (!success) {
				StringBuilder sb = new StringBuilder();
				for (Type messageType : expectedMessageTypes) {
					sb.append(", ").append(messageType);
				}
				sb.delete(0, 2); // delete the first ", "

				System.out.printf("FAIL: Expected type %s, but was %s\n", "[ " + sb.toString() + " ]",
						actualMessageType);
			} else {
				System.out.printf("PASS: Correct type (%s)\n", actualMessageType.toString());
			}

			return success;
		}

		/**
		 * Checks for Content-Type option.
		 * 
		 * @param response the response
		 * @return true, if successful
		 */
		protected boolean hasContentType(Response response) {
			boolean success = response.getOptions().hasContentFormat() || response.getPayloadSize() == 0
					|| !CoAP.ResponseCode.isSuccess(response.getCode());

			if (!success) {
				System.out.println("FAIL: Response without Content-Type");
			} else {
				System.out.printf("PASS: Content-Type (%s)\n",
						MediaTypeRegistry.toString(response.getOptions().getContentFormat()));
			}

			return success;
		}

		/**
		 * Checks for Location-Path option.
		 * 
		 * @param response the response
		 * @return true, if successful
		 */
		protected boolean hasLocation(Response response) {
			// boolean success =
			// response.hasOption(OptionNumberRegistry.LOCATION_PATH);
			boolean success = response.getOptions().getLocationPathCount() > 0;

			if (!success) {
				System.out.println("FAIL: Response without Location");
			} else {
				System.out.printf("PASS: Location (%s)\n", response.getOptions().getLocationPathString());
			}

			return success;
		}

		/**
		 * Checks for ETag option.
		 * 
		 * @param response the response
		 * @return true, if successful
		 */
		protected boolean hasEtag(Response response) {
			// boolean success = response.hasOption(OptionNumberRegistry.ETAG);
			boolean success = response.getOptions().getETagCount() > 0;

			if (!success) {
				System.out.println("FAIL: Response without Etag");
			} else {
				System.out.printf("PASS: Etag (%s)\n", Utils.toHexString(response.getOptions().getETags().get(0)));
			}

			return success;
		}

		/**
		 * Checks for not empty payload.
		 * 
		 * @param response the response
		 * @return true, if not empty payload
		 */
		protected boolean hasNonEmptyPalyoad(Response response) {
			boolean success = response.getPayloadSize() > 0;

			if (!success) {
				System.out.println("FAIL: Response with empty payload");
			} else {
				System.out.printf("PASS: Payload not empty \"%s\"\n", response.getPayloadString());
			}

			return success;
		}

		/**
		 * Checks for Max-Age option.
		 * 
		 * @param response the response
		 * @return true, if successful
		 */
		protected boolean hasMaxAge(Response response) {
			// boolean success =
			// response.hasOption(OptionNumberRegistry.MAX_AGE);
			boolean success = response.getOptions().hasMaxAge();

			if (!success) {
				System.out.println("FAIL: Response without Max-Age");
			} else {
				System.out.printf("PASS: Max-Age (%s)\n", response.getOptions().getMaxAge());
			}

			return success;
		}

		/**
		 * Checks for Location-Query option.
		 * 
		 * @param response the response
		 * @return true, if successful
		 */
		protected boolean hasLocationQuery(Response response) {
			// boolean success =
			// response.hasOption(OptionNumberRegistry.LOCATION_QUERY);
			boolean success = response.getOptions().getLocationQueryCount() > 0;

			if (!success) {
				System.out.println("FAIL: Response without Location-Query");
			} else {
				System.out.printf("PASS: Location-Query (%s)\n", response.getOptions().getLocationQueryString());
			}

			return success;
		}

		/**
		 * Checks for Token option.
		 * 
		 * @param response the response
		 * @return true, if successful
		 */
		protected boolean hasToken(Response response) {
			boolean success = response.getToken() != null;

			if (!success) {
				System.out.println("FAIL: Response without Token");
			} else {
				System.out.printf("PASS: Token (%s)\n", response.getTokenString());
			}

			return success;
		}

		/**
		 * Checks for absent Token option.
		 * 
		 * @param response the response
		 * @return true, if successful
		 */
		protected boolean hasNoToken(Response response) {
			boolean success = response.hasEmptyToken();

			if (!success) {
				System.out.println("FAIL: Expected no token but had " + response.getTokenString());
			} else {
				System.out.printf("PASS: No Token\n");
			}

			return success;
		}

		/**
		 * Checks for Observe option.
		 * 
		 * @param response the response
		 * @return true, if successful
		 */
		private boolean hasObserve(Response response, boolean invert) {
			// boolean success =
			// response.hasOption(OptionNumberRegistry.OBSERVE);
			boolean success = response.getOptions().hasObserve();

			// invert to check for not having the option
			success ^= invert;

			if (!success) {
				System.out.println("FAIL: Response without Observe");
			} else if (!invert) {
				System.out.printf("PASS: Observe (%d)\n",
						// response.getFirstOption(OptionNumberRegistry.OBSERVE).getIntValue());
						response.getOptions().getObserve());
			} else {
				System.out.println("PASS: No Observe");
			}

			return success;
		}

		protected boolean hasObserve(Response response) {
			return hasObserve(response, false);
		}

		protected boolean hasNoObserve(Response response) {
			return hasObserve(response, true);
		}

		protected boolean checkOption(Option expextedOption, Option actualOption) {
			// boolean success = actualOption!=null &&
			// expextedOption.getOptionNumber()==actualOption.getOptionNumber();
			boolean success = actualOption != null && expextedOption.getNumber() == actualOption.getNumber();

			if (!success) {
				System.out.printf("FAIL: Missing option nr %d\n", expextedOption.getNumber());
			} else {

				// raw value byte array can be different, although value is the
				// same
				success &= expextedOption.toString().equals(actualOption.toString());

				if (!success) {
					System.out.printf("FAIL: Expected %s, but was %s\n", expextedOption.toString(),
							actualOption.toString());
				} else {
					System.out.printf("PASS: Correct option (%s)\n", actualOption.toString());
				}
			}

			return success;
		}

		protected boolean checkOption(BlockOption expected, BlockOption actual, String optionName) {
			boolean success = expected == null ? actual == null : expected.equals(actual);

			if (!success) {
				System.out.println("FAIL: option " + optionName + ": expected " + expected + " but was " + actual);
			} else {
				System.out.println("PASS: Correct option " + actual);
			}

			return success;
		}

		protected boolean checkOption(byte[] expectedOption, byte[] actualOption, String optionName) {
			boolean success = Arrays.equals(expectedOption, actualOption);

			if (!success) {
				System.out.println("FAIL: Option " + optionName + ": expected " + Utils.toHexString(expectedOption)
						+ " but was " + Utils.toHexString(actualOption));
			} else {
				System.out.printf("PASS: Correct option %s\n", optionName);
			}

			return success;
		}

		protected boolean checkOption(List<String> expected, List<String> actual, String optionName) {
			// boolean success = expected.size() == actual.size();
			boolean success = expected.equals(actual);

			if (!success) {
				System.out.println("FAIL: Option " + optionName + ": expected " + expected + " but was " + actual);
			} else {
				System.out.printf("PASS: Correct option %s\n", optionName);
			}

			return success;
		}

		protected boolean checkOption(Integer expected, Integer actual, String optionName) {
			boolean success = expected == null ? actual == null : expected.equals(actual);

			if (!success) {
				System.out.println("FAIL: Option " + optionName + ": expected " + expected + " but was " + actual);
			} else {
				System.out.printf("PASS: Correct option %s\n", optionName);
			}

			return success;
		}

		protected boolean checkDifferentOption(Option expextedOption, Option actualOption) {
			// boolean success = actualOption!=null &&
			// expextedOption.getOptionNumber()==actualOption.getOptionNumber();
			boolean success = actualOption != null && expextedOption.getNumber() == actualOption.getNumber();

			if (!success) {
				System.out.printf("FAIL: Missing option nr %d\n", expextedOption.getNumber());
			} else {

				// raw value byte array can be different, although value is the
				// same
				success &= !expextedOption.toString().equals(actualOption.toString());

				if (!success) {
					System.out.printf("FAIL: Expected difference, but was %s\n", actualOption.toString());
				} else {
					System.out.printf("PASS: Expected not %s and was %s\n", expextedOption.toString(),
							actualOption.toString());
				}
			}

			return success;
		}

		protected boolean checkDifferentOption(byte[] expected, byte[] actual, String optionName) {
			boolean success = !Arrays.equals(expected, actual);

			if (!success) {
				System.out.println("FAIL: Option " + optionName + ": expected " + Utils.toHexString(expected)
						+ " but was " + Utils.toHexString(actual));
			} else {
				System.out.println("PASS: Correct option " + optionName);
			}

			return success;
		}

		/**
		 * Check token.
		 * 
		 * @param expectedToken the expected token
		 * @param actualToken the actual token
		 * @return true, if successful
		 */
		protected boolean checkToken(Token expectedToken, Token actualToken) {

			boolean success = true;

			if (expectedToken == null || expectedToken.isEmpty()) {

				success = actualToken == null || actualToken.isEmpty();

				if (!success) {
					System.out.printf("FAIL: Expected empty token, but was %s\n", actualToken.getAsString());
				} else {
					System.out.println("PASS: Correct empty token");
				}

				return success;

			} else {

				success = actualToken.length() <= 8;
				success &= actualToken.length() >= 1;

				// eval token length
				if (!success) {
					System.out.printf("FAIL: Expected token %s, but %s has illeagal length\n",
							expectedToken.getAsString(), actualToken.getAsString());
					return success;
				}

				success &= expectedToken.equals(actualToken);

				if (!success) {
					System.out.printf("FAIL: Expected token %s, but was %s\n", expectedToken.getAsString(),
							actualToken.getAsString());
				} else {
					System.out.printf("PASS: Correct token (%s)\n", actualToken.getAsString());
				}

				return success;
			}
		}

		protected boolean checkDiscovery(String expextedResource, String actualDiscovery) {
			return actualDiscovery.contains("<" + expextedResource + ">");
		}

		/**
		 * Check discovery.
		 * 
		 * @param expextedAttribute the resource attribute to filter
		 * @param actualDiscovery the reported Link Format
		 * @return true, if successful
		 */
		protected boolean checkDiscoveryAttributes(String expextedAttribute, String actualDiscovery) {

			if (actualDiscovery == "") {
				System.err.println("Empty Link Format, check manually");
				return false;
			}

			Resource res = LinkParser.parseTree(actualDiscovery);

			List<String> query = Arrays.asList(expextedAttribute);

			boolean success = true;

			for (Resource sub : res.getChildren()) {

				// goes to leaf resource -- necessary?
				while (sub.getChildren().size() > 0) {
					sub = sub.getChildren().iterator().next();
				}

				success &= LinkFormat.matches(sub, query);

				if (!success) {
					System.out.printf("FAIL: Expected %s, but was %s\n", expextedAttribute,
							LinkFormat.serializeResource(sub));
				}
			}

			if (success) {
				System.out.println("PASS: Correct Link Format filtering");
			}

			return success;
		}

	}


	private static boolean ping(String address) {
		try {
			Request request = new Request(null);
			request.setType(Type.CON);
			request.setToken(Token.EMPTY);
			request.setURI(address);

			System.out.println("++++++ Sending Ping ++++++");
			request.send().waitForResponse(5000);
			return request.isRejected();

		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
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
}
