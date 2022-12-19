/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.plugtests;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.WebLink;
import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.LinkFormat;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.coap.option.OptionDefinition;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EndpointContextTracer;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.observe.NotificationListener;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * Abstract class to support various test client implementations.
 */
public abstract class TestClientAbstract {

	private static final EndpointContextTracer ENDPOINT_CONTEXT_TRACER = new EndpointContextTracer() {
		@Override
		protected void onContextChanged(EndpointContext endpointContext) {
			System.out.println(Utils.prettyPrint(endpointContext));
		}
	};

	protected Report report = new Report();

	private Throwable sendError;
	protected Semaphore terminated = new Semaphore(0);

	/** The test name. */
	protected String testName = null;

	/** The verbose. */
	protected boolean verbose = true;

	/**
	 * Use synchronous or asynchronous requests. Sync recommended due to single
	 * threaded servers and slow resources.
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
	 * @see #waitForNotification(long)
	 * @see #startObserve(Request)
	 * @see #stopObservation()
	 */
	protected AtomicReference<Response> notification = new AtomicReference<Response>();

	/**
	 * Notification listener forwarding notifications to
	 * {@link #waitForNotification(long)}.
	 */
	protected TestNotificationListener listener;

	/**
	 * Instantiates a new test client abstract.
	 * 
	 * @param testName    the test name
	 * @param verbose     the verbose
	 * @param synchronous use synchronous or asynchronous requests
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
	 * 
	 * @param request request to start observation.
	 */
	protected void startObserve(Request request) {
		stopObservation();
		addContextObserver(request);
		Endpoint endpoint = EndpointManager.getEndpointManager().getDefaultEndpoint(request.getScheme());
		listener = new TestNotificationListener(endpoint);
		endpoint.addNotificationListener(listener);
		observe = request;
		request.send(endpoint);
	}

	/**
	 * Wait for notification.
	 * 
	 * @param timeout timeout in milliseconds
	 * @return response, or {@code null}, if no response is received within the
	 *         provided timeout.
	 * @throws IllegalStateException if the observation was not started calling
	 *                               {@link #startObserve(Request)}
	 * @throws InterruptedException  if thread was interrupted during wait.
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
	 * @param request     the request
	 * @param serverURI   the server uri
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

		addContextObserver(request);

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

	/**
	 * Add {@link #ENDPOINT_CONTEXT_TRACER} to request and set endpoint context, if
	 * not already available.
	 * 
	 * @param request request to add observer and set context
	 */
	protected static void addContextObserver(Request request) {
		EndpointContext context = ENDPOINT_CONTEXT_TRACER.getCurrentContext();
		if (context != null && request.getDestinationContext() == null) {
			request.setDestinationContext(context);
		}
		request.addMessageObserver(ENDPOINT_CONTEXT_TRACER);
	}

	public synchronized void addSummaryEntry(String entry) {
		report.addEntry(entry);
	}

	public Report getReport() {
		return report;
	}

	public void tickOffTest() {
		terminated.release();
	}

	public void waitForUntilTestHasTerminated() throws Throwable {
		try {
			terminated.acquire();
		} catch (Exception e) {
			e.printStackTrace();
		}
		if (sendError != null) {
			throw sendError;
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
		public void onSent(boolean retransmission) {
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
					System.out.println(
							"Time elapsed (ms): " + TimeUnit.NANOSECONDS.toMillis(response.getApplicationRttNanos()));
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

		@Override
		public void onSendError(Throwable error) {
			sendError = error;
			tickOffTest();
		}

		protected void failed() {
			tickOffTest();
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
			if (origin != null) {
				if (origin.isObserve()) {
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
			}
			endpoint.removeNotificationListener(this);
		}

	}

	/**
	 * Check response.
	 * 
	 * @param request  the request
	 * @param response the response
	 * @return true, if successful
	 */
	protected abstract boolean checkResponse(Request request, Response response);

	/**
	 * Check int.
	 * 
	 * @param expected  the expected
	 * @param actual    the actual
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
	 * @param expected  the expected
	 * @param actual    the actual
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
			System.out
					.println("FAIL: Expected " + fieldName + ": " + Arrays.toString(expected) + ", but was: " + actual);
		} else {
			System.out.println("PASS: Correct " + fieldName + String.format(" (%d)", actual));
		}

		return success;
	}

	/**
	 * Check code.
	 * 
	 * @param expected the expected code
	 * @param actual   the actual code
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
	 * @param actual   the actual code
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
	 * @param expected  the expected
	 * @param actual    the actual
	 * @param fieldName the field name
	 * @return true, if successful
	 */
	protected boolean checkString(String expected, String actual, String fieldName) {
		boolean success = expected.equals(actual);

		if (!success) {
			System.out.println("FAIL: Expected " + fieldName + ": \"" + expected + "\", but was: \"" + actual + "\"");
		} else {
			System.out.println("PASS: Correct " + fieldName + " \"" + actual + "\"");
		}

		return success;
	}

	/**
	 * Check type.
	 * 
	 * @param expectedMessageType the expected message type
	 * @param actualMessageType   the actual message type
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
	 * @param actualMessageType    the actual message type
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

			System.out.printf("FAIL: Expected type %s, but was %s\n", "[ " + sb.toString() + " ]", actualMessageType);
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
				|| !response.isSuccess();

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
	protected boolean hasNonEmptyPayload(Response response) {
		boolean success = response.getPayloadSize() > 0;
		boolean print = MediaTypeRegistry.isPrintable(response.getOptions().getContentFormat());

		if (!success) {
			System.out.println("FAIL: Response with empty payload");
		} else if (print) {
			String payload = response.getPayloadString();
			if (payload.length() < 50) {
				System.out.printf("PASS: Payload not empty \"%s\"%n", response.getPayloadString());
			} else {
				System.out.printf("PASS: Payload not empty%n%s%n", response.getPayloadString());
			}
		} else {
			System.out.printf("PASS: Payload not empty%n0x%s%n", StringUtil.byteArray2Hex(response.getPayload()));
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

	protected boolean hasObserve(Response response) {
		return hasOption(response, StandardOptionRegistry.OBSERVE, false);
	}

	protected boolean hasNoObserve(Response response) {
		return hasOption(response, StandardOptionRegistry.OBSERVE, true);
	}

	@Deprecated
	protected boolean hasOption(Response response, int optionNumber, boolean invert) {
		String name = OptionNumberRegistry.toString(optionNumber);
		List<Option> asSortedList = response.getOptions().asSortedList();
		Option match = null;
		for (Option option : asSortedList) {
			if (option.getNumber() == optionNumber) {
				match = option;
				break;
			}
		}
		// invert to check for not having the option
		boolean success = match != null ^ invert;

		StringBuilder result = new StringBuilder();
		if (success) {
			result.append("PASS: Response ");
		} else {
			result.append("FAIL: Response ");
		}
		if (match != null) {
			result.append("with ");
			result.append(name);
		} else {
			result.append("without ").append(name);
		}
		System.out.println(result);

		return success;
	}

	protected boolean hasOption(Response response, OptionDefinition optionDefintion, boolean invert) {
		String name = optionDefintion.getName();
		List<Option> asSortedList = response.getOptions().asSortedList();
		Option match = null;
		for (Option option : asSortedList) {
			if (optionDefintion.equals(option.getDefinition())) {
				match = option;
				break;
			}
		}
		// invert to check for not having the option
		boolean success = match != null ^ invert;

		StringBuilder result = new StringBuilder();
		if (success) {
			result.append("PASS: Response ");
		} else {
			result.append("FAIL: Response ");
		}
		if (match != null) {
			result.append("with ");
			result.append(name);
		} else {
			result.append("without ").append(name);
		}
		System.out.println(result);

		return success;
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
			System.out.println("FAIL: Option " + optionName + ": expected " + Utils.toHexString(expected) + " but was "
					+ Utils.toHexString(actual));
		} else {
			System.out.println("PASS: Correct option " + optionName);
		}

		return success;
	}

	/**
	 * Check token.
	 * 
	 * @param expectedToken the expected token
	 * @param actualToken   the actual token
	 * @return true, if successful
	 */
	protected boolean checkToken(Token expectedToken, Token actualToken) {

		if (expectedToken == null) {
			expectedToken = Token.EMPTY;
		}
		if (actualToken == null) {
			actualToken = Token.EMPTY;
		}
		if (expectedToken.isEmpty()) {
			if (actualToken.isEmpty()) {
				System.out.println("PASS: Correct empty token");
			} else {
				System.out.printf("FAIL: Expected empty token, but was %s\n", actualToken.getAsString());
				return false;
			}
		} else {

			if (actualToken.length() < 1 || actualToken.length() > 8) {
				System.out.printf("FAIL: Expected token %s, but %s has illeagal length\n", expectedToken.getAsString(),
						actualToken.getAsString());
				return false;
			}

			if (expectedToken.equals(actualToken)) {
				System.out.printf("PASS: Correct token (%s)\n", actualToken.getAsString());
			} else {
				System.out.printf("FAIL: Expected token %s, but was %s\n", expectedToken.getAsString(),
						actualToken.getAsString());
				return false;
			}
		}
		return true;
	}

	protected boolean checkDiscovery(String expextedResource, String actualDiscovery) {
		return actualDiscovery.contains("<" + expextedResource + ">");
	}

	/**
	 * Check discovery.
	 * 
	 * @param expextedAttribute the resource attribute to filter
	 * @param actualDiscovery   the reported Link Format
	 * @return true, if successful
	 */
	protected boolean checkDiscoveryAttributes(String expextedAttribute, String actualDiscovery) {

		if (actualDiscovery == "") {
			System.err.println("Empty Link Format, check manually");
			return false;
		}

		Set<WebLink> links = LinkFormat.parse(actualDiscovery);

		List<String> query = Arrays.asList(expextedAttribute);

		boolean success = true;

		for (WebLink link : links) {

			success &= LinkFormat.matches(link, query);

			if (!success) {
				System.out.printf("FAIL: Expected %s, but was %s\n", expextedAttribute, link);
			}
		}

		if (success) {
			System.out.println("PASS: Correct Link Format filtering");
		}

		return success;
	}

}