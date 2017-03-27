/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - test stop transfer on cancel
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CoapNetworkRule for
 *                                                    setup of test-network
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.eclipse.californium.TestTools.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.test.lockstep.ServerBlockwiseInterceptor;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * This test tests the blockwise transfer of requests and responses. This test
 * sets the maximum message size and the default block size to 32 bytes and
 * sends messages blockwise. All four combinations with short and long requests
 * and responses are tested.
 */
// Category Medium because shutdown of the CoapServer runs into timeout (after 1 sec)
// because of pending BlockCleanupTask
@Category(Medium.class)
public class BlockwiseTransferTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	private static final String PARAM_SHORT_RESP = "srr";
	private static final String PARAM_SHORT_REQ = "sr";
	private static final String RESOURCE_TEST = "test";
	private static final String RESOURCE_BIG = "big";

	private static final String SHORT_POST_REQUEST  = generateRandomPayload(15);
	private static final String LONG_POST_REQUEST   = generateRandomPayload(150);
	private static final String SHORT_POST_RESPONSE = generateRandomPayload(16);
	private static final String LONG_POST_RESPONSE  = generateRandomPayload(151);
	private static final String SHORT_GET_RESPONSE = generateRandomPayload(17);
	private static final String LONG_GET_RESPONSE  = generateRandomPayload(152);
	private static final String OVERSIZE_BODY = generateRandomPayload(510);

	private static CoapServer server;
	private static NetworkConfig config;
	private static Endpoint serverEndpoint;
	private static ServerBlockwiseInterceptor interceptor = new ServerBlockwiseInterceptor();

	private Endpoint clientEndpoint;

	@BeforeClass
	public static void prepare() {
		System.out.println(System.lineSeparator() + "Start " + BlockwiseTransferTest.class.getSimpleName());
		config = network.getStandardTestConfig()
			.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 32)
			.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 32)
			.setInt(NetworkConfig.Keys.MAX_RESOURCE_BODY_SIZE, 500);
		server = createSimpleServer();
	}

	@Before
	public void createClient() throws IOException {

		clientEndpoint = new CoapEndpoint(config);
		clientEndpoint.start();
	}

	@After
	public void destroyClient() throws Exception {
		clientEndpoint.destroy();
	}

	@AfterClass
	public static void shutdownServer() throws Exception {
		server.destroy();
		System.out.println("End " + BlockwiseTransferTest.class.getSimpleName());
	}

	@Test
	public void test_POST_short_short() throws Exception {
		System.out.println("-- POST short short --");
		executePOSTRequest(true, true);
	}

	@Test
	public void test_POST_long_short() throws Exception {
		System.out.println("-- POST long short --");
		executePOSTRequest(false, true);
	}

	@Test
	public void test_POST_short_long() throws Exception {
		System.out.println("-- POST short long --");
		executePOSTRequest(true, false);
	}

	@Test
	public void test_POST_long_long() throws Exception {
		System.out.println("-- POST long long --");
		executePOSTRequest(false, false);
		// repeat test to check ongoing clean-up
		executePOSTRequest(false, false);
	}

	@Test
	public void test_GET_short() throws Exception {
		System.out.println("-- GET short --");
		executeGETRequest(true);
	}

	@Test
	public void test_GET_long() throws Exception {
		System.out.println("-- GET long --");
		executeGETRequest(false);
		// repeat test to check ongoing clean-up
		executeGETRequest(false);
	}

	@Test
	public void test_GET_long_cancel() throws Exception {
		System.out.println("-- GET long, cancel --");
		executeGETRequest(false, true);
	}

	@Test
	public void testRequestForOversizedBodyGetsCanceled() throws InterruptedException {

		final CountDownLatch latch = new CountDownLatch(1);

		Request req = Request.newGet().setURI(getUri(serverEndpoint, RESOURCE_BIG));
		req.addMessageObserver(new MessageObserverAdapter() {

			@Override
			public void onCancel() {
				latch.countDown();
			}
		});
		clientEndpoint.sendRequest(req);
		assertTrue(latch.await(1000, TimeUnit.MILLISECONDS));
	}

	private void executeGETRequest(final boolean respondShort) throws Exception {
		executeGETRequest(respondShort, false);
	}

	private void executeGETRequest(final boolean respondShort, final boolean cancelRequest) throws Exception {
		String payload = "nothing";
		try {
			interceptor.clear();
			final AtomicInteger counter = new AtomicInteger(0);
			final Request request = Request.newGet();
			request.setURI(getUri(serverEndpoint, RESOURCE_TEST));
			if (respondShort) {
				request.getOptions().addUriQuery(PARAM_SHORT_RESP);
			}
			interceptor.handler = new ReceiveRequestHandler() {
				@Override
				public void receiveRequest(Request received) {
					counter.getAndIncrement();
					if (cancelRequest) {
						request.cancel();
					}
				}
			};

			clientEndpoint.sendRequest(request);

			// receive response and check
			Response response = request.waitForResponse(2000);

			if (cancelRequest) {
				Thread.sleep(1000); // Quickly wait for more blocks (should not happen)
				assertEquals(1, counter.get());
			} else {
				assertNotNull("Client received no response", response);
				payload = response.getPayloadString();
				if (respondShort) {
					assertEquals(SHORT_GET_RESPONSE, payload);
				} else {
					assertEquals(LONG_GET_RESPONSE, payload);
				}
			}
		} finally {
			Thread.sleep(100); // Quickly wait until last ACKs arrive
			System.out.println("Client received payload [" + payload + "]" + System.lineSeparator()
				+ interceptor.toString() + System.lineSeparator());
		}
	}

	private void executePOSTRequest(final boolean shortRequest, final boolean respondShort) throws Exception {
		String payload = "--no payload--";
		try {
			interceptor.clear();
			Request request = Request.newPost().setURI(getUri(serverEndpoint, RESOURCE_TEST));
			if (shortRequest) {
				request.setPayload(SHORT_POST_REQUEST);
				request.getOptions().addUriQuery(PARAM_SHORT_REQ);
			} else {
				request.setPayload(LONG_POST_REQUEST);
			}
			if (respondShort) {
				request.getOptions().addUriQuery(PARAM_SHORT_RESP);
			}
			clientEndpoint.sendRequest(request);

			// receive response and check
			Response response = request.waitForResponse(2000);

			assertNotNull("Client received no response", response);
			payload = response.getPayloadString();

			if (respondShort) {
				assertEquals(SHORT_POST_RESPONSE, payload);
			} else {
				assertEquals(LONG_POST_RESPONSE, payload);
			}
		} finally {
			Thread.sleep(100); // Quickly wait until last ACKs arrive
			System.out.println("Client received payload [" + payload + "]" + System.lineSeparator()
				+ interceptor.toString() + System.lineSeparator());
		}
	}

	private static CoapServer createSimpleServer() {

		CoapServer result = new CoapServer();

		serverEndpoint = new CoapEndpoint(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), config);
		serverEndpoint.addInterceptor(interceptor);
		result.addEndpoint(serverEndpoint);
		result.add(new CoapResource(RESOURCE_TEST) {

			private boolean isShortRequest(final CoapExchange exchange) {
				return exchange.getQueryParameter(PARAM_SHORT_REQ) != null;
			}

			private boolean isShortResponseRequested(final CoapExchange exchange) {
				return exchange.getQueryParameter(PARAM_SHORT_RESP) != null;
			}

			@Override
			public void handleGET(final CoapExchange exchange) {
				System.out.println("Server received GET request");
				if (isShortResponseRequested(exchange)) {
					exchange.respond(SHORT_GET_RESPONSE);
				} else {
					exchange.respond(LONG_GET_RESPONSE);
				}
			}

			@Override
			public void handlePOST(final CoapExchange exchange) {
				String payload = exchange.getRequestText();
				System.out.println("Server received " + payload);
				if (isShortRequest(exchange)) {
					assertEquals(payload, SHORT_POST_REQUEST);
				} else {
					assertEquals(payload, LONG_POST_REQUEST);
				}

				if (isShortResponseRequested(exchange)) {
					exchange.respond(SHORT_POST_RESPONSE);
				} else {
					exchange.respond(LONG_POST_RESPONSE);
				}
			}
		});
		result.add(new CoapResource(RESOURCE_BIG) {

			@Override
			public void handleGET(final CoapExchange exchange) {
				exchange.respond(OVERSIZE_BODY);
			}
		});

		result.start();
		System.out.println("serverPort: " + serverEndpoint.getAddress().getPort());
		return result;
	}

	public interface ReceiveRequestHandler {
		void receiveRequest(Request received);
	}
}
