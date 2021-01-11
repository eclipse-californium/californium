/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - test stop transfer on cancel
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CoapNetworkRule for
 *                                                    setup of test-network
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.eclipse.californium.TestTools.LOCALHOST_EPHEMERAL;
import static org.eclipse.californium.TestTools.generateRandomPayload;
import static org.eclipse.californium.TestTools.getUri;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.test.lockstep.ServerBlockwiseInterceptor;
import org.eclipse.californium.core.test.lockstep.ServerBlockwiseInterceptor.ReceiveRequestHandler;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
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

	@ClassRule
	public static CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final String PARAM_SHORT_RESP = "srr";
	private static final String PARAM_EMPTY_RESP = "empty";
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
	private static NetworkConfig configEndpointStrictBlock2Option;

	private static Endpoint serverEndpoint;
	private static Endpoint serverEndpointStrictBlock2Option;

	private static ServerBlockwiseInterceptor interceptor = new ServerBlockwiseInterceptor();

	private static NetworkConfig configEndpointWithoutTransparentBlockwise;
	
	private Endpoint clientEndpoint;
	
	private Endpoint clientEndpointWithoutTransparentBlockwise;
	
	private static AtomicInteger applicationLayerGetRequestCount = new AtomicInteger(0);

	@BeforeClass
	public static void prepare() {
		config = network.getStandardTestConfig()
				.setInt(Keys.PREFERRED_BLOCK_SIZE, 32)
				.setInt(Keys.MAX_MESSAGE_SIZE, 32)
				.setInt(Keys.MAX_RESOURCE_BODY_SIZE, 500)
				.setBoolean(Keys.BLOCKWISE_STRICT_BLOCK2_OPTION, false);
		
		configEndpointStrictBlock2Option = network.createTestConfig()
				.setInt(Keys.PREFERRED_BLOCK_SIZE, 32)
				.setInt(Keys.MAX_MESSAGE_SIZE, 32)
				.setInt(Keys.MAX_RESOURCE_BODY_SIZE, 500)
				.setBoolean(Keys.BLOCKWISE_STRICT_BLOCK2_OPTION, true);
		
		
		configEndpointWithoutTransparentBlockwise = network.createTestConfig()
			.setInt(Keys.PREFERRED_BLOCK_SIZE, 32)
			.setInt(Keys.MAX_MESSAGE_SIZE, 32)
			.setInt(Keys.MAX_RESOURCE_BODY_SIZE, 0)
			.setBoolean(Keys.BLOCKWISE_STRICT_BLOCK2_OPTION, true);
		
		server = createSimpleServer();
		cleanup.add(server);
	}

	@Before
	public void createClients() throws IOException {

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setNetworkConfig(config);
		clientEndpoint = builder.build();
		clientEndpoint.start();

		CoapEndpoint.Builder builderBis = new CoapEndpoint.Builder();
		builderBis.setNetworkConfig(configEndpointWithoutTransparentBlockwise);
		clientEndpointWithoutTransparentBlockwise = builderBis.build();
		clientEndpointWithoutTransparentBlockwise.start();		
	}

	@After
	public void destroyClient() throws Exception {
		clientEndpoint.destroy();
		clientEndpointWithoutTransparentBlockwise.destroy();
		applicationLayerGetRequestCount.set(0);
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
		executeGETRequest(false, true, false);

	}
	@Test
	public void test_GETlong_M1() throws Exception {
		System.out.println("-- GET long, accidently set M to 1 --");
		executeGETRequest(false, false, true);
	}

	@Test
	public void testRequestForOversizedBodyGetsCanceled() throws InterruptedException {
		CountingMessageObserver observer = new CountingMessageObserver();
		Request req = Request.newGet().setURI(getUri(serverEndpoint, RESOURCE_BIG));
		req.addMessageObserver(observer);
		clientEndpoint.sendRequest(req);
		assertTrue(observer.waitForCancelCalls(1, 1000, TimeUnit.MILLISECONDS));
	}
	
	/**
	 * Send request to the server with early blockwise negotiation through block2 option. The response content should fits into a single response.
	 * <p>The targeted endpoint has the {@link NetworkConfig.Keys#BLOCKWISE_STRICT_BLOCK2_OPTION} set to true and should respond with a block2 option indicating that no more blocks are available. </p>
	 * 
	 * @throws InterruptedException
	 */
	@Test
	public void testEarlyNegotiationWithStrictBlock2() throws InterruptedException {
		
		testGetRequestWithEarlyNegotiation(true, PARAM_SHORT_RESP);
	}
	
	/**
	 * Send request to the server with early blockwise negotiation through block2 option. The response content should fits into a single response.
	 * <p>The targeted endpoint has the {@link NetworkConfig.Keys#BLOCKWISE_STRICT_BLOCK2_OPTION} set to false and should respond without a block2 option. </p>
	 * 
	 * @throws InterruptedException
	 */
	@Test
	public void testEarlyNegotiationWithoutStrictBlock2() throws InterruptedException {
	
		testGetRequestWithEarlyNegotiation(false, PARAM_SHORT_RESP);
	}
	
	/**
	 * Send request to the server with early blockwise negotiation through block2 option. The response content should be empty and contains the block2 option.
	 * <p>The targeted endpoint has the {@link NetworkConfig.Keys#BLOCKWISE_STRICT_BLOCK2_OPTION} set to true and should respond with a block2 option. </p>
	 * 
	 * @throws InterruptedException
	 */
	@Test
	public void testEarlyNegotiationWithStrictBlock2NoResponsePayload() throws InterruptedException {
	
		testGetRequestWithEarlyNegotiation(true, PARAM_EMPTY_RESP);
	}
	
	
	/**
	 * Test that consecutive requests to a same resource with early blockwise negotiation are both going through the application layer
	 * @throws InterruptedException
	 */
	@Test
	public void testMultipleEarlyNegotiationWithShortInterval() throws InterruptedException {
		testGetRequestWithEarlyNegotiation(false, PARAM_SHORT_RESP);
		testGetRequestWithEarlyNegotiation(false, PARAM_SHORT_RESP);
		
		assertEquals("Application layer did not receive two requests", 2, applicationLayerGetRequestCount.get());
	}
	
	private void testGetRequestWithEarlyNegotiation(final boolean strictBlock2, String uriQueryResponseType) throws InterruptedException {

		final Endpoint targetEndpoint = strictBlock2 ? serverEndpointStrictBlock2Option : serverEndpoint;
		CountingMessageObserver observer = new CountingMessageObserver();
		Request req = Request.newGet().setURI(getUri(targetEndpoint, RESOURCE_TEST));
		req.getOptions().addUriQuery(uriQueryResponseType);
		req.getOptions().setBlock2(BlockOption.size2Szx(256), false, 0);

		req.addMessageObserver(observer);
		clientEndpointWithoutTransparentBlockwise.sendRequest(req);

		// receive response and check
		Response response = req.waitForResponse(1000);
		
		//ensure there is a response from the server
		assertNotNull("No response received", response);
		
		BlockOption block2 = response.getOptions().getBlock2();

		if (strictBlock2) {
			assertNotNull(block2);
			assertEquals("Block2 option should indicate that all blocks have been transfered", false, block2.isM());
		} else {
			assertNull(block2);
		}
		// 2 calls should not be reached!
		observer.waitForLoadCalls(2, 1000, TimeUnit.MILLISECONDS);
		assertEquals("Not exactly one block received", 1, observer.loadCalls.get());
	}

	private void executeGETRequest(final boolean respondShort) throws Exception {
		executeGETRequest(respondShort, false, false);
	}

	private void executeGETRequest(final boolean respondShort, final boolean cancelRequest, final boolean m) throws Exception {
		String payload = "nothing";
		try {
			interceptor.clear();
			final AtomicInteger counter = new AtomicInteger(0);
			final Request request = Request.newGet();
			String uri = getUri(serverEndpoint, RESOURCE_TEST);
			System.out.println(uri);
			request.setURI(uri);
			if (m) {
				// set BLOCK 2 with wrong m
				request.getOptions().setBlock2(2, m, 0);
			}
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

		CoapServer result = new CoapServer(config);

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(LOCALHOST_EPHEMERAL);
		builder.setNetworkConfig(config);

		serverEndpoint = builder.build();
		serverEndpoint.addInterceptor(interceptor);
		result.addEndpoint(serverEndpoint);
		
		//add another endpoint which purpose is to test the NetworkConfig.Keys.BLOCKWISE_STRICT_BLOCK2_OPTION
		CoapEndpoint.Builder builderStrictBlock2 = new CoapEndpoint.Builder();

		builderStrictBlock2.setInetSocketAddress(LOCALHOST_EPHEMERAL);
		builderStrictBlock2.setNetworkConfig(configEndpointStrictBlock2Option);
		serverEndpointStrictBlock2Option = builderStrictBlock2.build();
		result.addEndpoint(serverEndpointStrictBlock2Option);
		
		result.add(new CoapResource(RESOURCE_TEST) {

			private boolean isShortRequest(final CoapExchange exchange) {
				return exchange.getQueryParameter(PARAM_SHORT_REQ) != null;
			}

			private boolean isShortResponseRequested(final CoapExchange exchange) {
				return exchange.getQueryParameter(PARAM_SHORT_RESP) != null;
			}
			
			private boolean isEmptyResponseRequested(final CoapExchange exchange) {
				return exchange.getQueryParameter(PARAM_EMPTY_RESP) != null;
			}

			@Override
			public void handleGET(final CoapExchange exchange) {
				System.out.println("Server received GET request");
				applicationLayerGetRequestCount.incrementAndGet();
				if (isShortResponseRequested(exchange)) {
					
					exchange.respond(SHORT_GET_RESPONSE);
				} else if (isEmptyResponseRequested(exchange)){
					
					exchange.respond(ResponseCode.CONTENT);
				}else {
					
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

}
