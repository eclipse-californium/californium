/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - derived from DatagramReader
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.eclipse.californium.TestTools.LOCALHOST_EPHEMERAL;
import static org.eclipse.californium.TestTools.generateRandomPayload;
import static org.eclipse.californium.TestTools.getUri;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.test.lockstep.ServerBlockwiseInterceptor;
import org.eclipse.californium.core.test.lockstep.ServerBlockwiseInterceptor.ReceiveRequestHandler;
import org.eclipse.californium.elements.UDPConnector;
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
 * This test tests the BERT blockwise transfer of requests and responses. Uses a
 * UDP Connector which fakes TCP. Otherwise a "test-only" dependency to
 * element-connector-tcp-netty would have been required or a "pure-jdk"
 * tcp-connector implementation.
 */
// Category Medium because shutdown of the CoapServer runs into timeout (after 1
// sec)
// because of pending BlockCleanupTask
@Category(Medium.class)
public class BlockwiseBertTransferTest {

	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	@ClassRule
	public static CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final String RESOURCE_TEST = "test";
	private static final String RESOURCE_BIG = "big";

	private static final String LONG_POST_REQUEST = generateRandomPayload(2600);
	private static final String LONG_POST_RESPONSE = generateRandomPayload(4200);
	private static final String LONG_GET_RESPONSE = generateRandomPayload(6000);
	private static final String OVERSIZE_BODY = generateRandomPayload(16000);

	private static CoapServer server;
	private static NetworkConfig config;

	private static Endpoint serverEndpoint;

	private static ServerBlockwiseInterceptor interceptor = new ServerBlockwiseInterceptor();

	private Endpoint clientEndpoint;

	private static AtomicInteger applicationLayerGetRequestCount = new AtomicInteger(0);

	@BeforeClass
	public static void prepare() {
		config = network.getStandardTestConfig()
				.setInt(Keys.UDP_CONNECTOR_DATAGRAM_SIZE, 3000)
				.setInt(Keys.PREFERRED_BLOCK_SIZE, 1024)
				.setInt(Keys.MAX_MESSAGE_SIZE, 1024)
				.setInt(Keys.TCP_NUMBER_OF_BULK_BLOCKS, 2)
				.setInt(Keys.MAX_RESOURCE_BODY_SIZE, 8192);

		server = createSimpleServer();
		cleanup.add(server);
	}

	@Before
	public void createClients() throws IOException {

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setNetworkConfig(config);
		builder.setConnectorWithAutoConfiguration(new UDPConnector(LOCALHOST_EPHEMERAL) {

			@Override
			public String getProtocol() {
				return "TCP";
			}
		});

		clientEndpoint = builder.build();
		clientEndpoint.start();

	}

	@After
	public void destroyClient() throws Exception {
		clientEndpoint.destroy();
		applicationLayerGetRequestCount.set(0);
	}

	@Test
	public void test_POST_long_long() throws Exception {
		System.out.println("-- POST long long --");
		executePOSTRequest();
		// repeat test to check ongoing clean-up
		executePOSTRequest();
	}

	@Test
	public void test_GET_long() throws Exception {
		System.out.println("-- GET long --");
		executeGETRequest();
		// repeat test to check ongoing clean-up
		executeGETRequest();
	}

	@Test
	public void test_GET_long_cancel() throws Exception {
		System.out.println("-- GET long, cancel --");
		executeGETRequest(true, false);

	}

	@Test
	public void test_GET_long_M1() throws Exception {
		System.out.println("-- GET long, accidently set M to 1 --");
		executeGETRequest(false, true);
	}

	@Test
	public void testRequestForOversizedBodyGetsCanceled() throws InterruptedException {
		CountingMessageObserver observer = new CountingMessageObserver();
		Request req = Request.newGet().setURI(getUri(serverEndpoint, RESOURCE_BIG));
		req.addMessageObserver(observer);
		clientEndpoint.sendRequest(req);
		assertTrue(observer.waitForCancelCalls(1, 1000, TimeUnit.MILLISECONDS));
	}

	private void executeGETRequest() throws Exception {
		executeGETRequest(false, false);
	}

	private void executeGETRequest(final boolean cancelRequest, final boolean m) throws Exception {
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
				request.getOptions().setBlock2(BlockOption.BERT_SZX, m, 0);
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
				// Quickly wait for more blocks (should not happen)
				Thread.sleep(1000);
				assertEquals(1, counter.get());
			} else {
				assertNotNull("Client received no response", response);
				payload = response.getPayloadString();
				assertEquals(LONG_GET_RESPONSE, payload);
				assertEquals(getBertBlocks(LONG_GET_RESPONSE), counter.get());
			}
		} finally {
			Thread.sleep(100); // Quickly wait until last ACKs arrive
			System.out.println("Client received payload [" + payload + "]" + System.lineSeparator()
					+ interceptor.toString() + System.lineSeparator());
		}
	}

	private void executePOSTRequest() throws Exception {
		String payload = "--no payload--";
		try {
			interceptor.clear();
			final AtomicInteger counter = new AtomicInteger(0);
			Request request = Request.newPost().setURI(getUri(serverEndpoint, RESOURCE_TEST));
			request.setPayload(LONG_POST_REQUEST);

			interceptor.handler = new ReceiveRequestHandler() {

				@Override
				public void receiveRequest(Request received) {
					counter.getAndIncrement();
				}
			};

			clientEndpoint.sendRequest(request);

			// receive response and check
			Response response = request.waitForResponse(2000);

			assertNotNull("Client received no response", response);
			payload = response.getPayloadString();

			assertEquals(LONG_POST_RESPONSE, payload);
			assertEquals(getBertBlocks(LONG_POST_REQUEST) + getBertBlocks(LONG_POST_RESPONSE) - 1, counter.get());
		} finally {
			Thread.sleep(100); // Quickly wait until last ACKs arrive
			System.out.println("Client received payload [" + payload + "]" + System.lineSeparator()
					+ interceptor.toString() + System.lineSeparator());
		}
	}

	private static CoapServer createSimpleServer() {

		CoapServer result = new CoapServer(config);

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setNetworkConfig(config);
		builder.setConnectorWithAutoConfiguration(new UDPConnector(LOCALHOST_EPHEMERAL) {

			@Override
			public String getProtocol() {
				return "TCP";
			}
		});

		serverEndpoint = builder.build();
		serverEndpoint.addInterceptor(interceptor);
		result.addEndpoint(serverEndpoint);

		result.add(new CoapResource(RESOURCE_TEST) {

			@Override
			public void handleGET(final CoapExchange exchange) {
				System.out.println("Server received GET request");
				applicationLayerGetRequestCount.incrementAndGet();
				exchange.respond(LONG_GET_RESPONSE);
			}

			@Override
			public void handlePOST(final CoapExchange exchange) {
				String payload = exchange.getRequestText();
				System.out.println("Server received " + payload);
				assertEquals(payload, LONG_POST_REQUEST);
				exchange.respond(LONG_POST_RESPONSE);
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

	private static int getBertBlocks(String payload) {
		int bulk = config.getInt(Keys.TCP_NUMBER_OF_BULK_BLOCKS);
		int bulkSize = 1024 * bulk;
		return (payload.length() + bulkSize - 1) / bulkSize;
	}
}
