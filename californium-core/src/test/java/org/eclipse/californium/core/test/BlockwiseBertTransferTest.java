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
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.printServerLog;
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
import org.eclipse.californium.core.coap.TestResource;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.test.lockstep.ServerBlockwiseInterceptor;
import org.eclipse.californium.core.test.lockstep.ServerBlockwiseInterceptor.ReceiveRequestHandler;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.UdpConfig;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
	private static final Logger LOGGER = LoggerFactory.getLogger(BlockwiseBertTransferTest.class);

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
	private static Configuration config;

	private static Endpoint serverEndpoint;

	private static ServerBlockwiseInterceptor interceptor = new ServerBlockwiseInterceptor();

	private Endpoint clientEndpoint;

	private static AtomicInteger applicationLayerGetRequestCount = new AtomicInteger(0);

	@BeforeClass
	public static void prepare() {
		config = network.getStandardTestConfig()
				.set(UdpConfig.UDP_DATAGRAM_SIZE, 3000)
				.set(CoapConfig.PREFERRED_BLOCK_SIZE, 1024)
				.set(CoapConfig.MAX_MESSAGE_SIZE, 1024)
				.set(CoapConfig.TCP_NUMBER_OF_BULK_BLOCKS, 2)
				.set(CoapConfig.MAX_RESOURCE_BODY_SIZE, 8192);

		server = createSimpleServer();
		cleanup.add(server);
	}

	@Before
	public void createClients() throws IOException {

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setConfiguration(config);
		builder.setConnector(new UDPConnector(LOCALHOST_EPHEMERAL, config) {

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
		executePOSTRequest();
		// repeat test to check ongoing clean-up
		executePOSTRequest();
	}

	@Test
	public void test_GET_long() throws Exception {
		executeGETRequest();
		// repeat test to check ongoing clean-up
		executeGETRequest();
	}

	@Test
	public void test_GET_long_cancel() throws Exception {
		executeGETRequest(true, false);

	}

	@Test
	public void test_GET_long_M1() throws Exception {
		executeGETRequest(false, true);
	}

	@Test
	public void testRequestForOversizedBodyGetsCanceled() throws InterruptedException {
		CountingMessageObserver observer = new CountingMessageObserver();
		Request req = Request.newGet().setURI(getUri(serverEndpoint, RESOURCE_BIG));
		req.addMessageObserver(observer);
		clientEndpoint.sendRequest(req);
		assertTrue(observer.waitForResponseErrorCalls(1, 1000, TimeUnit.MILLISECONDS));
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
			LOGGER.info("{}", uri);
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
			LOGGER.info("Client received payload [{}]", payload);
			printServerLog(interceptor);
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
			LOGGER.info("Client received payload [{}]", payload);
			printServerLog(interceptor);
		}
	}

	private static CoapServer createSimpleServer() {

		CoapServer result = new CoapServer(config);

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setConfiguration(config);
		builder.setConnector(new UDPConnector(LOCALHOST_EPHEMERAL, config) {

			@Override
			public String getProtocol() {
				return "TCP";
			}
		});

		serverEndpoint = builder.build();
		serverEndpoint.addInterceptor(interceptor);
		result.addEndpoint(serverEndpoint);
		TestResource testResource = new TestResource(RESOURCE_TEST) {

			@Override
			public void handleGET(final CoapExchange exchange) {
				LOGGER.info("Server received GET request");
				applicationLayerGetRequestCount.incrementAndGet();
				exchange.respond(LONG_GET_RESPONSE);
			}

			@Override
			public void handlePOST(final CoapExchange exchange) {
				String payload = exchange.getRequestText();
				LOGGER.info("Server received {}", payload);
				assertEquals(payload, LONG_POST_REQUEST);
				exchange.respond(LONG_POST_RESPONSE);
			}
		};
		cleanup.add(testResource);
		result.add(testResource);
		result.add(new CoapResource(RESOURCE_BIG) {

			@Override
			public void handleGET(final CoapExchange exchange) {
				exchange.respond(OVERSIZE_BODY);
			}
		});

		result.start();
		LOGGER.info("serverPort: {}", serverEndpoint.getAddress().getPort());
		return result;
	}

	private static int getBertBlocks(String payload) {
		int bulk = config.get(CoapConfig.TCP_NUMBER_OF_BULK_BLOCKS);
		int bulkSize = 1024 * bulk;
		return (payload.length() + bulkSize - 1) / bulkSize;
	}
}
