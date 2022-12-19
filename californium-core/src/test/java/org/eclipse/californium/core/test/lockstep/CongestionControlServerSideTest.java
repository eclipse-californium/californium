/*******************************************************************************
 * Copyright (c) 2022 Contributors to the Eclipse Foundation.
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
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import static org.eclipse.californium.TestTools.generateRandomPayload;
import static org.eclipse.californium.core.coap.CoAP.Code.GET;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.Type.ACK;
import static org.eclipse.californium.core.coap.CoAP.Type.CON;
import static org.eclipse.californium.core.test.MessageExchangeStoreTool.assertAllExchangesAreCompleted;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.createLockstepEndpoint;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.generateNextToken;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.printServerLog;
import static org.junit.Assert.assertNull;

import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.config.CoapConfig.CongestionControlMode;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.test.MessageExchangeStoreTool.CoapTestEndpoint;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.rule.TestTimeRule;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Category(Medium.class)
public class CongestionControlServerSideTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(CongestionControlServerSideTest.class);
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestTimeRule time = new TestTimeRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final int TEST_EXCHANGE_LIFETIME = 247; // milliseconds
	private static final int TEST_SWEEP_DEDUPLICATOR_INTERVAL = 100; // milliseconds

	private static final int RESPONSE_TIMEOUT_IN_MS = 1000;
	// client retransmits after 200 ms
	private static final int ACK_TIMEOUT_IN_MS = 20000;

	private static final String RESOURCE_PATH = "test";

	private Configuration config;

	private CoapServer server;
	private CoapTestEndpoint serverEndpoint;
	private LockstepEndpoint client;

	private TestResource testResource;

	private ServerBlockwiseInterceptor serverInterceptor = new ServerBlockwiseInterceptor();

	@Before
	public void setup() throws Exception {
		config = network.createStandardTestConfig()
				.set(CoapConfig.MARK_AND_SWEEP_INTERVAL, TEST_SWEEP_DEDUPLICATOR_INTERVAL, TimeUnit.MILLISECONDS)
				.set(CoapConfig.EXCHANGE_LIFETIME, TEST_EXCHANGE_LIFETIME, TimeUnit.MILLISECONDS)
				.set(CoapConfig.ACK_TIMEOUT, ACK_TIMEOUT_IN_MS, TimeUnit.MILLISECONDS)
				.set(CoapConfig.ACK_INIT_RANDOM, 1F)
				.set(CoapConfig.MAX_RETRANSMIT, 2)
				.set(CoapConfig.ACK_TIMEOUT_SCALE, 1F)
				.set(CoapConfig.CONGESTION_CONTROL_ALGORITHM, CongestionControlMode.BASIC_RTO)
				.set(CoapConfig.NSTART, 3);

		testResource = new TestResource(RESOURCE_PATH);

		serverEndpoint = new CoapTestEndpoint(TestTools.LOCALHOST_EPHEMERAL, config);
		serverEndpoint.addInterceptor(serverInterceptor);
		server = new CoapServer(config);
		server.addEndpoint(serverEndpoint);
		server.add(testResource);
		server.start();
		cleanup.add(server);

		InetSocketAddress serverAddress = serverEndpoint.getAddress();
		LOGGER.info("Server binds to port {}", serverAddress.getPort());
		client = createLockstepEndpoint(serverAddress, config);
		cleanup.add(client);
	}

	@After
	public void shutdown() {
		try {
			assertAllExchangesAreCompleted(serverEndpoint, time);
		} finally {
			printServerLog(serverInterceptor);
		}
	}

	@Test
	public void testNstartLimitSeparateResponse() throws Exception {
		int mid = 1000;
		String payload = generateRandomPayload(16);
		Token tok = generateNextToken();

		testResource.setSeparateResponse(true);
		testResource.setPayload(payload);

		// request 1
		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).go();
		client.startMultiExpectation();
		client.expectEmpty(ACK, mid).go();
		client.expectSeparateResponse(CON, CONTENT, tok).storeMID("A").payload(payload).go();
		client.goMultiExpectation();

		payload = generateRandomPayload(16);
		tok = generateNextToken();
		testResource.setPayload(payload);

		// request 2
		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).go();
		client.startMultiExpectation();
		client.expectEmpty(ACK, mid).go();
		client.expectSeparateResponse(CON, CONTENT, tok).storeMID("B").payload(payload).go();
		client.goMultiExpectation();

		payload = generateRandomPayload(16);
		tok = generateNextToken();
		testResource.setPayload(payload);

		// request 3
		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).go();
		client.startMultiExpectation();
		client.expectEmpty(ACK, mid).go();
		client.expectSeparateResponse(CON, CONTENT, tok).storeMID("C").payload(payload).go();
		client.goMultiExpectation();

		payload = generateRandomPayload(16);
		tok = generateNextToken();
		testResource.setPayload(payload);

		// request 4, NSTART 3 postpone response
		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).go();
		client.expectEmpty(ACK, mid).go();

		assertNull("send response exceeds nstart", client.receiveNextMessage(RESPONSE_TIMEOUT_IN_MS, TimeUnit.MILLISECONDS));

		String payload2 = generateRandomPayload(16);
		Token tok2 = generateNextToken();
		testResource.setSeparateResponse(false);
		testResource.setPayload(payload2);

		// piggybacked response still send
		client.sendRequest(CON, GET, tok2, ++mid).path(RESOURCE_PATH).go();
		client.expectResponse(ACK, CONTENT, tok2, mid).payload(payload2).go();

		// ACK for first response
		client.sendEmpty(ACK).loadMID("A").go();

		// delayed response for 4. request is sent
		client.expectSeparateResponse(CON, CONTENT, tok).storeMID("D").payload(payload).go();

		client.sendEmpty(ACK).loadMID("B").go();
		client.sendEmpty(ACK).loadMID("C").go();
		client.sendEmpty(ACK).loadMID("D").go();
	}

	@Test
	public void testNstartLimitPiggyBacked() throws Exception {
		int mid = 2000;
		testResource.setSeparateResponse(false);
		String payload = generateRandomPayload(16);
		Token tok = generateNextToken();

		testResource.setPayload(payload);

		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).go();
		client.expectResponse(ACK, CONTENT, tok, mid).payload(payload).go();

		payload = generateRandomPayload(16);
		tok = generateNextToken();

		testResource.setPayload(payload);

		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).go();
		client.expectResponse(ACK, CONTENT, tok, mid).payload(payload).go();
	}

	// All tests are made with this resource
	private class TestResource extends CoapResource {

		private volatile boolean separateResponse;
		private volatile String payload;

		public TestResource(String name) {
			super(name);
		}

		public void setSeparateResponse(boolean enable) {
			this.separateResponse = enable;
		}

		public void setPayload(String payload) {
			this.payload = payload;
		}

		public void handleGET(final CoapExchange exchange) {
			respond(exchange, ResponseCode.CONTENT, payload);
		}

		private void respond(final CoapExchange exchange, final ResponseCode code, final String payload) {
			if (separateResponse) {
				exchange.accept();
			}
			exchange.respond(code, payload);
		}
	}

}
