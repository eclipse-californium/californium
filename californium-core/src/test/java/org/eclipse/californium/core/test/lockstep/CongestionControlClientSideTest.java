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
 *    Bosch IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import static org.eclipse.californium.TestTools.generateRandomPayload;
import static org.eclipse.californium.core.coap.CoAP.Code.GET;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.Type.NON;
import static org.eclipse.californium.core.test.MessageExchangeStoreTool.assertAllExchangesAreCompleted;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.createLockstepEndpoint;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.createRequest;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.printServerLog;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.concurrent.TimeUnit;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.config.CoapConfig.CongestionControlMode;
import org.eclipse.californium.core.network.stack.congestioncontrol.Rto;
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
public class CongestionControlClientSideTest {
	private static final Logger LOGGER = LoggerFactory.getLogger(CongestionControlClientSideTest.class);
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestTimeRule time = new TestTimeRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final int TEST_EXCHANGE_LIFETIME = 247; // milliseconds
	private static final int TEST_SWEEP_DEDUPLICATOR_INTERVAL = 100; // milliseconds

	private static final int RESPONSE_TIMEOUT_IN_MS = 1000;
	private static final int ERROR_TIMEOUT_IN_MS = 500;
	// client retransmits after 200 ms
	private static final int ACK_TIMEOUT_IN_MS = 200;

	private Configuration config;

	private LockstepEndpoint server;
	private CoapTestEndpoint client;
	private String respPayload;
	private ClientBlockwiseInterceptor clientInterceptor = new ClientBlockwiseInterceptor();

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

		client = new CoapTestEndpoint(TestTools.LOCALHOST_EPHEMERAL, config);
		cleanup.add(client);
		client.addInterceptor(clientInterceptor);
		client.start();
		LOGGER.info("Client binds to port {}", client.getAddress().getPort());
		server = createLockstepEndpoint(client.getAddress(), config);
		cleanup.add(server);
	}

	@After
	public void shutdown() {
		try {
			assertAllExchangesAreCompleted(client, time);
		} finally {
			printServerLog(clientInterceptor);
		}
	}

	@Test
	public void testNstartLimit() throws Exception {
		int mid = 1000;
		respPayload = generateRandomPayload(16);
		String path = "test";
		Request request1 = createRequest(GET, path, server);
		request1.setType(NON);
		client.sendRequest(request1);
		server.expectRequest(NON, GET, path).storeToken("A").go();

		Request request2 = createRequest(GET, path, server);
		request2.setType(NON);
		client.sendRequest(request2);
		server.expectRequest(NON, GET, path).storeToken("B").go();

		Request request3 = createRequest(GET, path, server);
		request3.setType(NON);
		client.sendRequest(request3);
		server.expectRequest(NON, GET, path).storeToken("C").go();

		// NSTART 3 will postpone request 4
		Request request4 = createRequest(GET, path, server);
		request4.setType(NON);
		client.sendRequest(request4);

		assertNull("received message exceeds nstart", server.receiveNextMessage(RESPONSE_TIMEOUT_IN_MS, TimeUnit.MILLISECONDS));

		server.sendResponse(NON, CONTENT).mid(++mid).loadToken("B").payload(respPayload).go();

		assertNull(request1.waitForResponse(ERROR_TIMEOUT_IN_MS));

		Response response = request2.waitForResponse(RESPONSE_TIMEOUT_IN_MS);
		assertNotNull(response);

		server.expectRequest(NON, GET, path).storeToken("D").go();
		server.sendResponse(NON, CONTENT).mid(++mid).loadToken("A").payload(respPayload).go();
		server.sendResponse(NON, CONTENT).mid(++mid).loadToken("C").payload(respPayload).go();
		server.sendResponse(NON, CONTENT).mid(++mid).loadToken("D").payload(respPayload).go();
		assertNotNull(request1.waitForResponse(RESPONSE_TIMEOUT_IN_MS));
		assertNotNull(request3.waitForResponse(RESPONSE_TIMEOUT_IN_MS));
		assertNotNull(request4.waitForResponse(RESPONSE_TIMEOUT_IN_MS));
	}

	@Test
	public void testRto() throws Exception {
		Rto rto = new Rto(4, 2000);
		assertThat(rto.apply(1000), is(3000L));
		for (int count = 1; count < 25; ++count) {
			rto.apply(1000);
		}
		// RTO = RTT + G 
		assertThat(rto.apply(1000), is(1100L));
	}

}
