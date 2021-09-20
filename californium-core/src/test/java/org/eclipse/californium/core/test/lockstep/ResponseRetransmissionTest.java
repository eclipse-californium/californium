/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *     Achim Kraus (Bosch Software Innovations GmbH) - initial implementation
 *******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import static org.eclipse.californium.core.coap.CoAP.Code.GET;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.Type.ACK;
import static org.eclipse.californium.core.coap.CoAP.Type.CON;
import static org.eclipse.californium.core.test.MessageExchangeStoreTool.assertAllExchangesAreCompleted;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.createLockstepEndpoint;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.generateNextToken;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.printServerLog;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNull;

import java.util.concurrent.TimeUnit;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.interceptors.HealthStatisticLogger;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.test.MessageExchangeStoreTool.CoapTestEndpoint;
import org.eclipse.californium.core.test.MessageExchangeStoreTool.UDPTestConnector;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.rule.TestTimeRule;
import org.eclipse.californium.elements.util.TestConditionTools;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.hamcrest.Matcher;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This test checks for correct MID namespaces and deduplication.
 */
@Category(Medium.class)
public class ResponseRetransmissionTest {
	private static final Logger LOGGER = LoggerFactory.getLogger(ResponseRetransmissionTest.class);

	private static final String PIGGYBACKED = "ack";
	private static final String SEPARATE = "con";
	private static final int TEST_EXCHANGE_LIFETIME = 247; // milliseconds
	private static final int TEST_SWEEP_DEDUPLICATOR_INTERVAL = 100; // milliseconds
	private static final int TEST_ACK_TIMEOUT = 200; // milliseconds

	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	@Rule
	public TestTimeRule time = new TestTimeRule();

	private int mid = 17000;
	private LockstepEndpoint client;

	private CoapServer server;
	private CoapTestEndpoint serverEndpoint;
	private UDPTestConnector serverConnector;
	private ServerBlockwiseInterceptor serverInterceptor = new ServerBlockwiseInterceptor();
	private HealthStatisticLogger health = new HealthStatisticLogger("server", true);

	@Before
	public void setup() throws Exception {
		Configuration config = network.createTestConfig()
				// server retransmits after 200 ms
				.set(CoapConfig.ACK_TIMEOUT, TEST_ACK_TIMEOUT, TimeUnit.MILLISECONDS)
				.set(CoapConfig.ACK_INIT_RANDOM, 1F)
				.set(CoapConfig.MAX_RETRANSMIT, 1)
				.set(CoapConfig.MARK_AND_SWEEP_INTERVAL, TEST_SWEEP_DEDUPLICATOR_INTERVAL, TimeUnit.MILLISECONDS)
				.set(CoapConfig.EXCHANGE_LIFETIME, TEST_EXCHANGE_LIFETIME, TimeUnit.MILLISECONDS);
		serverConnector = new UDPTestConnector(TestTools.LOCALHOST_EPHEMERAL, config);
		serverEndpoint = new CoapTestEndpoint(serverConnector, config, false);
		serverEndpoint.addInterceptor(serverInterceptor);
		serverEndpoint.addPostProcessInterceptor(health);
		server = new CoapServer(config);
		server.addEndpoint(serverEndpoint);
		server.add(new TestResource(SEPARATE, true));
		server.add(new TestResource(PIGGYBACKED, false));
		server.start();
		cleanup.add(server);

		client = createLockstepEndpoint(serverEndpoint.getAddress(), config);
		cleanup.add(client);
		LOGGER.info("Server binds to port {}", serverEndpoint.getAddress().getPort());
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
	public void testGET() throws Exception {
		Token tok = generateNextToken();

		client.sendRequest(CON, GET, tok, ++mid).path(SEPARATE).go();
		client.startMultiExpectation();
		client.expectEmpty(ACK, mid).go();
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("M").go();
		client.goMultiExpectation();

		client.sendEmpty(ACK).loadMID("M").go();

		assertAllExchangesAreCompleted(serverEndpoint, time);

		// may be on the way
		assertHealthCounter("recv-acks", is(1L), 1000);

		assertHealthCounter("send-responses", is(1L));
		assertHealthCounter("send-response retransmissions", is(0L));
		assertHealthCounter("send-acks", is(1L));
		assertHealthCounter("send-rejects", is(0L));
		assertHealthCounter("send-errors", is(0L));
		assertHealthCounter("recv-requests", is(1L));
		assertHealthCounter("recv-duplicate requests", is(0L));
		assertHealthCounter("recv-rejects", is(0L));
		assertHealthCounter("recv-ignored", is(0L));
	}

	@Test
	public void testGETRequestRetransmittedConResponse() throws Exception {
		Token tok = generateNextToken();

		client.sendRequest(CON, GET, tok, ++mid).path(SEPARATE).go();
		client.startMultiExpectation();
		client.expectEmpty(ACK, mid).go();
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("M").go();
		client.goMultiExpectation();

		client.sendRequest(CON, GET, tok, mid).path(SEPARATE).go();
		client.startMultiExpectation();
		client.expectEmpty(ACK, mid).go();
		client.expectResponse().type(CON).code(CONTENT).token(tok).sameMID("M").go();
		client.goMultiExpectation();

		client.sendEmpty(ACK).loadMID("M").go();

		assertAllExchangesAreCompleted(serverEndpoint, time);

		// may be on the way
		assertHealthCounter("recv-acks", is(1L), 1000);

		assertHealthCounter("send-responses", is(1L));
		assertHealthCounter("send-response retransmissions", is(1L));
		assertHealthCounter("send-acks", is(2L));
		assertHealthCounter("send-rejects", is(0L));
		assertHealthCounter("send-errors", is(0L));
		assertHealthCounter("recv-requests", is(1L));
		assertHealthCounter("recv-duplicate requests", is(1L));
		assertHealthCounter("recv-rejects", is(0L));
		assertHealthCounter("recv-ignored", is(0L));
	}

	@Test
	public void testGETRequestRetransmittedAckResponse() throws Exception {
		Token tok = generateNextToken();

		client.sendRequest(CON, GET, tok, ++mid).path(PIGGYBACKED).go();
		client.expectResponse().type(ACK).code(CONTENT).token(tok).mid(mid).go();

		client.sendRequest(CON, GET, tok, mid).path(PIGGYBACKED).go();
		client.expectResponse().type(ACK).code(CONTENT).token(tok).mid(mid).go();

		assertAllExchangesAreCompleted(serverEndpoint, time);

		// may be on the way
		assertHealthCounter("recv-duplicate requests", is(1L), 1000);

		assertHealthCounter("send-responses", is(1L));
		assertHealthCounter("send-response retransmissions", is(1L));
		assertHealthCounter("send-acks", is(0L));
		assertHealthCounter("send-rejects", is(0L));
		assertHealthCounter("send-errors", is(0L));
		assertHealthCounter("recv-requests", is(1L));
		assertHealthCounter("recv-acks", is(0L));
		assertHealthCounter("recv-rejects", is(0L));
		assertHealthCounter("recv-ignored", is(0L));
	}

	@Test
	public void testGETResponseRetransmitted() throws Exception {
		Token tok = generateNextToken();

		client.sendRequest(CON, GET, tok, ++mid).path(SEPARATE).go();
		client.startMultiExpectation();
		client.expectEmpty(ACK, mid).go();
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("M").go();
		client.goMultiExpectation();

		client.expectResponse().type(CON).code(CONTENT).token(tok).sameMID("M").go();

		client.sendEmpty(ACK).loadMID("M").go();

		assertAllExchangesAreCompleted(serverEndpoint, time);

		// may be on the way
		assertHealthCounter("recv-acks", is(1L), 1000);

		assertHealthCounter("send-responses", is(1L));
		assertHealthCounter("send-response retransmissions", is(1L));
		assertHealthCounter("send-acks", is(1L));
		assertHealthCounter("send-rejects", is(0L));
		assertHealthCounter("send-errors", is(0L));
		assertHealthCounter("recv-requests", is(1L));
		assertHealthCounter("recv-duplicate requests", is(0L));
		assertHealthCounter("recv-rejects", is(0L));
		assertHealthCounter("recv-ignored", is(0L));
	}

	@Test
	public void testGETResponseTimeout() throws Exception {
		Token tok = generateNextToken();

		client.sendRequest(CON, GET, tok, ++mid).path(SEPARATE).go();
		client.startMultiExpectation();
		client.expectEmpty(ACK, mid).go();
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("M").go();
		client.goMultiExpectation();

		client.expectResponse().type(CON).code(CONTENT).token(tok).sameMID("M").go();
		assertNull(client.receiveNextMessage(TEST_ACK_TIMEOUT * 2, TimeUnit.MILLISECONDS));

		assertAllExchangesAreCompleted(serverEndpoint, time);
		assertHealthCounter("send-responses", is(1L));
		assertHealthCounter("send-response retransmissions", is(1L));
		assertHealthCounter("send-acks", is(1L));
		assertHealthCounter("send-rejects", is(0L));
		assertHealthCounter("send-errors", is(0L));
		assertHealthCounter("recv-requests", is(1L));
		assertHealthCounter("recv-duplicate requests", is(0L));
		assertHealthCounter("recv-acks", is(0L));
		assertHealthCounter("recv-rejects", is(0L));
		assertHealthCounter("recv-ignored", is(0L));
	}

	@Test
	public void testGETResponseSendError() throws Exception {
		serverConnector.setDrops(1, 2);
		Token tok = generateNextToken();

		client.setVerbose(true);
		client.sendRequest(CON, GET, tok, ++mid).path(SEPARATE).go();
		client.expectEmpty(ACK, mid).go();
		assertNull(client.receiveNextMessage(TEST_ACK_TIMEOUT * 2, TimeUnit.MILLISECONDS));

		assertAllExchangesAreCompleted(serverEndpoint, time);
		assertHealthCounter("send-responses", is(0L));
		assertHealthCounter("send-response retransmissions", is(0L));
		assertHealthCounter("send-acks", is(1L));
		assertHealthCounter("send-rejects", is(0L));
		assertHealthCounter("send-errors", is(1L));
		assertHealthCounter("recv-requests", is(1L));
		assertHealthCounter("recv-duplicate requests", is(0L));
		assertHealthCounter("recv-acks", is(0L));
		assertHealthCounter("recv-rejects", is(0L));
		assertHealthCounter("recv-ignored", is(0L));
	}

	private void assertHealthCounter(final String name, final Matcher<? super Long> matcher, long timeout)
			throws InterruptedException {
		TestConditionTools.assertStatisticCounter(health, name, matcher, timeout, TimeUnit.MILLISECONDS);
	}

	private void assertHealthCounter(String name, Matcher<? super Long> matcher) {
		TestConditionTools.assertStatisticCounter(health, name, matcher);
	}

	private class TestResource extends CoapResource {

		private boolean separate;

		public TestResource(String name, boolean separate) {
			super(name);
			this.separate = separate;
		}

		public void handleGET(final CoapExchange exchange) {
			if (separate) {
				exchange.accept();
			}
			exchange.respond("hi!");
		}
	}
}
