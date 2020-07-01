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
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CoapNetworkRule for
 *                                                    setup of test-network
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import static org.eclipse.californium.core.coap.CoAP.Code.GET;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.Type.ACK;
import static org.eclipse.californium.core.coap.CoAP.Type.CON;
import static org.eclipse.californium.core.coap.CoAP.Type.RST;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.assertResponseContainsExpectedPayload;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.createLockstepEndpoint;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.createRequest;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.printServerLog;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;

import java.util.concurrent.TimeUnit;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.HealthStatisticLogger;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.network.stack.ReliabilityLayerParameters;
import org.eclipse.californium.core.network.stack.ReliabilityLayerParameters.Builder;
import org.eclipse.californium.core.test.CountingMessageObserver;
import org.eclipse.californium.core.test.MessageExchangeStoreTool.UDPTestConnector;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
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

/**
 * This test checks for correct MID namespaces and deduplication.
 */
@Category(Medium.class)
public class DeduplicationTest {

	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private LockstepEndpoint server;

	private Endpoint client;
	private UDPTestConnector clientConnector;
	private ClientBlockwiseInterceptor clientInterceptor = new ClientBlockwiseInterceptor();
	private HealthStatisticLogger health = new HealthStatisticLogger("client", true);

	@Before
	public void setup() throws Exception {
		NetworkConfig config = network.createTestConfig().setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 128)
				// client retransmits after 200 ms
				.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 128).setInt(NetworkConfig.Keys.ACK_TIMEOUT, 200)
				.setInt(NetworkConfig.Keys.ACK_RANDOM_FACTOR, 1);
		clientConnector = new UDPTestConnector(TestTools.LOCALHOST_EPHEMERAL);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setConnector(clientConnector);
		builder.setNetworkConfig(config);
		CoapEndpoint coapEndpoint = builder.build();
		coapEndpoint.addInterceptor(clientInterceptor);
		coapEndpoint.addPostProcessInterceptor(health);
		client = coapEndpoint;
		cleanup.add(client);
		client.addInterceptor(new MessageTracer());
		client.start();
		server = createLockstepEndpoint(client.getAddress());
		cleanup.add(server);
		System.out.println("Client binds to port " + client.getAddress().getPort());
	}

	@After
	public void printLogs() {
		printServerLog(clientInterceptor);
	}

	@Test
	public void testGET() throws Exception {
		System.out.println("Simple GET:");
		String path = "test";
		String payload = "possible conflict";

		Request request = createRequest(GET, path, server);
		request.setMID(1234);
		client.sendRequest(request);

		server.expectRequest(CON, GET, path).storeToken("A").go();
		server.sendEmpty(ACK).mid(1234).go();
		server.sendEmpty(ACK).mid(1234).go();
		server.sendResponse(CON, CONTENT).loadToken("A").mid(4711).payload("separate").go();
		server.expectEmpty(ACK, 4711).go();
		server.sendResponse(CON, CONTENT).loadToken("A").mid(4711).payload("separate").go();
		server.expectEmpty(ACK, 4711).go();
		server.sendResponse(CON, CONTENT).loadToken("A").mid(42).payload("separate").go();
		server.expectEmpty(RST, 42).go();

		// may be on the way
		assertHealthCounter("recv-ignored", is(2L), 1000);
		assertHealthCounter("send-rejects", is(1L), 1000);
		assertHealthCounter("send-requests", is(1L));
		assertHealthCounter("send-acks", is(2L));
		assertHealthCounter("send-errors", is(0L));
		assertHealthCounter("recv-responses", is(1L));
		assertHealthCounter("recv-duplicate responses", is(1L));
		assertHealthCounter("recv-acks", is(1L));
		health.reset();

		request = createRequest(GET, path, server);
		request.setMID(4711);
		client.sendRequest(request);

		server.expectRequest(CON, GET, path).storeBoth("B").storeToken("C").go();
		server.sendResponse(ACK, CONTENT).loadBoth("B").payload("possible conflict").go();
		server.sendResponse(ACK, CONTENT).loadBoth("B").payload("possible conflict").go();

		Response response = request.waitForResponse(500);
		assertResponseContainsExpectedPayload(response, CONTENT, payload);

		response = request.waitForResponse(500);
		assertNull("Client received duplicate", response);

		// may be on the way
		assertHealthCounter("recv-ignored", is(1L), 1000);
		assertHealthCounter("send-requests", is(1L));
		assertHealthCounter("send-acks", is(0L));
		assertHealthCounter("send-rejects", is(0L));
		assertHealthCounter("send-errors", is(0L));
		assertHealthCounter("recv-responses", is(1L));
		assertHealthCounter("recv-acks", is(0L));
		health.reset();
	}

	@Test
	public void testGETWithReliabilityLayerParameters() throws Exception {
		System.out.println("Simple GET (with ReliabilityLayerParameters):");
		String path = "test";

		Builder builder = ReliabilityLayerParameters.builder().applyConfig(network.getStandardTestConfig());
		builder.maxRetransmit(2);
		builder.ackTimeout(100);
		builder.ackTimeoutScale(1.0F);
		builder.ackRandomFactor(1.0F);
		Request request = createRequest(GET, path, server);
		request.setReliabilityLayerParameters(builder.build());
		client.sendRequest(request);

		server.expectRequest(CON, GET, path).storeBoth("A").go();
		server.expectRequest(CON, GET, path).sameBoth("A").go();
		server.expectRequest(CON, GET, path).sameBoth("A").go();
		Message message = server.receiveNextMessage(1000, TimeUnit.MILLISECONDS);
		assertNull("received unexpected message", message);

		assertHealthCounter("send-requests", is(1L));
		assertHealthCounter("send-request retransmissions", is(2L), 1000);
		assertHealthCounter("send-errors", is(0L));
		assertHealthCounter("recv-responses", is(0L));
		assertHealthCounter("recv-ignored", is(0L));
		health.reset();

		builder.maxRetransmit(1);
		request = createRequest(GET, path, server);
		request.setReliabilityLayerParameters(builder.build());
		client.sendRequest(request);

		server.expectRequest(CON, GET, path).storeBoth("B").go();
		server.expectRequest(CON, GET, path).sameBoth("B").go();
		message = server.receiveNextMessage(1000, TimeUnit.MILLISECONDS);
		assertNull("received unexpected message", message);

		assertHealthCounter("send-requests", is(1L));
		assertHealthCounter("send-request retransmissions", is(1L), 1000);
		assertHealthCounter("send-errors", is(0L));
		assertHealthCounter("recv-responses", is(0L));
		assertHealthCounter("recv-ignored", is(0L));
		health.reset();
	}

	@Test
	public void testGETSendError() throws Exception {
		clientConnector.setDrops(0);
		System.out.println("Simple GET (send error):");
		String path = "test";

		CountingMessageObserver observer = new CountingMessageObserver();
		Request request = createRequest(GET, path, server);
		request.setMID(1234);
		request.addMessageObserver(observer);
		client.sendRequest(request);

		observer.waitForErrorCalls(1, 1000, TimeUnit.MILLISECONDS);
		assertNull("Client received unexpected response", request.getResponse());

		assertHealthCounter("send-errors", is(1L), 1000);
		assertHealthCounter("send-requests", is(0L));
		assertHealthCounter("send-request retransmissions", is(0L));
		assertHealthCounter("recv-responses", is(0L));
		assertHealthCounter("recv-ignored", is(0L));
	}

	@Test
	public void testGETWithRetransmissionAndDtlsHandshakeMode() throws Exception {
		System.out.println("Simple GET with retransmission and dtls handshake mode:");
		String path = "test";

		Builder builder = ReliabilityLayerParameters.builder().applyConfig(network.getStandardTestConfig());
		builder.maxRetransmit(1);
		builder.ackTimeout(100);
		builder.ackTimeoutScale(1.0F);
		builder.ackRandomFactor(1.0F);

		EndpointContext destination = new AddressEndpointContext(server.getSocketAddress());
		destination = MapBasedEndpointContext.addEntries(destination, DtlsEndpointContext.KEY_HANDSHAKE_MODE,
				DtlsEndpointContext.HANDSHAKE_MODE_NONE);
		Request request = createRequest(GET, path, server);
		request.setDestinationContext(destination);
		request.setReliabilityLayerParameters(builder.build());
		client.sendRequest(request);

		server.expectRequest(CON, GET, path).storeBoth("A").go();
		server.expectRequest(CON, GET, path).sameBoth("A").go();
		Message message = server.receiveNextMessage(1000, TimeUnit.MILLISECONDS);
		assertNull("received unexpected message", message);

		assertThat(request.getEffectiveDestinationContext().get(DtlsEndpointContext.KEY_HANDSHAKE_MODE), is(DtlsEndpointContext.HANDSHAKE_MODE_NONE));

		destination = new AddressEndpointContext(server.getSocketAddress());
		destination = MapBasedEndpointContext.addEntries(destination, DtlsEndpointContext.KEY_HANDSHAKE_MODE,
				DtlsEndpointContext.HANDSHAKE_MODE_FORCE);
		request = createRequest(GET, path, server);
		request.setDestinationContext(destination);
		request.setReliabilityLayerParameters(builder.build());
		client.sendRequest(request);

		server.expectRequest(CON, GET, path).storeBoth("A").go();
		server.expectRequest(CON, GET, path).sameBoth("A").go();
		message = server.receiveNextMessage(1000, TimeUnit.MILLISECONDS);
		assertNull("received unexpected message", message);

		assertThat(request.getEffectiveDestinationContext().get(DtlsEndpointContext.KEY_HANDSHAKE_MODE), is(nullValue()));

		assertHealthCounter("send-requests", is(2L));
		assertHealthCounter("send-request retransmissions", is(2L), 1000);
		assertHealthCounter("send-errors", is(0L));
		assertHealthCounter("recv-responses", is(0L));
		assertHealthCounter("recv-ignored", is(0L));
		health.reset();
	}

	private void assertHealthCounter(final String name, final Matcher<? super Long> matcher, long timeout)
			throws InterruptedException {
		TestConditionTools.assertStatisticCounter(health, name, matcher, timeout, TimeUnit.MILLISECONDS);
	}

	private void assertHealthCounter(String name, Matcher<? super Long> matcher) {
		TestConditionTools.assertStatisticCounter(health, name, matcher);
	}
}
