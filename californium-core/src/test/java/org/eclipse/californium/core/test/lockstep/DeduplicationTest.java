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
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.*;
import static org.junit.Assert.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
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
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private LockstepEndpoint server;

	private Endpoint client;

	@Before
	public void setup() throws Exception {
		NetworkConfig config = network.createTestConfig()
			.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 128)
			.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 128)
			.setInt(NetworkConfig.Keys.ACK_TIMEOUT, 200) // client retransmits after 200 ms
			.setInt(NetworkConfig.Keys.ACK_RANDOM_FACTOR, 1);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		builder.setNetworkConfig(config);
		client = builder.build();
		cleanup.add(client);
		client.addInterceptor(new MessageTracer());
		client.start();
		server = createLockstepEndpoint(client.getAddress());
		cleanup.add(server);
		System.out.println("Client binds to port " + client.getAddress().getPort());
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
	}
}
