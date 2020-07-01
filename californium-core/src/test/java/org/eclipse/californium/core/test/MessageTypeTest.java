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
package org.eclipse.californium.core.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * This test tests that the message type of responses is correct.
 */
@Category(Medium.class)
public class MessageTypeTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	@ClassRule
	public static CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final String SERVER_RESPONSE = "server responds hi";
	private static final String ACC_RESOURCE = "acc-res";
	private static final String NO_ACC_RESOURCE = "no-acc-res";

	private static Endpoint serverEndpoint;

	@BeforeClass
	public static void setupServer() {
		EndpointManager.clear();

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		serverEndpoint = builder.build();

		CoapServer server = new CoapServer(network.getStandardTestConfig());
		cleanup.add(server);
		server.addEndpoint(serverEndpoint);
		server.add(new CoapResource(ACC_RESOURCE) {
			public void handlePOST(CoapExchange exchange) {
				exchange.accept();
				System.out.println("gotit");
				exchange.respond(SERVER_RESPONSE);
			}
		});
		server.add(new CoapResource(NO_ACC_RESOURCE) {
			public void handlePOST(CoapExchange exchange) {
				exchange.respond(SERVER_RESPONSE);
			}
		});
		server.start();
	}

	@Test
	public void testNonConfirmable() throws Exception {
		// send request
		Request req2acc = new Request(Code.POST);
		req2acc.setConfirmable(false);
		req2acc.setURI(getUri(ACC_RESOURCE));
		req2acc.setPayload("client says hi");
		req2acc.send();

		// receive response and check
		Response response = req2acc.waitForResponse(1000);
		assertPayloadIsOfCorrectType(response, SERVER_RESPONSE, Type.NON);

		Request req2noacc = new Request(Code.POST);
		req2noacc.setConfirmable(false);
		req2noacc.setURI(getUri(NO_ACC_RESOURCE));
		req2noacc.setPayload("client says hi");
		req2noacc.send();

		// receive response and check
		response = req2noacc.waitForResponse(1000);
		assertPayloadIsOfCorrectType(response, SERVER_RESPONSE, Type.NON);
	}

	@Test
	public void testConfirmable() throws Exception {
		// send request
		Request req2acc = new Request(Code.POST);
		req2acc.setConfirmable(true);
		req2acc.setURI(getUri(ACC_RESOURCE));
		req2acc.setPayload("client says hi");
		req2acc.send();

		// receive response and check
		Response response = req2acc.waitForResponse(1000);
		assertPayloadIsOfCorrectType(response, SERVER_RESPONSE, Type.CON);

		Request req2noacc = new Request(Code.POST);
		req2noacc.setConfirmable(true);
		req2noacc.setURI(getUri(NO_ACC_RESOURCE));
		req2noacc.setPayload("client says hi");
		req2noacc.send();

		// receive response and check
		response = req2noacc.waitForResponse(1000);
		assertPayloadIsOfCorrectType(response, SERVER_RESPONSE, Type.ACK);
	}

	private static void assertPayloadIsOfCorrectType(final Response response, final String expectedPayload,
			final Type expectedType) {
		assertNotNull("Client received no response", response);
		assertEquals(response.getPayloadString(), expectedPayload);
		assertEquals(response.getType(), expectedType);
	}

	private static String getUri(final String resourceName) {
		return TestTools.getUri(serverEndpoint, resourceName);
	}
}
