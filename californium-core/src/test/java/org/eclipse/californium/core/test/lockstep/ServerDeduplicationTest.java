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
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CoapNetworkRule for
 *                                                    setup of test-network
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import static org.eclipse.californium.core.coap.CoAP.Code.GET;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.Type.ACK;
import static org.eclipse.californium.core.coap.CoAP.Type.CON;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.createLockstepEndpoint;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * Test case verifying handling of duplicate messages.
 */
@Category(Medium.class)
public class ServerDeduplicationTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	private static final int DEDUPLICATOR_SWEEP_INTERVAL = 200; // ms
	private static final String resourceName = "test";
	private static final String payload = "hello there";

	private static CoapServer server;
	private static InetSocketAddress serverAddress;

	private LockstepEndpoint client;

	@BeforeClass
	public static void setupServer() throws Exception {

		NetworkConfig config = network.getStandardTestConfig();
		config.setString(NetworkConfig.Keys.DEDUPLICATOR, NetworkConfig.Keys.DEDUPLICATOR_MARK_AND_SWEEP);
		config.setInt(NetworkConfig.Keys.MARK_AND_SWEEP_INTERVAL, DEDUPLICATOR_SWEEP_INTERVAL);
		Endpoint ep = new CoapEndpoint(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), config);
		ep.addInterceptor(new MessageTracer());
		server = new CoapServer();
		server.addEndpoint(ep);
		server.add(new CoapResource(resourceName) {
			@Override
			public void handleGET(CoapExchange exchange) {
				exchange.respond(payload);
			}
		});
		server.start();
		serverAddress = ep.getAddress();
	}

	@Before
	public void createClient() {
		client = createLockstepEndpoint(serverAddress);
	}

	@After
	public void destroyClient() {
		if (client != null) {
			client.destroy();
		}
	}

	@After
	public void shutdownServer() {
		if (server != null) {
			server.destroy();
		}
	}

	/**
	 * Verifies that the server recognizes a duplicate request (same MID) and sends
	 * back the same response.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testServerRespondsToDuplicateRequest() throws Exception {

		byte[] token = new byte[]{0x00, 0x00};
		int mid = 1234;

		client.sendRequest(CON, GET, token, mid).path(resourceName).go();
		// server will send response but response is lost
		Thread.sleep(DEDUPLICATOR_SWEEP_INTERVAL / 2);
		// therefore, client re-transmits request
		client.sendRequest(CON, GET, token, mid).path(resourceName).go();
		client.expectResponse(ACK, CONTENT, token, mid).token(token).mid(mid).payload(payload).go();
	}
}
