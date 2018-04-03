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
import static org.eclipse.californium.core.coap.CoAP.Type.NON;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.createLockstepEndpoint;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.printServerLog;
import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.After;
import org.junit.AfterClass;
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
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	private static final int DEDUPLICATOR_SWEEP_INTERVAL = 200; // ms
	private static final String resourceName = "test";
	private static final String payload = "hello there ";

	private static AtomicInteger handleCounter;
	private static CoapServer server;
	private static ServerBlockwiseInterceptor serverInterceptor = new ServerBlockwiseInterceptor();
	private static InetSocketAddress serverAddress;

	private LockstepEndpoint client;

	@BeforeClass
	public static void setupServer() throws Exception {

		NetworkConfig config = network.getStandardTestConfig();
		config.setString(Keys.DEDUPLICATOR, Keys.DEDUPLICATOR_MARK_AND_SWEEP);
		config.setInt(Keys.MARK_AND_SWEEP_INTERVAL, DEDUPLICATOR_SWEEP_INTERVAL);
		config.setInt(Keys.ACK_TIMEOUT, 1000);
		config.setFloat(Keys.ACK_TIMEOUT_SCALE, 1.0F);
		config.setFloat(Keys.ACK_RANDOM_FACTOR, 1.0F);
		CoapEndpoint.CoapEndpointBuilder builder = new CoapEndpoint.CoapEndpointBuilder();
		builder.setInetSocketAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
		builder.setNetworkConfig(config);
		Endpoint ep = builder.build();
		ep.addInterceptor(new MessageTracer());
		ep.addInterceptor(serverInterceptor);
		handleCounter = new AtomicInteger();
		server = new CoapServer();
		server.addEndpoint(ep);
		server.add(new CoapResource(resourceName) {

			@Override
			public Resource getChild(String name) {
				return this;
			}

			@Override
			public void handleGET(CoapExchange exchange) {
				int count = handleCounter.incrementAndGet();
				String uriPath = exchange.getRequestOptions().getUriPathString();
				if (uriPath.endsWith("/CON")) {
					exchange.accept();
					Response response = new Response(CONTENT);
					response.setType(CON);
					response.setPayload(payload + count);
					response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
					exchange.respond(response);
				} else if (uriPath.endsWith("/NON")) {
					exchange.accept();
					Response response = new Response(CONTENT);
					response.setType(NON);
					response.setPayload(payload + count);
					response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
					exchange.respond(response);
				} else if (uriPath.endsWith("/SEP")) {
					exchange.accept();
					exchange.respond(payload + count);
				} else if (uriPath.endsWith("/NODEDUP")) {
					if (!exchange.advanced().setupDeliverDuplicate(2)) {
						exchange.respond(payload + count);
					}
					else {
						serverInterceptor.log(StringUtil.lineSeparator() + "// setup to deliver duplicate request again!");
					}
				} else {
					exchange.respond(payload + count);
				}
			}
		});
		server.start();
		serverAddress = ep.getAddress();
	}

	@Before
	public void createClient() {
		handleCounter.set(0);
		client = createLockstepEndpoint(serverAddress);
	}

	@After
	public void destroyClient() {
		if (client != null) {
			client.destroy();
		}
		printServerLog(serverInterceptor);
	}

	@AfterClass
	public static void shutdownServer() {
		if (server != null) {
			server.destroy();
		}
	}

	/**
	 * Verifies that the server recognizes a duplicate request (same MID) and
	 * sends back the same "piggybacked" ACK response.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testServerPiggybackedRespondsToDuplicateRequest() throws Exception {

		Token token = Token.fromProvider(new byte[] { 0x00, 0x00 });
		int mid = 1234;

		client.sendRequest(CON, GET, token, mid).path(resourceName).go();
		// server will send response but response is lost
		// even then, the response must be read from lockstep client,
		// otherwise the 2. expect will just read the first response!
		client.expectResponse(ACK, CONTENT, token, mid).payload(payload + "1").go();

		Thread.sleep(DEDUPLICATOR_SWEEP_INTERVAL / 2);

		// caused by the lost response, client re-transmits request
		client.sendRequest(CON, GET, token, mid).path(resourceName).go();
		client.expectResponse(ACK, CONTENT, token, mid).payload(payload + "1").go();

		// new client request
		client.sendRequest(CON, GET, token, ++mid).path(resourceName).go();
		client.expectResponse(ACK, CONTENT, token, mid).payload(payload + "2").go();

		// no more messages
		assertThat(client.receiveNextMessage(500, TimeUnit.MILLISECONDS), is(nullValue()));
	}

	/**
	 * Verifies that the server recognizes a duplicate request (same MID) and
	 * delivers the request, if the exchange is prepared to do so.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testServerPiggybackedRespondsToDeliveredDuplicateRequest() throws Exception {

		Token token = Token.fromProvider(new byte[] { 0x00, 0x00 });
		int mid = 2345;
		String path = resourceName + "/NODEDUP";

		client.sendRequest(CON, GET, token, mid).path(path).go();
		// server will not response to the first request
		assertThat(client.receiveNextMessage(500, TimeUnit.MILLISECONDS), is(nullValue()));
		client.sendRequest(CON, GET, token, mid).path(path).go();
		// server will not response to the first retransmission (second request) 
		assertThat(client.receiveNextMessage(500, TimeUnit.MILLISECONDS), is(nullValue()));
		client.sendRequest(CON, GET, token, mid).path(path).go();
		// server send response for the 3. request
		client.expectResponse(ACK, CONTENT, token, mid).payload(payload + "3").go();

		// client re-transmits request
		client.sendRequest(CON, GET, token, mid).path(path).go();
		client.expectResponse(ACK, CONTENT, token, mid).payload(payload + "3").go();

		// no more messages
		assertThat(client.receiveNextMessage(500, TimeUnit.MILLISECONDS), is(nullValue()));
	}

	/**
	 * Verifies that the server recognizes a duplicate request (same MID) and
	 * sends back the same separate CON response.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testServerSeparateConRespondsToDuplicateRequest() throws Exception {

		Token token = Token.fromProvider(new byte[] { 0x00, 0x01 });
		int mid = 3456;
		String path = resourceName + "/CON";

		client.sendRequest(CON, GET, token, mid).path(path).go();
		// server will send a ACK but that ACK is lost
		// even then, the response must be read from lockstep client,
		// otherwise the 2. expect will just read the first response!
		client.startMultiExpectation();
		client.expectEmpty(ACK, mid).go();
		client.expectResponse().type(CON).code(CONTENT).token(token).storeMID("M").payload(payload + "1").go();
		client.goMultiExpectation();
		// don't ACK the "lost" CON response

		// caused by the lost response, client re-transmits request
		client.sendRequest(CON, GET, token, mid).path(path).go();

		client.startMultiExpectation();
		client.expectEmpty(ACK, mid).go();
		client.expectResponse().type(CON).code(CONTENT).token(token).sameMID("M").payload(payload + "1").go();
		client.goMultiExpectation();

		// don't ACK, check retransmission
		client.expectResponse().type(CON).code(CONTENT).token(token).sameMID("M").payload(payload + "1").go();
		client.sendEmpty(ACK).loadMID("M").go();

		// new client request
		client.sendRequest(CON, GET, token, ++mid).path(path).go();
		client.startMultiExpectation();
		client.expectEmpty(ACK, mid).go();
		client.expectResponse().type(CON).code(CONTENT).token(token).storeMID("M").payload(payload + "2").go();
		client.goMultiExpectation();
		client.sendEmpty(ACK).loadMID("M").go();

		// no more messages
		assertThat(client.receiveNextMessage(500, TimeUnit.MILLISECONDS), is(nullValue()));
	}

	@Test
	public void testServerSeparateNonRespondsToDuplicateRequest() throws Exception {

		Token token = Token.fromProvider(new byte[] { 0x00, 0x01 });
		int mid = 4567;
		String path = resourceName + "/NON";

		client.sendRequest(CON, GET, token, mid).path(path).go();
		// server will send a ACK but that ACK is lost
		// even then, the response must be read from lockstep client,
		// otherwise the 2. expect will just read the first response!
		client.startMultiExpectation();
		client.expectEmpty(ACK, mid).go();
		client.expectResponse().type(NON).code(CONTENT).token(token).storeMID("M").payload(payload + "1").go();
		client.goMultiExpectation();

		// caused by the lost response, client re-transmits request
		client.sendRequest(CON, GET, token, mid).path(path).go();

		client.startMultiExpectation();
		client.expectEmpty(ACK, mid).go();
		client.expectResponse().type(NON).code(CONTENT).token(token).sameMID("M").payload(payload + "1").go();
		client.goMultiExpectation();

		// new client request
		client.sendRequest(CON, GET, token, ++mid).path(path).go();
		client.startMultiExpectation();
		client.expectEmpty(ACK, mid).go();
		client.expectResponse().type(NON).code(CONTENT).token(token).storeMID("M").payload(payload + "2").go();
		client.goMultiExpectation();

		// no more messages
		assertThat(client.receiveNextMessage(500, TimeUnit.MILLISECONDS), is(nullValue()));
	}
}
