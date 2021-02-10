/*******************************************************************************
 * Copyright (c) 2020 RISE SICS and others.
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
 * This test class is based on org.eclipse.californium.integration.test.SecureBlockwiseTest
 * 
 * Contributors: 
 *    Rikard Höglund (RISE SICS) - testing OSCORE Block-Wise messages
 ******************************************************************************/
package org.eclipse.californium.oscore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointContextMatcherFactory.MatcherMode;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.ExpectedExceptionWrapper;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.ExpectedException;

/**
 * Class for testing OSCORE together with Block-Wise requests and responses.
 * This is for testing the "inner Block-Wise" mode of OSCORE where the Block
 * CoAP options are encrypted.
 * https://tools.ietf.org/html/rfc8613#section-4.1.3.4.1
 * 
 * The tests cover POST, PUT and GET methods. It tests Block-Wise requests with
 * Block-Wise responses, Block-Wise requests with normal responses and normal
 * requests with Block-Wise responses.
 *
 * It also tests the MAX_UNFRAGMENTED_SIZE parameter to ensure that messages
 * exceeding it cannot be sent without inner block-wise.
 *
 */
@Category(Medium.class)
public class OSCoreInnerBlockwiseTest {

	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final int DEFAULT_BLOCK_SIZE = 64;

	static final int TIMEOUT_IN_MILLIS = 5000;
	static final int REPEATS = 3;
	static final String TARGET = "resource";
	static final String IDENITITY = "client1";

	// OSCORE context information shared between server and client
	private final static HashMapCtxDB dbClient = new HashMapCtxDB();
	private final static HashMapCtxDB dbServer = new HashMapCtxDB();
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };

	private MyResource resource;

	private String uri;
	private String payload;

	@BeforeClass
	public static void setStackFactory() {
		OSCoreCoapStackFactory.useAsDefault(dbClient);
	}

	@Before
	public void startupServer() {
		payload = createRandomPayload(DEFAULT_BLOCK_SIZE * 4);
		createOscoreServer(MatcherMode.STRICT);
		resource.setPayload(payload);
	}

	/**
	 * Perform GET request with Block-Wise response.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testOscoreBlockwiseGet() throws Exception {
		setClientContext(uri);
		Request request = Request.newGet().setURI(uri);
		request.getOptions().setOscore(Bytes.EMPTY);

		CoapClient client = new CoapClient();
		CoapResponse response = client.advanced(request);
		assertNotNull(response);
		assertEquals(CoAP.ResponseCode.CONTENT, response.getCode());
		assertTrue(response.getOptions().hasSize2());
		assertFalse(response.getOptions().hasBlock1());
		assertEquals(payload, response.getResponseText());
		assertEquals(1, resource.getCounter());
		client.shutdown();
	}

	/**
	 * Perform POST Block-Wise request with Block-Wise response.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testOscoreBlockwisePost() throws Exception {
		setClientContext(uri);
		String payload = createRandomPayload(DEFAULT_BLOCK_SIZE * 4);
		Request request = Request.newPost().setURI(uri);
		request.getOptions().setOscore(Bytes.EMPTY);
		request.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		request.getOptions().setAccept(MediaTypeRegistry.TEXT_PLAIN);
		request.setPayload(payload);

		CoapClient client = new CoapClient();
		CoapResponse response = client.advanced(request);
		assertNotNull(response);
		assertEquals(response.getCode(), CoAP.ResponseCode.CONTENT);
		assertTrue(response.getOptions().hasSize2());
		assertFalse(response.getOptions().hasBlock1());
		assertEquals(this.payload + payload, response.getResponseText());
		assertEquals(this.payload + payload, resource.currentPayload);
		assertEquals(1, resource.getCounter());
		client.shutdown();
	}

	/**
	 * Perform PUT Block-Wise request with normal response.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testOscoreBlockwisePut() throws Exception {
		setClientContext(uri);
		String payload = createRandomPayload(DEFAULT_BLOCK_SIZE * 4);
		Request request = Request.newPut().setURI(uri);
		request.getOptions().setOscore(Bytes.EMPTY);
		request.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		request.getOptions().setAccept(MediaTypeRegistry.TEXT_PLAIN);
		request.setPayload(payload);

		CoapClient client = new CoapClient();
		CoapResponse response = client.advanced(request);
		assertNotNull(response);
		assertEquals(response.getCode(), CoAP.ResponseCode.CHANGED);
		assertFalse(response.getOptions().hasSize2());
		assertTrue(response.getOptions().hasBlock1());
		assertEquals(0, response.getPayloadSize());
		assertEquals(payload, resource.currentPayload);
		assertEquals(1, resource.getCounter());
		client.shutdown();
	}

	@Rule
	public ExpectedException exceptionRule = ExpectedExceptionWrapper.none();

	/**
	 * Perform a PUT request that is not sent with (inner) block-wise even
	 * though it is exceeding the configured MAX_UNFRAGMENTED_SIZE parameter.
	 * This means that transmission of the request should be rejected by the
	 * Object Security Layer.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testOscoreExceedMaxUnfragmentedSize() throws Exception {
		exceptionRule.expect(IOException.class);
		exceptionRule.expectMessage(
				"java.lang.IllegalStateException: outgoing request is exceeding the MAX_UNFRAGMENTED_SIZE!");

		setClientContext(uri);
		OSCoreCtx ctx = dbClient.getContext(uri);
		ctx.setMaxUnfragmentedSize(DEFAULT_BLOCK_SIZE / 2); // Restrict size

		String payload = createRandomPayload(DEFAULT_BLOCK_SIZE);
		Request request = Request.newPut().setURI(uri);
		request.getOptions().setOscore(Bytes.EMPTY);
		request.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		request.getOptions().setAccept(MediaTypeRegistry.TEXT_PLAIN);
		request.setPayload(payload);

		CoapClient client = new CoapClient();
		client.advanced(request);
		client.shutdown();
	}

	public void setClientContext(String serverUri) {
		// Set up OSCORE context information for request (client)
		byte[] sid = Bytes.EMPTY;
		byte[] rid = new byte[] { 0x01 };

		try {
			OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null);
			dbClient.addContext(serverUri, ctx);
		} catch (OSException e) {
			System.err.println("Failed to set client OSCORE Context information!");
		}
	}

	public void setServerContext() {
		// Set up OSCORE context information for response (server)
		byte[] sid = new byte[] { 0x01 };
		byte[] rid = Bytes.EMPTY;

		try {
			OSCoreCtx ctx_B = new OSCoreCtx(master_secret, false, alg, sid, rid, kdf, 32, master_salt, null);
			dbServer.addContext(ctx_B);
		} catch (OSException e) {
			System.err.println("Failed to set server OSCORE Context information!");
		}
	}

	private void createOscoreServer(MatcherMode mode) {

		setServerContext();

		// retransmit constantly all 200 milliseconds
		NetworkConfig config = network.createTestConfig().setInt(Keys.ACK_TIMEOUT, 200)
				.setFloat(Keys.ACK_RANDOM_FACTOR, 1f).setFloat(Keys.ACK_TIMEOUT_SCALE, 1f)
				// set response timeout (indirect) to 10s
				.setLong(Keys.EXCHANGE_LIFETIME, 10 * 1000L).setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE)
				.setInt(Keys.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE).setString(Keys.RESPONSE_MATCHING, mode.name());
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setNetworkConfig(config);
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		builder.setCustomCoapStackArgument(dbServer);
		CoapEndpoint serverEndpoint = builder.build();

		CoapServer server = new CoapServer();
		cleanup.add(server);
		server.addEndpoint(serverEndpoint);
		resource = new MyResource(TARGET);
		server.add(resource);
		server.start();

		uri = TestTools.getUri(serverEndpoint, TARGET);

		builder = new CoapEndpoint.Builder();
		builder.setNetworkConfig(config);
		EndpointManager.getEndpointManager().setDefaultEndpoint(builder.build());
	}

	private static String createRandomPayload(int size) {
		StringBuilder builder = new StringBuilder(size);
		Random random = new Random(size);
		for (int i = 0; i < size; ++i) {
			builder.append(random.nextInt(10));
		}
		return builder.toString();
	}

	private static class MyResource extends CoapResource {

		/**
		 * Request counter. Ensure, that transparent blockwise is not accidently
		 * split into "intermediary block" requests.
		 */
		private final AtomicInteger counter = new AtomicInteger();
		private volatile String currentPayload;

		public MyResource(String name) {
			super(name);
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			counter.incrementAndGet();
			Response response = new Response(ResponseCode.CONTENT);
			response.setPayload(currentPayload);
			exchange.respond(response);
		}

		@Override
		public void handlePUT(CoapExchange exchange) {
			counter.incrementAndGet();
			currentPayload = exchange.getRequestText();
			Response response = new Response(ResponseCode.CHANGED);
			exchange.respond(response);
		}

		@Override
		public void handlePOST(CoapExchange exchange) {
			counter.incrementAndGet();
			currentPayload += exchange.getRequestText();
			Response response = new Response(ResponseCode.CONTENT);
			response.setPayload(currentPayload);
			exchange.respond(response);
		}

		public void setPayload(String payload) {
			currentPayload = payload;
		}

		public int getCounter() {
			return counter.get();
		}
	}
}
