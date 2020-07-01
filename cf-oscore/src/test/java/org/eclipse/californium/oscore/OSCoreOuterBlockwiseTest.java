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
 *    Rikard Höglund (RISE SICS) - testing OSCORE outer Block-Wise messages
 ******************************************************************************/
package org.eclipse.californium.oscore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.URI;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointContextMatcherFactory.MatcherMode;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.proxy2.Coap2CoapTranslator;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Class for testing OSCORE together with Block-Wise requests and responses.
 * This is for testing the "outer Block-Wise" mode of OSCORE where an OSCORE
 * messages is fragmented into blocks by a proxy. See
 * https://tools.ietf.org/html/rfc8613#section-4.1.3.4.2
 * 
 * The test class contains a server, client and proxy. The client will not be
 * using block-wise with the proxy, however the proxy will split requests from
 * the server and use block-wise towards the server. The proxy is also unaware
 * of OSCORE.
 * 
 * The tests cover POST, PUT and GET methods. It tests Block-Wise requests with
 * Block-Wise responses, Block-Wise requests with normal responses and normal
 * requests with Block-Wise responses.
 * 
 * It also tests messages that use outer block-wise and their cumulative payload
 * size exceeds the MAX_UNFRAGMENTED_SIZE meaning they should be rejected.
 * 
 */
@Category(Medium.class)
public class OSCoreOuterBlockwiseTest {

	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final int DEFAULT_BLOCK_SIZE = 32;
	static final int TIMEOUT_IN_MILLIS = 5000;
	static final String TARGET = "resource";

	static final boolean USE_OSCORE = true;

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

	private String serverUri;
	private String proxyUri;
	private String payload;

	private static MatcherMode mode = MatcherMode.STRICT;

	private static NetworkConfig blockwiseConfig;

	public void startupServer(boolean serverResponseBlockwiseEnabled) {
		payload = createRandomPayload(DEFAULT_BLOCK_SIZE * 4);
		createOscoreServer(serverResponseBlockwiseEnabled);
		resource.setPayload(payload);
	}

	public void startupProxy(boolean proxyRequestBlockwiseEnabled, boolean proxyResponseBlockwiseEnabled) {
		createSimpleProxy(proxyRequestBlockwiseEnabled, proxyResponseBlockwiseEnabled);
	}

	/**
	 * Create network config to apply when building endpoints to enable
	 * block-wise transfers (for messages exceeding DEFAULT_BLOCK_SIZE)
	 */
	@BeforeClass
	public static void createBlockwiseConfig() {
		blockwiseConfig = network.createTestConfig().setInt(Keys.ACK_TIMEOUT, 200).setFloat(Keys.ACK_RANDOM_FACTOR, 1f)
				.setFloat(Keys.ACK_TIMEOUT_SCALE, 1f)
				// set response timeout (indirect) to 10s
				.setLong(Keys.EXCHANGE_LIFETIME, 10 * 1000L).setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE)
				.setInt(Keys.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE).setString(Keys.RESPONSE_MATCHING, mode.name());
	}

	/**
	 * Perform GET request via proxy with small response payload. No block-wise
	 * messages involved.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testProxySmallGet() throws Exception {
		startupServer(false);
		startupProxy(false, false);
		setClientContext(serverUri);

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());
		builder.setCustomCoapStackArgument(dbClient);
		CoapEndpoint clientEndpoint = builder.build();

		String responsePayload = "test";
		resource.setPayload(responsePayload);

		Request request = Request.newGet().setURI(proxyUri);
		request.getOptions().setProxyUri(serverUri);
		if (USE_OSCORE) {
			request.getOptions().setOscore(Bytes.EMPTY);
		}

		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);
		cleanup.add(clientEndpoint);
		CoapResponse response = client.advanced(request);
		System.out.println(Utils.prettyPrint(response));
		assertNotNull(response);
		assertEquals(CoAP.ResponseCode.CONTENT, response.getCode());
		assertFalse(response.getOptions().hasSize2());
		assertFalse(response.getOptions().hasBlock1());
		assertEquals(responsePayload, response.getResponseText());
		assertEquals(1, resource.getCounter());
		client.shutdown();
	}

	/**
	 * Perform GET request via proxy with large response payload. No block-wise
	 * messages involved.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testProxyLargeGet() throws Exception {
		startupServer(false);
		startupProxy(false, false);
		setClientContext(serverUri);

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());
		builder.setCustomCoapStackArgument(dbClient);
		CoapEndpoint clientEndpoint = builder.build();

		Request request = Request.newGet().setURI(proxyUri);
		request.getOptions().setProxyUri(serverUri);
		if (USE_OSCORE) {
			request.getOptions().setOscore(Bytes.EMPTY);
		}

		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);
		cleanup.add(clientEndpoint);
		CoapResponse response = client.advanced(request);
		System.out.println(Utils.prettyPrint(response));
		assertNotNull(response);
		assertEquals(CoAP.ResponseCode.CONTENT, response.getCode());
		assertFalse(response.getOptions().hasSize2());
		assertFalse(response.getOptions().hasBlock1());
		assertEquals(payload, response.getResponseText());
		assertEquals(1, resource.getCounter());
		client.shutdown();
	}

	/**
	 * Perform POST request via proxy with large request and response payload.
	 * The proxy->server request will be Block-Wise.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testOuterBlockwisePostProxyServerBW() throws Exception {
		startupServer(false);
		startupProxy(true, false);
		setClientContext(serverUri);

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());
		builder.setCustomCoapStackArgument(dbClient);
		CoapEndpoint clientEndpoint = builder.build();

		String payload = createRandomPayload(DEFAULT_BLOCK_SIZE * 4);
		Request request = Request.newPost().setURI(proxyUri);
		request.getOptions().setProxyUri(serverUri);
		if (USE_OSCORE) {
			request.getOptions().setOscore(Bytes.EMPTY);
		}
		request.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		request.getOptions().setAccept(MediaTypeRegistry.TEXT_PLAIN);
		request.setPayload(payload);

		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);
		cleanup.add(clientEndpoint);
		CoapResponse response = client.advanced(request);
		System.out.println(Utils.prettyPrint(response));
		assertNotNull(response);
		assertEquals(response.getCode(), CoAP.ResponseCode.CONTENT);
		assertFalse(response.getOptions().hasSize2());
		assertFalse(response.getOptions().hasBlock1());
		assertEquals(this.payload + payload, response.getResponseText());
		assertEquals(this.payload + payload, resource.currentPayload);
		assertEquals(1, resource.getCounter());
		client.shutdown();
	}

	/**
	 * Perform PUT Block-Wise request via proxy with large request payload and
	 * no response payload. The proxy->server request will be Block-Wise.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testOuterBlockwisePutProxyServerBW() throws Exception {
		startupServer(false);
		startupProxy(true, false);
		setClientContext(serverUri);

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());
		builder.setCustomCoapStackArgument(dbClient);
		CoapEndpoint clientEndpoint = builder.build();

		String payload = createRandomPayload(DEFAULT_BLOCK_SIZE * 4);
		Request request = Request.newPut().setURI(proxyUri);
		request.getOptions().setProxyUri(serverUri);
		if (USE_OSCORE) {
			request.getOptions().setOscore(Bytes.EMPTY);
		}
		request.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		request.getOptions().setAccept(MediaTypeRegistry.TEXT_PLAIN);
		request.setPayload(payload);

		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);
		cleanup.add(clientEndpoint);
		CoapResponse response = client.advanced(request);
		System.out.println(Utils.prettyPrint(response));
		assertNotNull(response);
		assertEquals(response.getCode(), CoAP.ResponseCode.CHANGED);
		assertFalse(response.getOptions().hasSize2());
		assertFalse(response.getOptions().hasBlock1());
		assertNull(response.getPayload());
		assertEquals(payload, resource.currentPayload);
		assertEquals(1, resource.getCounter());
		client.shutdown();
	}

	/**
	 * Perform GET request via proxy with large response payload. The
	 * proxy->client response will be Block-Wise.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testOuterBlockwiseGetProxyClientBW() throws Exception {
		startupServer(false);
		startupProxy(false, true);
		setClientContext(serverUri);

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());
		builder.setCustomCoapStackArgument(dbClient);
		CoapEndpoint clientEndpoint = builder.build();

		Request request = Request.newGet().setURI(proxyUri);
		request.getOptions().setProxyUri(serverUri);
		if (USE_OSCORE) {
			request.getOptions().setOscore(Bytes.EMPTY);
		}

		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);
		cleanup.add(clientEndpoint);
		CoapResponse response = client.advanced(request);
		System.out.println(Utils.prettyPrint(response));
		assertNotNull(response);
		assertEquals(CoAP.ResponseCode.CONTENT, response.getCode());
		assertFalse(response.getOptions().hasBlock1());
		assertFalse(response.getOptions().hasBlock2());
		assertEquals(payload, response.getResponseText());
		assertEquals(1, resource.getCounter());
		client.shutdown();
	}

	/**
	 * Perform POST request via proxy with large request and response payload.
	 * The proxy->client response will be Block-Wise.
	 *
	 * @throws Exception on test failure
	 */
	@Test
	public void testOuterBlockwisePostProxyClientBW() throws Exception {
		startupServer(false);
		startupProxy(false, true);
		setClientContext(serverUri);

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());
		builder.setCustomCoapStackArgument(dbClient);
		CoapEndpoint clientEndpoint = builder.build();

		String payload = createRandomPayload(DEFAULT_BLOCK_SIZE * 4);
		Request request = Request.newPost().setURI(proxyUri);
		request.getOptions().setProxyUri(serverUri);
		if (USE_OSCORE) {
			request.getOptions().setOscore(Bytes.EMPTY);
		}
		request.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		request.getOptions().setAccept(MediaTypeRegistry.TEXT_PLAIN);
		request.setPayload(payload);

		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);
		cleanup.add(clientEndpoint);
		CoapResponse response = client.advanced(request);
		System.out.println(Utils.prettyPrint(response));
		assertNotNull(response);
		assertEquals(response.getCode(), CoAP.ResponseCode.CONTENT);
		assertFalse(response.getOptions().hasBlock1());
		assertFalse(response.getOptions().hasBlock2());
		assertEquals(this.payload + payload, response.getResponseText());
		assertEquals(this.payload + payload, resource.currentPayload);
		assertEquals(1, resource.getCounter());
		client.shutdown();
	}

	/**
	 * Perform PUT request via proxy with large request payload that is
	 * exceeding the configured MAX_UNFRAGMENTED_SIZE parameter. Since the
	 * cumulative size of the request block messages exceed this limit and use
	 * outer block-wise its reception should be rejected by the server and a
	 * 4.13 response sent. The proxy->server request will be Block-Wise.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testOuterBlockwiseExceedMaxUnfragmentedSizeProxyServerBW() throws Exception {
		NetworkConfig config = NetworkConfig.getStandard();
		config.setInt(NetworkConfig.Keys.MAX_RETRANSMIT, 0); // Don't retransmit

		startupServer(false);
		startupProxy(true, false);
		setClientContext(serverUri);

		OSCoreCtx ctx = dbServer.getContext(Bytes.EMPTY);
		// Set acceptable cumulative request size.
		// The actual request will be DEFAULT_BLOCK_SIZE * 4
		ctx.setMaxUnfragmentedSize(DEFAULT_BLOCK_SIZE * 2);

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());
		builder.setCustomCoapStackArgument(dbClient);
		CoapEndpoint clientEndpoint = builder.build();

		String payload = createRandomPayload(DEFAULT_BLOCK_SIZE * 4);
		Request request = Request.newPut().setURI(proxyUri);
		request.getOptions().setProxyUri(serverUri);
		if (USE_OSCORE) {
			request.getOptions().setOscore(Bytes.EMPTY);
		}
		request.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		request.getOptions().setAccept(MediaTypeRegistry.TEXT_PLAIN);
		request.setPayload(payload);

		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);
		cleanup.add(clientEndpoint);
		CoapResponse response = client.advanced(request);

		System.out.println(Utils.prettyPrint(response));
		assertNotNull(response);
		assertEquals(response.getCode(), CoAP.ResponseCode.REQUEST_ENTITY_TOO_LARGE);
		assertFalse(response.getOptions().hasSize2());
		assertFalse(response.getOptions().hasBlock1());
		assertEquals(0, resource.getCounter());
		client.shutdown();
	}

	/**
	 * Perform GET request via proxy with large response payload that is
	 * exceeding the configured MAX_UNFRAGMENTED_SIZE parameter. Since the
	 * cumulative size of the response block messages exceed this limit and use
	 * outer block-wise its reception should be rejected by the client. The
	 * proxy->client response will be Block-Wise.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testOuterBlockwiseExceedMaxUnfragmentedSizeProxyClientBW() throws Exception {
		NetworkConfig config = NetworkConfig.getStandard();
		config.setInt(NetworkConfig.Keys.MAX_RETRANSMIT, 0); // Don't retransmit

		startupServer(false);
		startupProxy(false, true);
		setClientContext(serverUri);

		OSCoreCtx ctx = dbClient.getContext(serverUri);

		// Set acceptable cumulative response size.
		// The actual response will be DEFAULT_BLOCK_SIZE * 4
		ctx.setMaxUnfragmentedSize(DEFAULT_BLOCK_SIZE * 2);

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());
		builder.setCustomCoapStackArgument(dbClient);
		CoapEndpoint clientEndpoint = builder.build();

		Request request = Request.newGet().setURI(proxyUri);
		request.getOptions().setProxyUri(serverUri);
		if (USE_OSCORE) {
			request.getOptions().setOscore(Bytes.EMPTY);
		}

		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);
		cleanup.add(clientEndpoint);

		CoapResponse response = client.advanced(request);

		assertNull(response);
		assertEquals(1, resource.getCounter());
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

	/**
	 * Create a simple OSCORE server that supports block-wise.
	 * 
	 * @param serverResponseBlockwise the server responds with block-wise
	 */
	private void createOscoreServer(boolean serverResponseBlockwise) {

		setServerContext();

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		if (serverResponseBlockwise) {
			builder.setNetworkConfig(blockwiseConfig);
		}
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());
		builder.setCustomCoapStackArgument(dbServer);
		CoapEndpoint serverEndpoint = builder.build();

		CoapServer server = new CoapServer();
		cleanup.add(server);
		server.addEndpoint(serverEndpoint);
		resource = new MyResource(TARGET);
		server.add(resource);
		server.start();

		serverUri = TestTools.getUri(serverEndpoint, TARGET);
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

	/**
	 * Create simple non-OSCORE proxy.
	 * 
	 * @param proxyRequestBlockwise the proxy sends requests with block-wise
	 * @param proxyResponseBlockwiseEnabled the proxy responds with block-wise
	 */
	private void createSimpleProxy(final boolean proxyRequestBlockwise, final boolean proxyResponseBlockwiseEnabled) {

		final Coap2CoapTranslator coapTranslator = new Coap2CoapTranslator();

		// Create endpoint for proxy server side
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCoapStackFactory(CoapEndpoint.STANDARD_COAP_STACK_FACTORY);
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		if (proxyResponseBlockwiseEnabled) {
			builder.setNetworkConfig(blockwiseConfig);
		}

		CoapEndpoint proxyServerEndpoint = builder.build();
		
		// Create proxy
		CoapServer proxy = new CoapServer();
		cleanup.add(proxy);
		proxy.addEndpoint(proxyServerEndpoint);
		proxy.setMessageDeliverer(new MessageDeliverer() {

			@Override
			public void deliverRequest(Exchange exchange) {

				Response outgoingResponse = null;
				try {
					// Create and send request to the server based on the
					// incoming request from the client
					Request incomingRequest = exchange.getRequest();
					URI finalDestinationUri = coapTranslator.getDestinationURI(incomingRequest,
							coapTranslator.getExposedInterface(incomingRequest));
					Request outgoingRequest = coapTranslator.getRequest(finalDestinationUri, incomingRequest);

					CoapClient proxyClient = new CoapClient();

					// Create endpoint for proxy client side
					CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
					builder.setCoapStackFactory(CoapEndpoint.STANDARD_COAP_STACK_FACTORY);
					if (proxyRequestBlockwise) {
						builder.setNetworkConfig(blockwiseConfig);
					}
					CoapEndpoint proxyClientEndpoint = builder.build();
					proxyClient.setEndpoint(proxyClientEndpoint);
					cleanup.add(proxyClientEndpoint);

					// Now receive the response from the server and prepare the
					// final response to the client
					CoapResponse incomingResponse = proxyClient.advanced(outgoingRequest);
					outgoingResponse = coapTranslator.getResponse(incomingResponse.advanced());
				} catch (org.eclipse.californium.proxy2.TranslationException | ConnectorException | IOException e) {
					System.err.println("Processing on proxy failed.");
					e.printStackTrace();
					fail();
				}

				// Send response to client
				exchange.sendResponse(outgoingResponse);
			}

			@Override
			public void deliverResponse(Exchange exchange, Response response) {
				System.out.println("Proxy: Deliver response called.");
			}
		});

		proxy.start();
		proxyUri = TestTools.getUri(proxyServerEndpoint, "/");
	}

}
