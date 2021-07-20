/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation.
 ******************************************************************************/
package org.eclipse.californium.integration.test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.config.CoapConfig.MatcherMode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.integration.test.util.CoapsNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedPskStore;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedSinglePskStore;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Medium.class)
public class SecureBlockwiseTest {

	@ClassRule
	public static CoapsNetworkRule network = new CoapsNetworkRule(CoapsNetworkRule.Mode.DIRECT,
			CoapsNetworkRule.Mode.NATIVE);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final int DEFAULT_BLOCK_SIZE = 64;

	static final int TIMEOUT_IN_MILLIS = 5000;
	static final int REPEATS = 3;
	static final String TARGET = "resource";
	static final String IDENITITY = "client1";
	static final String KEY = "key1";

	private MyResource resource;

	private String uri;
	private String payload;

	@Before
	public void startupServer() {
		payload = createRandomPayload(DEFAULT_BLOCK_SIZE * 4);
		createSecureServer(MatcherMode.STRICT);
		resource.setPayload(payload);
	}

	@Test
	public void testSecureBlockwiseGet() throws Exception {
		CoapClient client = new CoapClient(uri);
		CoapResponse response = client.get();
		assertThat(response, is(notNullValue()));
		assertThat(response.getCode(), is(CoAP.ResponseCode.CONTENT));
		assertThat(response.getResponseText(), is(payload));
		assertThat(resource.getCounter(), is(1));
		client.shutdown();
	}

	@Test
	public void testSecureBlockwisePut() throws Exception {
		String payload = createRandomPayload(DEFAULT_BLOCK_SIZE * 4);
		CoapClient client = new CoapClient(uri);
		CoapResponse response = client.put(payload, MediaTypeRegistry.TEXT_PLAIN);
		assertThat(response, is(notNullValue()));
		assertThat(response.getCode(), is(CoAP.ResponseCode.CHANGED));
		assertThat(resource.currentPayload, is(payload));
		assertThat(resource.getCounter(), is(1));
		client.shutdown();
	}

	@Test
	public void testSecureBlockwisePost() throws Exception {
		String payload = createRandomPayload(DEFAULT_BLOCK_SIZE * 4);
		CoapClient client = new CoapClient(uri);
		CoapResponse response = client.post(payload, MediaTypeRegistry.TEXT_PLAIN, MediaTypeRegistry.TEXT_PLAIN);
		assertThat(response, is(notNullValue()));
		assertThat(response.getCode(), is(CoAP.ResponseCode.CONTENT));
		assertThat(response.getResponseText(), is(this.payload + payload));
		assertThat(resource.currentPayload, is(this.payload + payload));
		assertThat(resource.getCounter(), is(1));
		client.shutdown();
	}

	private void createSecureServer(MatcherMode mode) {
		AdvancedPskStore pskStore = new AdvancedSinglePskStore(IDENITITY, KEY.getBytes());
		Configuration configuration = network.createTestConfig()
				// retransmit constantly all 200 milliseconds
				.set(CoapConfig.ACK_TIMEOUT, 200, TimeUnit.MILLISECONDS)
				.set(CoapConfig.ACK_INIT_RANDOM, 1f)
				.set(CoapConfig.ACK_TIMEOUT_SCALE, 1f)
				// set response timeout (indirect) to 10s
				.set(CoapConfig.EXCHANGE_LIFETIME, 10, TimeUnit.SECONDS)
				.set(CoapConfig.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE)
				.set(CoapConfig.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE)
				.set(CoapConfig.RESPONSE_MATCHING, mode)
				.set(DtlsConfig.DTLS_RECEIVER_THREAD_COUNT, 2)
				.set(DtlsConfig.DTLS_CONNECTOR_THREAD_COUNT, 2);
		
		DtlsConnectorConfig dtlsConfig = DtlsConnectorConfig.builder(configuration)
				.setAddress(TestTools.LOCALHOST_EPHEMERAL)
				.setLoggingTag("server")
				.setAdvancedPskStore(pskStore).build();

		DTLSConnector serverConnector = new DTLSConnector(dtlsConfig);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setConnector(serverConnector);
		builder.setConfiguration(configuration);
		CoapEndpoint serverEndpoint = builder.build();

		CoapServer server = new CoapServer();
		cleanup.add(server);
		server.addEndpoint(serverEndpoint);
		resource = new MyResource(TARGET);
		server.add(resource);
		server.start();

		uri = TestTools.getUri(serverEndpoint, TARGET);

		// prepare secure client endpoint
		DtlsConnectorConfig clientdtlsConfig = DtlsConnectorConfig.builder(configuration)
				.setAddress(TestTools.LOCALHOST_EPHEMERAL)
				.setLoggingTag("client")
				.setAdvancedPskStore(pskStore).build();
		DTLSConnector clientConnector = new DTLSConnector(clientdtlsConfig);
		builder = new CoapEndpoint.Builder();
		builder.setConnector(clientConnector);
		builder.setConfiguration(configuration);
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
