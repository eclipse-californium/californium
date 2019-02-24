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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation.
 ******************************************************************************/
package org.eclipse.californium.integration.test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointContextMatcherFactory.MatcherMode;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.integration.test.util.CoapsNetworkRule;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Medium.class)
public class SecureBlockwiseTest {

	@ClassRule
	public static CoapsNetworkRule network = new CoapsNetworkRule(CoapsNetworkRule.Mode.DIRECT,
			CoapsNetworkRule.Mode.NATIVE);

	private static final int DEFAULT_BLOCK_SIZE = 64;

	static final int TIMEOUT_IN_MILLIS = 5000;
	static final int REPEATS = 3;
	static final String TARGET = "resource";
	static final String IDENITITY = "client1";
	static final String KEY = "key1";

	private CoapServer server;
	private TestUtilPskStore pskStore;
	private DTLSConnector serverConnector;
	private DTLSConnector clientConnector;
	private CoapEndpoint serverEndpoint;
	private CoapEndpoint clientEndpoint;
	private MyResource resource;

	private String uri;
	private String payload;

	@Before
	public void startupServer() {
		System.out.println(System.lineSeparator() + "Start " + getClass().getSimpleName());
		payload = createRandomPayload(DEFAULT_BLOCK_SIZE * 4);
		createSecureServer(MatcherMode.STRICT);
		resource.setPayload(payload);
	}

	@After
	public void shutdownServer() {
		server.destroy();
		EndpointManager.reset();
		System.out.println("End " + getClass().getSimpleName());
	}

	@Test
	public void testSecureBlockwiseGet() throws Exception {
		CoapClient client = new CoapClient(uri);
		CoapResponse response = client.get();
		assertThat(response, is(notNullValue()));
		assertThat(response.getCode(), is(CoAP.ResponseCode.CONTENT));
		assertThat(response.getResponseText(), is(payload));
		assertThat(resource.getCounter(), is(1));
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
	}

	private void createSecureServer(MatcherMode mode) {
		pskStore = new TestUtilPskStore(IDENITITY, KEY.getBytes());
		DtlsConnectorConfig dtlsConfig = new DtlsConnectorConfig.Builder()
				.setAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
				.setLoggingTag("server")
				.setReceiverThreadCount(2)
				.setConnectionThreadCount(2)
				.setPskStore(pskStore).build();
		// retransmit constantly all 200 milliseconds
		NetworkConfig config = network.createTestConfig().setInt(Keys.ACK_TIMEOUT, 200)
				.setFloat(Keys.ACK_RANDOM_FACTOR, 1f).setFloat(Keys.ACK_TIMEOUT_SCALE, 1f)
				// set response timeout (indirect) to 10s
				.setLong(Keys.EXCHANGE_LIFETIME, 10 * 1000L).setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE)
				.setInt(Keys.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE)
				.setString(Keys.RESPONSE_MATCHING, mode.name());
		serverConnector = new DTLSConnector(dtlsConfig);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setConnector(serverConnector);
		builder.setNetworkConfig(config);
		serverEndpoint = builder.build();

		server = new CoapServer();
		server.addEndpoint(serverEndpoint);
		resource = new MyResource(TARGET);
		server.add(resource);
		server.start();

		uri = serverEndpoint.getUri() + "/" + TARGET;

		// prepare secure client endpoint
		DtlsConnectorConfig clientdtlsConfig = new DtlsConnectorConfig.Builder()
				.setAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
				.setLoggingTag("client")
				.setReceiverThreadCount(2)
				.setConnectionThreadCount(2)
				.setPskStore(pskStore).build();
		clientConnector = new DTLSConnector(clientdtlsConfig);
		builder = new CoapEndpoint.Builder();
		builder.setConnector(clientConnector);
		builder.setNetworkConfig(config);
		clientEndpoint = builder.build();
		EndpointManager.getEndpointManager().setDefaultEndpoint(clientEndpoint);
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
