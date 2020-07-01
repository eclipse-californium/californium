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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add test for ping()
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.concurrent.atomic.AtomicBoolean;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageInterceptorAdapter;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Medium.class)
public class ClientSynchronousTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	@ClassRule
	public static CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final String TARGET = "storage";
	private static final String CONTENT_1 = "one";
	private static final String CONTENT_2 = "two";
	private static final String CONTENT_3 = "three";
	private static final String CONTENT_4 = "four";
	private static final String QUERY_UPPER_CASE = "uppercase";
	private static final String OVERLOAD = "overload";
	private static final int OVERLOAD_TIME = 123;

	private static Endpoint serverEndpoint;
	private static StorageResource resource;

	@BeforeClass
	public static void startupServer() {
		network.getStandardTestConfig().setLong(NetworkConfig.Keys.MAX_TRANSMIT_WAIT, 100);
		CoapServer server = createServer();
		cleanup.add(server);
	}

	@Before
	public void resetResource() {
		resource.reset();
	}

	@Test
	public void testSynchronousCall() throws Exception {

		String uri = TestTools.getUri(serverEndpoint, TARGET);
		CoapClient client = new CoapClient(uri).useExecutor();
		cleanup.add(client);

		// Check that we get the right content when calling get()
		String resp1 = client.get().getResponseText();
		assertEquals(CONTENT_1, resp1);

		String resp2 = client.get().getResponseText();
		assertEquals(CONTENT_1, resp2);

		// Change the content to "two" and check
		String resp3 = client.post(CONTENT_2, MediaTypeRegistry.TEXT_PLAIN).getResponseText();
		assertEquals(CONTENT_1, resp3);

		String resp4 = client.get().getResponseText();
		assertEquals(CONTENT_2, resp4);

		CountingCoapHandler handler = new CountingCoapHandler();
		// Observe the resource
		CoapObserveRelation obs1 = client.observeAndWait(handler);
		assertFalse(obs1.isCanceled());
		CoapResponse response = handler.waitOnLoad(100);
		assertNotNull("missing initial notification", response);
		assertEquals(CONTENT_2, response.getResponseText());

		resource.changed();
		response = handler.waitOnLoad(100);
		assertNotNull("missing notification", response);
		assertEquals(CONTENT_2, response.getResponseText());

		resource.changed();
		response = handler.waitOnLoad(100);
		assertNotNull("missing notification", response);
		assertEquals(CONTENT_2, response.getResponseText());

		resource.changed();
		response = handler.waitOnLoad(100);
		assertNotNull("missing notification", response);
		assertEquals(CONTENT_2, response.getResponseText());

		String resp5 = client.post(CONTENT_3, MediaTypeRegistry.TEXT_PLAIN).getResponseText();
		assertEquals(CONTENT_2, resp5);

		response = handler.waitOnLoad(100);
		assertNotNull("missing notification", response);
		assertEquals(CONTENT_3, response.getResponseText());

		// Try a put and receive a METHOD_NOT_ALLOWED
		ResponseCode code6 = client.put(CONTENT_4, MediaTypeRegistry.TEXT_PLAIN).getCode();
		assertEquals(ResponseCode.METHOD_NOT_ALLOWED, code6);

		// Cancel observe relation of obs1 and check that it does no longer receive notifications
		obs1.reactiveCancel();
		resource.changed();
		response = handler.waitOnLoad(100);
		assertNull("unexpected notification", response == null ? null : response.getResponseText());

		// Make another post
		String resp7 = client.post(CONTENT_4, MediaTypeRegistry.TEXT_PLAIN).getResponseText();
		assertEquals(CONTENT_3, resp7);

		// Try to use the builder and add a query
		CoapClient client2 = new CoapClient.Builder("localhost", serverEndpoint.getAddress().getPort())
			.scheme("coap").path(TARGET).query(QUERY_UPPER_CASE).create();
		cleanup.add(client2);
		String resp8 = client2.get().getResponseText();
		assertEquals(CONTENT_4.toUpperCase(), resp8);

		// Check that we indeed received 5 notifications
		// 1 from origin GET request, 3 x from changed(), 1 from post()
		Thread.sleep(100);
		assertEquals(5, handler.getOnLoadCalls());
		assertEquals(0, handler.getOnErrorCalls());
		client2.shutdown();
		client.shutdown();
	}

	@Test
	public void testSynchronousPing() throws Exception {
		final AtomicBoolean sent = new AtomicBoolean();
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		CoapEndpoint clientEndpoint = builder.build();
		cleanup.add(clientEndpoint);
		clientEndpoint.addInterceptor(new MessageInterceptorAdapter() {

			@Override
			public void sendRequest(Request request) {
				sent.set(true);
			}
		});

		String uri = TestTools.getUri(serverEndpoint, TARGET);
		CoapClient client = new CoapClient(uri).useExecutor();
		cleanup.add(client);
		client.setEndpoint(clientEndpoint);

		// Check that we get the right content when calling get()
		boolean ping = client.ping();
		assertTrue(ping);
		assertTrue("Ping not sent using provided endpoint", sent.get());
		client.shutdown();
	}

	@Test
	public void testAdvancedUsesTypeFromRequest() throws Exception {

		String uri = TestTools.getUri(serverEndpoint, TARGET);
		CoapClient client = new CoapClient(uri).useExecutor();
		cleanup.add(client);

		// Set NONs but expecting CONs as specified in request
		client.useNONs();

		Request request = new Request(Code.GET, Type.CON);

		CoapResponse resp = client.advanced(request);

		assertEquals(Type.ACK, resp.advanced().getType());
		assertEquals(CONTENT_1, resp.getResponseText());
		client.shutdown();
	}

	@Test
	public void testAdvancedUsesUriFromRequest() throws Exception {

		String nonExistingUri = TestTools.getUri(serverEndpoint, "non-existing");
		CoapClient client = new CoapClient(nonExistingUri).useExecutor();
		cleanup.add(client);

		Request request = new Request(Code.GET, Type.CON);
		String uri = TestTools.getUri(serverEndpoint, TARGET);
		request.setURI(uri);

		CoapResponse resp = client.advanced(request);

		assertEquals(Type.ACK, resp.advanced().getType());
		assertEquals(CONTENT_1, resp.getResponseText());
		client.shutdown();
	}

	@Test
	public void testOverloadResponse() throws Exception {

		String uri = TestTools.getUri(serverEndpoint, TARGET);
		CoapClient client = new CoapClient(uri).useExecutor();
		cleanup.add(client);

		CoapResponse resp = client.post(OVERLOAD, MediaTypeRegistry.TEXT_PLAIN);

		assertEquals(ResponseCode.SERVICE_UNAVAILABLE, resp.getCode());
		assertEquals(OVERLOAD_TIME, resp.getOptions().getMaxAge().intValue());
		client.shutdown();
	}

	private static CoapServer createServer() {
		NetworkConfig config = network.getStandardTestConfig();
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		builder.setNetworkConfig(config);
		serverEndpoint = builder.build();

		resource = new StorageResource(TARGET, CONTENT_1);
		CoapServer server = new CoapServer(config);
		server.add(resource);

		server.addEndpoint(serverEndpoint);
		server.start();
		return server;
	}

	private static class StorageResource extends CoapResource {

		private final String originalContent;
		private String content;

		public StorageResource(String name, String content) {
			super(name);
			this.originalContent = content;
			this.content = content;
			setObservable(true);
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			String c = content;
			if (exchange.getQueryParameter(QUERY_UPPER_CASE) != null) {
				c = content.toUpperCase();
			}
			exchange.respond(ResponseCode.CONTENT, c);
		}

		@Override
		public void handlePOST(CoapExchange exchange) {
			String requestText = exchange.getRequestText();
			if (requestText.equals(OVERLOAD)) {
				exchange.respondOverload(OVERLOAD_TIME);
				return;
			}
			String old = this.content;
			this.content = requestText;
			// call changed before response, otherwise there may be a race-condition
			// if a future observe get processed before the changed().
			changed();
			exchange.respond(ResponseCode.CHANGED, old);
		}

		public void reset() {
			content = originalContent;
		}
	}
}
