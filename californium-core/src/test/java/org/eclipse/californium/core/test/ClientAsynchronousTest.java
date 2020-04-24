/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Bosch Software Innovations GmbH - refactor into separate test cases, remove
 *                                      wait cycles
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CoapNetworkRule for
 *                                                    setup of test-network
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix race condition with
 *                                                    reordered notifications
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.util.List;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Medium.class)
public class ClientAsynchronousTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	@ClassRule
	public static CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	public static final String TARGET = "storage";
	public static final String CONTENT_1 = "one";
	public static final String CONTENT_2 = "two";
	public static final String QUERY_UPPER_CASE = "uppercase";

	private static Endpoint serverEndpoint;
	private static String uri;

	private static StorageResource resource;

	private CoapClient client;

	@BeforeClass
	public static void init() {
		network.getStandardTestConfig()
			.setLong(NetworkConfig.Keys.MAX_TRANSMIT_WAIT, 100);
		cleanup.add(createServer());
	}

	@Before
	public void startupClient() {
		resource.setContent(CONTENT_1);
		client = new CoapClient(uri).useExecutor();
	}

	@After
	public void shutdownClient() {
		client.shutdown();
	}

	@Test
	public void testAsyncGetTriggersOnLoad() throws Exception {
		CountingCoapHandler handler = new CountingCoapHandler() {
			@Override
			public void assertLoad(CoapResponse response) {
				assertEquals(CONTENT_1, response.getResponseText());
			}
		};
		// Check that we get the right content when calling get()
		client.get(handler);
		assertTrue(handler.waitOnLoadCalls(1, 1, TimeUnit.SECONDS));
	}

	@Test
	public void testAsyncPostUpdatesResource() throws Exception {
		CountingCoapHandler handler = new CountingCoapHandler() {
			@Override
			public void assertLoad(CoapResponse response) {
				assertEquals(CONTENT_1, response.getResponseText());
			}
		};
		// Change the content to "two" and check
		client.post(handler, CONTENT_2, MediaTypeRegistry.TEXT_PLAIN);
		assertTrue(handler.waitOnLoadCalls(1, 1, TimeUnit.SECONDS));
		assertThat(resource.getContent(), is(CONTENT_2));
	}

	@Test
	public void testAsyncObserveTriggersOnLoad() throws Exception {
		CountingCoapHandler handler = new CountingCoapHandler() {
			@Override
			public void assertLoad(CoapResponse response) {
				assertThat(response.getResponseText(), startsWith(CONTENT_1));
				assertTrue(response.advanced().getOptions().hasObserve());
			}
		};

		// Observe the resource
		CoapObserveRelation obs1 = client.observe(handler);

		assertTrue("missing notifications", handler.waitOnLoadCalls(1, 2000, TimeUnit.MILLISECONDS));

		System.err.println("changed 1");
		resource.setContent(CONTENT_1 + " - 1");
		resource.changed();

		assertTrue("missing notifications", handler.waitOnLoadCalls(2, 2000, TimeUnit.MILLISECONDS));

		System.err.println("changed 2");
		resource.setContent(CONTENT_1 + " - 2");
		resource.changed();

		assertTrue("missing notifications", handler.waitOnLoadCalls(3, 2000, TimeUnit.MILLISECONDS));

		System.err.println("changed 3");
		resource.setContent(CONTENT_1 + " - 3");
		resource.changed();

		assertTrue("missing notifications", handler.waitOnLoadCalls(4, 2000, TimeUnit.MILLISECONDS));
		obs1.reactiveCancel();
		resource.changed();
		Thread.sleep(50);
		assertThat("unexpected notifications", handler.getOnLoadCalls(), is(4));
	}

	@Test
	public void testAsyncPutIsNotAllowed() throws Exception {
		CountingCoapHandler handler = new CountingCoapHandler() {
			@Override
			public void assertLoad(CoapResponse response) {
				assertEquals(ResponseCode.METHOD_NOT_ALLOWED, response.getCode());
			}
		};

		// Try a put and receive a METHOD_NOT_ALLOWED
		client.put(handler, CONTENT_2, MediaTypeRegistry.TEXT_PLAIN);
		assertTrue(handler.waitOnLoadCalls(1, 1, TimeUnit.SECONDS));
	}

	@Test
	public void testAsyncGetUsingBuilder() throws Exception {
		CountingCoapHandler handler = new CountingCoapHandler() {
			@Override
			public void assertLoad(CoapResponse response) {
				assertEquals(CONTENT_1.toUpperCase(), response.getResponseText());
			}
		};

		// Try to use the builder and add a query
		String uri = client.getURI() + "?" + QUERY_UPPER_CASE;
		client.setURI(uri);
		client.get(handler);

		assertTrue(handler.waitOnLoadCalls(1, 1, TimeUnit.SECONDS));
	}

	@Test
	public void testAdvancedUsesTypeFromRequest() throws Exception {
		CountingCoapHandler handler = new CountingCoapHandler();

		// But expecting CONs as specified in request
		client.useNONs();

		Request request = new Request(Code.GET, Type.CON);
		// Try a put and receive a METHOD_NOT_ALLOWED
		client.advanced(handler, request);

		assertTrue(handler.waitOnLoadCalls(1, 1, TimeUnit.SECONDS));
	}

	@Test
	public void testAdvancedUsesUriFromRequest() throws Exception {
		String unexistingUri = TestTools.getUri(serverEndpoint, "unexisting");
		client.setURI(unexistingUri);
		CountingCoapHandler handler = new CountingCoapHandler();

		Request request = new Request(Code.GET, Type.CON);
		request.setURI(uri);

		// Try a put and receive a METHOD_NOT_ALLOWED
		client.advanced(handler, request);

		assertTrue(handler.waitOnLoadCalls(1, 1, TimeUnit.SECONDS));
	}

	private static CoapServer createServer() {
		NetworkConfig config = network.getStandardTestConfig();
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setNetworkConfig(config);
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		serverEndpoint = builder.build();

		resource = new StorageResource(TARGET, CONTENT_1);
		CoapServer server = new CoapServer(config);
		server.add(resource);

		server.addEndpoint(serverEndpoint);
		server.start();
		uri = TestTools.getUri(serverEndpoint, TARGET);
		return server;
	}

	private static class StorageResource extends CoapResource {

		private String content;

		public StorageResource(String name, String content) {
			super(name);
			this.content = content;
			setObservable(true);
		}

		public String getContent() {
			return content;
		}

		public void setContent(String content) {
			this.content = content;
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			List<String> queries = exchange.getRequestOptions().getUriQuery();
			String c = content;
			for (String q : queries) {
				if (QUERY_UPPER_CASE.equals(q)) {
					c = content.toUpperCase();
				}
			}

			exchange.respond(ResponseCode.CONTENT, c);
		}

		@Override
		public void handlePOST(CoapExchange exchange) {
			String old = this.content;
			this.content = exchange.getRequestText();
			exchange.respond(ResponseCode.CHANGED, old);
			changed();
		}
	}
}
