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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add test for ping()
 ******************************************************************************/
package org.eclipse.californium.core.test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Assert;
import org.eclipse.californium.TestTools;
import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
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
import org.eclipse.californium.core.network.interceptors.MessageInterceptorAdapter;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Medium.class)
public class ClientSynchronousTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	private static final String TARGET = "storage";
	private static final String CONTENT_1 = "one";
	private static final String CONTENT_2 = "two";
	private static final String CONTENT_3 = "three";
	private static final String CONTENT_4 = "four";
	private static final String QUERY_UPPER_CASE = "uppercase";

	private static CoapServer server;
	private static Endpoint serverEndpoint;
	private static int serverPort;
	private static StorageResource resource;

	private String expected;
	private AtomicInteger notifications = new AtomicInteger();
	private boolean failed = false;

	@BeforeClass
	public static void startupServer() {
		network.getStandardTestConfig().setLong(NetworkConfig.Keys.MAX_TRANSMIT_WAIT, 100);
		createServer();
		System.out.println(System.lineSeparator() + "Start " + ClientSynchronousTest.class.getSimpleName() +
				" on " + serverEndpoint.getAddress());
	}

	@Before
	public void resetResource() {
		resource.reset();
	}

	@AfterClass
	public static void shutdownServer() {
		server.destroy();
		System.out.println("End " + ClientSynchronousTest.class.getSimpleName());
	}

	@Test
	public void testSynchronousCall() throws Exception {

		String uri = TestTools.getUri(serverEndpoint, TARGET);
		CoapClient client = new CoapClient(uri).useExecutor();

		// Check that we get the right content when calling get()
		String resp1 = client.get().getResponseText();
		Assert.assertEquals(CONTENT_1, resp1);

		String resp2 = client.get().getResponseText();
		Assert.assertEquals(CONTENT_1, resp2);

		// Change the content to "two" and check
		String resp3 = client.post(CONTENT_2, MediaTypeRegistry.TEXT_PLAIN).getResponseText();
		Assert.assertEquals(CONTENT_1, resp3);

		String resp4 = client.get().getResponseText();
		Assert.assertEquals(CONTENT_2, resp4);

		// Observe the resource
		expected = CONTENT_2;
		CoapObserveRelation obs1 = client.observeAndWait(
			new CoapHandler() {
				@Override public void onLoad(CoapResponse response) {
					notifications.incrementAndGet();
					String payload = response.getResponseText();
					Assert.assertEquals(expected, payload);
					Assert.assertTrue(response.advanced().getOptions().hasObserve());
				}
				@Override public void onError() {
					failed = true;
					Assert.assertTrue(false);
				}
			});
		Assert.assertFalse(obs1.isCanceled());

		Thread.sleep(100);
		resource.changed();
		Thread.sleep(100);
		resource.changed();
		Thread.sleep(100);
		resource.changed();

		Thread.sleep(100);
		expected = CONTENT_3;
		String resp5 = client.post(CONTENT_3, MediaTypeRegistry.TEXT_PLAIN).getResponseText();
		Assert.assertEquals(CONTENT_2, resp5);

		// Try a put and receive a METHOD_NOT_ALLOWED
		ResponseCode code6 = client.put(CONTENT_4, MediaTypeRegistry.TEXT_PLAIN).getCode();
		Assert.assertEquals(ResponseCode.METHOD_NOT_ALLOWED, code6);

		// Cancel observe relation of obs1 and check that it does no longer receive notifications
		Thread.sleep(100);
		expected = null; // The next notification would now cause a failure
		obs1.reactiveCancel();
		Thread.sleep(100);
		resource.changed();

		// Make another post
		Thread.sleep(100);
		String resp7 = client.post(CONTENT_4, MediaTypeRegistry.TEXT_PLAIN).getResponseText();
		Assert.assertEquals(CONTENT_3, resp7);

		// Try to use the builder and add a query
		String resp8 = new CoapClient.Builder("localhost", serverPort)
			.path(TARGET).query(QUERY_UPPER_CASE).create().get().getResponseText();
		Assert.assertEquals(CONTENT_4.toUpperCase(), resp8);

		// Check that we indeed received 5 notifications
		// 1 from origin GET request, 3 x from changed(), 1 from post()
		Thread.sleep(100);
		Assert.assertEquals(5, notifications.get());
		Assert.assertFalse(failed);
	}

	@Test
	public void testSynchronousPing() throws Exception {
		final AtomicBoolean sent = new AtomicBoolean();
		CoapEndpoint clientEndpoint = new CoapEndpoint(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
		clientEndpoint.addInterceptor(new MessageInterceptorAdapter() {
			
			@Override
			public void sendRequest(Request request) {
				sent.set(true);
			}
		});
		
		String uri = TestTools.getUri(serverEndpoint, TARGET);
		CoapClient client = new CoapClient(uri).useExecutor();
		client.setEndpoint(clientEndpoint);
		
		// Check that we get the right content when calling get()
		boolean ping = client.ping();
		Assert.assertTrue(ping);
		Assert.assertTrue("Ping not sent using provided endpoint", sent.get());
	}

	@Test
	public void testAdvancedUsesTypeFromRequest() throws Exception {

		String uri = TestTools.getUri(serverEndpoint, TARGET);
		CoapClient client = new CoapClient(uri).useExecutor();

		// Set NONs but expecting CONs as specified in request
		client.useNONs();

		Request request = new Request(Code.GET, Type.CON);

		CoapResponse resp = client.advanced(request);

		Assert.assertEquals(Type.ACK, resp.advanced().getType());
		Assert.assertEquals(CONTENT_1, resp.getResponseText());
	}

	@Test
	public void testAdvancedUsesUriFromRequest() throws Exception {

		String nonExistingUri = TestTools.getUri(serverEndpoint, "non-existing");
		CoapClient client = new CoapClient(nonExistingUri).useExecutor();

		Request request = new Request(Code.GET, Type.CON);
		String uri = TestTools.getUri(serverEndpoint, TARGET);
		request.setURI(uri);

		CoapResponse resp = client.advanced(request);

		Assert.assertEquals(Type.ACK, resp.advanced().getType());
		Assert.assertEquals(CONTENT_1, resp.getResponseText());
	}

	private static void createServer() {

		serverEndpoint = new CoapEndpoint(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));

		resource = new StorageResource(TARGET, CONTENT_1);
		server = new CoapServer();
		server.add(resource);

		server.addEndpoint(serverEndpoint);
		server.start();
		serverPort = serverEndpoint.getAddress().getPort();
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
			List<String> queries = exchange.getRequestOptions().getUriQuery();
			String c = content;
			for (String q:queries) {
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

		public void reset() {
			content = originalContent;
		}
	}
}
