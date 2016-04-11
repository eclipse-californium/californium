/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Bosch Software Innovations GmbH - refactor into separate test cases, remove
 *                                      wait cycles
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Medium.class)
public class ClientAsynchronousTest {

	public static final String TARGET = "storage";
	public static final String CONTENT_1 = "one";
	public static final String CONTENT_2 = "two";
	public static final String QUERY_UPPER_CASE = "uppercase";

	private static CoapServer server;
	private static InetSocketAddress serverAddress;
	private static String uri;

	private static StorageResource resource;

	private CoapClient client;
	private List<String> failed = new CopyOnWriteArrayList<String>();

	@BeforeClass
	public static void init() {
		System.out.println(System.lineSeparator() + "Start " + ClientAsynchronousTest.class.getSimpleName());
		NetworkConfig.getStandard()
			.setLong(NetworkConfig.Keys.MAX_TRANSMIT_WAIT, 100);
		createServer();
		uri = String.format("coap://%s:%d/%s", serverAddress.getHostString(), serverAddress.getPort(), TARGET);
	}

	@Before
	public void startupServer() {
		resource.setContent(CONTENT_1);
		client = new CoapClient(uri).useExecutor();
	}

	@After
	public void shutdownServer() {
	}

	@AfterClass
	public static void finish() {
		server.destroy();
		System.out.println("End " + ClientAsynchronousTest.class.getSimpleName());
	}

	@Test
	public void testAsyncGetTriggersOnLoad() throws Exception {
		final CountDownLatch latch = new CountDownLatch(1);
		// Check that we get the right content when calling get()
		client.get(new TestHandler("Test 1") {
			@Override public void onLoad(CoapResponse response) {
				if (CONTENT_1.equals(response.getResponseText())) {
					latch.countDown();
				}
			}
		});
		assertTrue(latch.await(1, TimeUnit.SECONDS));
	}

	@Test
	public void testAsyncPostUpdatesResource() throws Exception {
		final CountDownLatch latch = new CountDownLatch(1);

		// Change the content to "two" and check
		client.post(new TestHandler("Test 3") {
			@Override public void onLoad(CoapResponse response) {
				if (CONTENT_1.equals(response.getResponseText())) {
					latch.countDown();
				}
			}
		}, CONTENT_2, MediaTypeRegistry.TEXT_PLAIN);

		assertTrue(latch.await(1, TimeUnit.SECONDS));
		assertThat(resource.getContent(), is(CONTENT_2));
	}

	@Test
	public void testAsyncObserveTriggersOnLoad() throws Exception {
		final CountDownLatch latch = new CountDownLatch(1);
		final CountDownLatch expectedNotifications = new CountDownLatch(3);
		final AtomicInteger receivedNotifications = new AtomicInteger();

		// Observe the resource
		CoapObserveRelation obs1 = client.observe(new TestHandler("Test Observe") {
			@Override public void onLoad(final CoapResponse response) {
				if (CONTENT_1.equals(response.getResponseText())
					&& response.advanced().getOptions().hasObserve()) {
					if (latch.getCount() > 0) {
						latch.countDown();
					} else {
						expectedNotifications.countDown();
						receivedNotifications.incrementAndGet();
					}
				}
			}
		});
		assertTrue(latch.await(1, TimeUnit.SECONDS));
		resource.changed();
		resource.changed();
		resource.changed();
		assertTrue(expectedNotifications.await(1, TimeUnit.SECONDS));
		obs1.reactiveCancel();
		resource.changed();
		Thread.sleep(50);
		assertThat(receivedNotifications.get(), is(3));
	}

	@Test
	public void testAsycPutIsNotAllowed() throws Exception {
		final CountDownLatch latch = new CountDownLatch(1);

		// Try a put and receive a METHOD_NOT_ALLOWED
		client.put(new TestHandler("Test 6") {
			@Override public void onLoad(CoapResponse response) {
				if (ResponseCode.METHOD_NOT_ALLOWED.equals(response.getCode())) {
					latch.countDown();
				}
			}
		}, CONTENT_2, MediaTypeRegistry.TEXT_PLAIN);

		assertTrue(latch.await(1, TimeUnit.SECONDS));
	}

	@Test
	public void testAsycGetUsingBuilder() throws Exception {
		final CountDownLatch latch = new CountDownLatch(1);

		// Try to use the builder and add a query
		new CoapClient.Builder(serverAddress.getHostString(), serverAddress.getPort())
			.path(TARGET).query(QUERY_UPPER_CASE).create()
			.get(new TestHandler("Test 8") {
				@Override public void onLoad(CoapResponse response) {
					if (CONTENT_1.toUpperCase().equals(response.getResponseText())) {
						latch.countDown();
					}
				}
			}
		);

		assertTrue(latch.await(1, TimeUnit.SECONDS));
	}

	private static void createServer() {
		CoapEndpoint endpoint = new CoapEndpoint(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));

		resource = new StorageResource(TARGET, CONTENT_1);
		server = new CoapServer();
		server.add(resource);

		server.addEndpoint(endpoint);
		server.start();
		serverAddress = endpoint.getAddress();
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

	private abstract class TestHandler implements CoapHandler {
		private String name;
		public TestHandler(String name) {
			this.name = name;
		}

		@Override
		public void onError() {
			failed.add(name);
		}
	}
}
