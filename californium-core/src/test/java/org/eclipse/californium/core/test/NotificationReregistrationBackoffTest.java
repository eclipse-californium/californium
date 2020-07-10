/*******************************************************************************
 * Copyright (c) 2019 Rogier Cobben.
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
 *    Rogier Cobben - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.eclipse.californium.elements.util.TestConditionTools.inRange;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.TestScope;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

/**
 * Test notification back-off.
 */
@RunWith(Parameterized.class)
@Category(Medium.class)
public class NotificationReregistrationBackoffTest {

	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	@ClassRule
	public static CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	/**
	 * No exception expected by default
	 */
	@Rule
	public ExpectedException exception = ExpectedException.none();

	/**
	 * Service resource name.
	 */
	private static final String TARGET = "lazy_resource";

	/**
	 * Max age of resource state. [s]
	 */
	private static final long MAX_AGE = 1;

	/**
	 * @return List of notification re-registration backoff times to test. [ms]
	 */
	@Parameters(name = "notification re-registration backoff = {0}")
	public static Iterable<Long> backoffParams() {
		if (TestScope.enableIntensiveTests()) {
			return Arrays.asList(500L, 2000L, 4000L);
		} else {
			return Arrays.asList(500L);
		}
	}

	/**
	 * Actual notification re-registration backoff to test. [ms]
	 */
	@Parameter
	public long backoff;

	/**
	 * Test client.
	 */
	private CoapClient client = null;
	/**
	 * Test client endpoint;
	 */
	private CoapEndpoint clientEndpoint = null;

	/**
	 * Start server
	 */
	@BeforeClass
	public static void setupServer() {
		CoapServer server = new CoapServer(network.getStandardTestConfig());
		cleanup.add(server);
		server.add(new LazyResource(TARGET));
		server.start();
	}

	/**
	 * Create client.
	 */
	@Before
	public void setupClient() {
		NetworkConfig config = NetworkConfig.createStandardWithoutFile();
		config.setLong(NetworkConfig.Keys.NOTIFICATION_REREGISTRATION_BACKOFF, backoff); // [ms]
		clientEndpoint = new CoapEndpoint.Builder().setNetworkConfig(config).build();
		client = new CoapClient();
		client.setURI("coap://127.0.0.1/" + TARGET);
		client.setEndpoint(clientEndpoint);
		client.setTimeout(1000L);
	}

	/**
	 * Destroy client.
	 */
	@After
	public void tearDownClient() {
		if (clientEndpoint != null) {
			clientEndpoint.destroy();
			clientEndpoint = null;
		}
		if (client != null) {
			client.shutdown();
			client = null;
		}
	}

	/**
	 * Test re-registration when notifications do not arrive.
	 * 
	 * @throws InterruptedException should not occur
	 */
	@Test
	public void reregistrationTest() throws InterruptedException {
		final long expectedTimespanMillis = 3 * (MAX_AGE * 1000 + backoff);
		CountingCoapHandler handler = new CountingCoapHandler();
		long time = System.nanoTime();
		CoapObserveRelation relation = client.observe(handler);
		// wait for 3 re-registrations to happen, plus some grace time
		boolean ready = handler.waitOnLoadCalls(4, expectedTimespanMillis + 200, TimeUnit.MILLISECONDS);
		time = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - time);
		relation.proactiveCancel();
		assertTrue("cancel times out", handler.waitOnLoadCalls(5, 2000, TimeUnit.MILLISECONDS));

		assertTrue("wrong number of responses/notifications", ready);
		assertThat("timespan not in expected range", time, is(inRange(expectedTimespanMillis - 100L, expectedTimespanMillis + 200L)));

		for (int index = 0; index < 5; ++index) {
			CoapResponse response = handler.waitOnLoad(0);
			assertNotNull("no response from server: ", response);
			assertEquals("wrong responsecode: ", ResponseCode.CONTENT, response.getCode());
		}
	}

	/**
	 * Service resource that does not bother to notify observing clients.
	 *
	 */
	public static class LazyResource extends CoapResource {

		/**
		 * Constructor.
		 * 
		 * @param name of the resource
		 */
		public LazyResource(String name) {
			super(name);
			this.setObservable(true);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.eclipse.californium.core.CoapResource#handleGET(org.eclipse.
		 * californium.core.server.resources.CoapExchange)
		 */
		@Override
		public void handleGET(CoapExchange exchange) {
			Response response = new Response(ResponseCode.CONTENT);
			// make an empty promise that observing clients get notified within
			// MAX_AGE seconds
			response.getOptions().setMaxAge(MAX_AGE);
			exchange.respond(response);
		}
	}
}
