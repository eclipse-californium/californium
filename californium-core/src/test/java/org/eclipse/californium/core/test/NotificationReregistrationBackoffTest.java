/*******************************************************************************
 * Copyright (c) 2019 Rogier Cobben.
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
 *    Rogier Cobben - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.After;
import org.junit.AfterClass;
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
		return Arrays.asList(100L, 2000L, 4000L);
	}

	/**
	 * Actual notification re-registration backoff to test. [ms]
	 */
	@Parameter
	public long backoff;

	/**
	 * Test server.
	 */
	private static CoapServer server = null;
	/**
	 * Test client.
	 */
	private CoapClient client = null;

	/**
	 * Start server
	 */
	@BeforeClass
	public static void setupServer() {
		System.out.println(System.lineSeparator() + "Start " + NotificationReregistrationBackoffTest.class.getName());
		server = new CoapServer();
		server.add(new LazyResource(TARGET));
		server.start();
	}

	/**
	 * Stop server.
	 */
	@AfterClass
	public static void tearDownServer() {
		if (server != null) {
			server.stop();
			server.destroy();
			server = null;
		}
	}

	/**
	 * Create client.
	 */
	@Before
	public void setupClient() {
		NetworkConfig config = NetworkConfig.createStandardWithoutFile();
		config.setLong(NetworkConfig.Keys.NOTIFICATION_REREGISTRATION_BACKOFF, backoff); // [ms]
		CoapEndpoint endpoint = new CoapEndpoint.Builder().setNetworkConfig(config).build();
		client = new CoapClient();
		client.setURI("coap://127.0.0.1/" + TARGET);
		client.setEndpoint(endpoint);
		client.setTimeout(1000L);
	}

	/**
	 * Destroy client.
	 */
	@After
	public void tearDownClient() {
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
		final List<CoapResponse> observations = Collections.synchronizedList(new ArrayList<CoapResponse>());
		CoapObserveRelation relation = client.observe(new ResponseHander(observations));
		// wait for 3 re-registrations to happen, plus some grace time
		Thread.sleep(3 * (MAX_AGE * 1000 + backoff) + 100);
		relation.proactiveCancel();

		synchronized (observations) {
			// expect 1 primary response + 3 re-registration responses = 4
			assertEquals("wrong number of responses/notifications", 4, observations.size());
			for (CoapResponse response : observations) {
				assertNotNull("no response from server: ", response);
				assertEquals("wrong responsecode: ", ResponseCode.CONTENT, response.getCode());
			}
		}
	}

	/**
	 * Handler that collects responses
	 *
	 */
	public class ResponseHander implements CoapHandler {

		private List<CoapResponse> responses;

		/**
		 * Constructor
		 * 
		 * @param responses list to deposit received responses in
		 */
		public ResponseHander(List<CoapResponse> responses) {
			this.responses = responses;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.eclipse.californium.core.CoapHandler#onLoad(org.eclipse.
		 * californium.core. CoapResponse)
		 */
		@Override
		public void onLoad(CoapResponse response) {
			responses.add(response);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.eclipse.californium.core.CoapHandler#onError()
		 */
		@Override
		public void onError() {
			//note that an error occured
			responses.add(null);
		}
	};

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
