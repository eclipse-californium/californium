/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageInterceptor;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.TestThreadFactory;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Medium.class)
public class ObserveProActiveCancelTest {

	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	private static final int LOOPS = 100;
	static final String TARGET_X = "resX";
	static final String RESPONSE = "hi";

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private CoapEndpoint serverEndpoint;
	private MyResource resourceX;
	private ExecutorService executor;

	private String uriX;

	@Before
	public void startupServer() {
		cleanup.add(createServer());
		executor = ExecutorsUtil.newFixedThreadPool(1, new TestThreadFactory("Core-Test-"));
	}

	@After
	public void shutdown() {
		Endpoint endpoint = EndpointManager.getEndpointManager().getDefaultEndpoint();
		for (MessageInterceptor interceptor : endpoint.getInterceptors()) {
			endpoint.removeInterceptor(interceptor);
		}
		for (MessageInterceptor interceptor : serverEndpoint.getInterceptors()) {
			endpoint.removeInterceptor(interceptor);
		}
		ExecutorsUtil.shutdownExecutorGracefully(100, executor);
	}

	@Test
	public void testObserveClient() throws Exception {

		CoapClient client = new CoapClient(uriX);
		cleanup.add(client);
		for (int index = 0; index < LOOPS; ++index) {
			ObserveCountingCoapHandler handler = new ObserveCountingCoapHandler();
			CoapObserveRelation rel = client.observeAndWait(handler);

			// onLoad is called asynchronous to returning the response
			// therefore wait for one onLoad
			assertTrue(handler.waitOnLoadCalls(1, 1000, TimeUnit.MILLISECONDS));

			assertFalse("Response not received", rel.isCanceled());
			assertNotNull("Response not received", rel.getCurrent());
			assertEquals(RESPONSE, rel.getCurrent().getResponseText());

			assertTrue("reregister denied", rel.reregister());
			assertTrue("reregister failed", handler.waitOnLoadCalls(2, 1000, TimeUnit.MILLISECONDS));
			assertTrue("reregister denied", rel.reregister());
			rel.proactiveCancel();
			assertTrue("observation not canceled", handler.waitOnNotify(false, 1000, TimeUnit.MILLISECONDS));
		}
	}

	@Test
	public void testObserveClientAsynchronous() throws Exception {

		CoapClient client = new CoapClient(uriX);
		cleanup.add(client);
		for (int index = 0; index < LOOPS; ++index) {
			ObserveCountingCoapHandler handler = new ObserveCountingCoapHandler();
			final CoapObserveRelation rel = client.observeAndWait(handler);
			final AtomicInteger reregisterCounter = new AtomicInteger();
			Runnable reregisterJob = new Runnable() {

				@Override
				public void run() {
					try {
						if (rel.reregister()) {
							reregisterCounter.incrementAndGet();
						}
					} catch (IllegalStateException ex) {
					}
				}
			};
			// onLoad is called asynchronous to returning the response
			// therefore wait for one onLoad
			assertTrue(handler.waitOnLoadCalls(1, 1000, TimeUnit.MILLISECONDS));

			assertFalse("Response not received", rel.isCanceled());
			assertNotNull("Response not received", rel.getCurrent());
			assertEquals(RESPONSE, rel.getCurrent().getResponseText());

			executor.execute(reregisterJob);
			boolean ok = handler.waitOnLoadCalls(2, 1000, TimeUnit.MILLISECONDS);
			assertTrue("reregister failed, " + reregisterCounter.get(), ok);
			executor.execute(reregisterJob);
			rel.proactiveCancel();
			assertTrue("observation not canceled", handler.waitOnNotify(false, 1000, TimeUnit.MILLISECONDS));
		}
	}

	private CoapServer createServer() {
		// retransmit constantly all 200 milliseconds
		NetworkConfig config = network.createTestConfig().setInt(NetworkConfig.Keys.ACK_TIMEOUT, 200)
				.setFloat(NetworkConfig.Keys.ACK_RANDOM_FACTOR, 1f).setFloat(NetworkConfig.Keys.ACK_TIMEOUT_SCALE, 1f);

		MessageTracer tracer = new MessageTracer();

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		builder.setNetworkConfig(config);

		serverEndpoint = builder.build();
		serverEndpoint.addInterceptor(tracer);

		CoapServer server = new CoapServer(config);
		server.addEndpoint(serverEndpoint);
		resourceX = new MyResource(TARGET_X);
		server.add(resourceX);
		server.start();

		uriX = TestTools.getUri(serverEndpoint, TARGET_X);

		// setup the client endpoint using the special observation store
		builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		builder.setNetworkConfig(config);
		CoapEndpoint coapEndpoint = builder.build();
		coapEndpoint.addInterceptor(tracer);
		EndpointManager.getEndpointManager().setDefaultEndpoint(coapEndpoint);

		return server;
	}

	private static class MyResource extends CoapResource {

		private volatile Type type = Type.CON;
		private volatile String currentResponse;

		public MyResource(String name) {
			super(name);
			currentResponse = RESPONSE;
			setObservable(true);
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			Response response = new Response(ResponseCode.CONTENT);
			response.setPayload(currentResponse);
			response.setType(type);
			exchange.respond(response);
		}

	}

	private static class ObserveCountingCoapHandler extends CountingCoapHandler {

		private volatile boolean notify;

		protected void assertLoad(CoapResponse response) {
			notify = response.getOptions().hasObserve();
			notify();
		}

		private synchronized boolean waitOnNotify(boolean notify, final long timeout, final TimeUnit unit)
				throws InterruptedException {
			if (0 < timeout) {
				long end = System.nanoTime() + unit.toNanos(timeout);

				while (this.notify != notify) {
					long left = TimeUnit.NANOSECONDS.toMillis(end - System.nanoTime());
					if (0 < left) {
						wait(left);
					} else {
						break;
					}
				}
			}
			return this.notify == notify;
		}

	}
}
