/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
package org.eclipse.californium.secure.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.eclipse.californium.core.network.EndpointContextMatcherFactory.DtlsMode;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Medium.class)
public class SecureObserveTest {

	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	static final int REPEATS = 3;
	static final String TARGET = "resource";
	static final String RESPONSE = "hi";
	static final String IDENITITY = "client1";
	static final String KEY = "key1";

	private TestUtilNat nat;
	private CoapServer server;
	private TestUtilPskStore pskStore;
	private DTLSConnector serverConnector;
	private CoapEndpoint serverEndpoint;
	private CoapEndpoint clientEndpoint;
	private MyResource resource;

	private String uri;

	@Before
	public void startupServer() {
		System.out.println(System.lineSeparator() + "Start " + getClass().getSimpleName());
	}

	@After
	public void shutdownServer() {
		if (nat != null) {
			nat.stop();
		}
		server.destroy();
		System.out.println("End " + getClass().getSimpleName());
	}

	/**
	 * Test observe using a DTLS connection.
	 */
	@Test
	public void testSecureObserve() throws Exception {

		createSecureServer(DtlsMode.STRICT);

		CoapClient client = new CoapClient(uri);
		CountingHandler handler = new CountingHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);

		assertFalse("Observe relation not established!", rel.isCanceled());

		// onLoad is called asynchronous to returning the response
		// therefore wait for one onLoad
		assertTrue(handler.waitForLoadCalls(1, 1000, TimeUnit.MILLISECONDS));

		assertFalse("Response not received", rel.isCanceled());
		assertNotNull("Response not received", rel.getCurrent());
		assertEquals("\"resource says hi for the 1 time\"", rel.getCurrent().getResponseText());

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies", handler.waitForLoadCalls(REPEATS + 1, 1000, TimeUnit.MILLISECONDS));
	}

	/**
	 * Test observe using a DTLS connection when the observed server changed the
	 * address and resumed the DTLS session. Though the number of the epoch
	 * after resume will still be 1, this is not detected by the (current)
	 * STRICT matcher.
	 */
	@Test
	public void testSecureObserveServerAddressChangedWithResume() throws Exception {

		createSecureServer(DtlsMode.STRICT);

		createNat();

		CoapClient client = new CoapClient(uri);
		CountingHandler handler = new CountingHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);

		assertFalse("Observe relation not established!", rel.isCanceled());

		// onLoad is called asynchronous to returning the response
		// therefore wait for one onLoad
		assertTrue(handler.waitForLoadCalls(1, 1000, TimeUnit.MILLISECONDS));

		assertFalse("Response not received", rel.isCanceled());
		assertNotNull("Response not received", rel.getCurrent());
		assertEquals("\"resource says hi for the 1 time\"", rel.getCurrent().getResponseText());

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies", handler.waitForLoadCalls(REPEATS + 1, 1000, TimeUnit.MILLISECONDS));

		nat.setChangeServerAddress(true);
		serverConnector.forceResumeAllSessions();

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies after address changed",
				handler.waitForLoadCalls(REPEATS + REPEATS + 1, 1000, TimeUnit.MILLISECONDS));
	}

	/**
	 * Test observe using a DTLS connection when the observed server changed the
	 * address and a new DTLS session is established using the RELAXED response
	 * matching.
	 */
	@Test
	public void testSecureObserveServerAddressChangedWithNewSessionRelaxedMatching() throws Exception {
		createSecureServer(DtlsMode.RELAXED);
		createNat();

		CoapClient client = new CoapClient(uri);
		CountingHandler handler = new CountingHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);

		assertFalse("Observe relation not established!", rel.isCanceled());

		// onLoad is called asynchronous to returning the response
		// therefore wait for one onLoad
		assertTrue(handler.waitForLoadCalls(1, 1000, TimeUnit.MILLISECONDS));

		assertFalse("Response not received", rel.isCanceled());
		assertNotNull("Response not received", rel.getCurrent());
		assertEquals("\"resource says hi for the 1 time\"", rel.getCurrent().getResponseText());

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies", handler.waitForLoadCalls(REPEATS + 1, 1000, TimeUnit.MILLISECONDS));

		nat.setChangeServerAddress(true);
		serverConnector.clearConnectionState();
		resource.changed("client");

		assertFalse("Unexpected notifies after address changed",
				handler.waitForLoadCalls(REPEATS + 2, 1000, TimeUnit.MILLISECONDS));

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertFalse("Unexpected notifies after address changed",
				handler.waitForLoadCalls(REPEATS + 2, 1000, TimeUnit.MILLISECONDS));
	}

	/**
	 * Test observe using a DTLS connection when the observed server changed the
	 * address and a new DTLS session is established using the PRINCIPAL
	 * matching.
	 */
	@Test
	public void testSecureObserveServerAddressChangedWithNewSessionPrincipalMatching() throws Exception {
		createSecureServer(DtlsMode.PRINCIPAL);
		createNat();

		CoapClient client = new CoapClient(uri);
		CountingHandler handler = new CountingHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);

		assertFalse("Observe relation not established!", rel.isCanceled());

		// onLoad is called asynchronous to returning the response
		// therefore wait for one onLoad
		assertTrue(handler.waitForLoadCalls(1, 1000, TimeUnit.MILLISECONDS));

		assertFalse("Response not received", rel.isCanceled());
		assertNotNull("Response not received", rel.getCurrent());
		assertEquals("\"resource says hi for the 1 time\"", rel.getCurrent().getResponseText());

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies", handler.waitForLoadCalls(REPEATS + 1, 1000, TimeUnit.MILLISECONDS));

		nat.setChangeServerAddress(true);
		serverConnector.clearConnectionState();
		resource.changed("client");

		assertTrue("Missing notifies", handler.waitForLoadCalls(REPEATS + 2, 1000, TimeUnit.MILLISECONDS));

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies after address changed",
				handler.waitForLoadCalls(REPEATS + REPEATS + 2, 1000, TimeUnit.MILLISECONDS));
	}

	/**
	 * Test observe using a DTLS connection when the observed server changed the
	 * address and a new DTLS session is established using a different PRINCIPAL.
	 */
	@Test
	public void testObserveServerAddressChangedWithNewSessionAndPrincipal() throws Exception {
		createSecureServer(DtlsMode.PRINCIPAL);
		createNat();

		CoapClient client = new CoapClient(uri);
		CountingHandler handler = new CountingHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);

		assertFalse("Observe relation not established!", rel.isCanceled());

		// onLoad is called asynchronous to returning the response
		// therefore wait for one onLoad
		assertTrue(handler.waitForLoadCalls(1, 1000, TimeUnit.MILLISECONDS));

		assertFalse("Response not received", rel.isCanceled());
		assertNotNull("Response not received", rel.getCurrent());
		assertEquals("\"resource says hi for the 1 time\"", rel.getCurrent().getResponseText());

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies", handler.waitForLoadCalls(REPEATS + 1, 1000, TimeUnit.MILLISECONDS));

		nat.setChangeServerAddress(true);
		serverConnector.clearConnectionState();
		// change principal
		pskStore.set("stranger", "danger".getBytes());
		resource.changed("client");

		assertFalse("Unexpected notifies after address and principal changed",
				handler.waitForLoadCalls(REPEATS + 2, 1000, TimeUnit.MILLISECONDS));

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertFalse("Unexpected notifies after address and principal changed",
				handler.waitForLoadCalls(REPEATS + 2, 1000, TimeUnit.MILLISECONDS));
	}

	private void createSecureServer(DtlsMode mode) {
		pskStore = new TestUtilPskStore(IDENITITY, KEY.getBytes());
		DtlsConnectorConfig dtlsConfig = new DtlsConnectorConfig.Builder()
				.setAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0)).setPskStore(pskStore).build();
		// retransmit constantly all 200 milliseconds
		NetworkConfig config = network.createTestConfig().setInt(NetworkConfig.Keys.ACK_TIMEOUT, 200)
				.setFloat(NetworkConfig.Keys.ACK_RANDOM_FACTOR, 1f).setFloat(NetworkConfig.Keys.ACK_TIMEOUT_SCALE, 1f)
				.setString(NetworkConfig.Keys.DTLS_RESPONSE_MATCHING, mode.name());
		serverConnector = new DTLSConnector(dtlsConfig);
		serverEndpoint = new CoapEndpoint(serverConnector, config);

		server = new CoapServer();
		server.addEndpoint(serverEndpoint);
		resource = new MyResource(TARGET);
		server.add(resource);
		server.start();

		uri = serverEndpoint.getUri().toString() + "/" + TARGET;

		// prepare secure client endpoint
		DtlsConnectorConfig clientdtlsConfig = new DtlsConnectorConfig.Builder()
				.setAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0)).setPskStore(pskStore).build();
		clientEndpoint = new CoapEndpoint(new DTLSConnector(clientdtlsConfig), config);
		EndpointManager.getEndpointManager().setDefaultEndpoint(clientEndpoint);
	}

	private void createNat() throws Exception {
		nat = new TestUtilNat(InetAddress.getLoopbackAddress(), clientEndpoint.getAddress().getPort(),
				serverEndpoint.getAddress().getPort());
		uri = uri.replace(Integer.toString(serverEndpoint.getAddress().getPort()), Integer.toString(nat.getPort1()));
	}

	private static class MyResource extends CoapResource {

		private volatile Type type = Type.NON;
		private volatile String currentLabel;
		private volatile String currentResponse;
		private AtomicInteger counter = new AtomicInteger();

		public MyResource(String name) {
			super(name);
			prepareResponse();
			setObservable(true);
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			Response response = new Response(ResponseCode.CONTENT);
			response.setPayload(currentResponse);
			response.setType(type);
			exchange.respond(response);
		}

		@Override
		public void changed() {
			prepareResponse();
			super.changed();
		}

		public void changed(String label) {
			currentLabel = label;
			changed();
		}

		public void prepareResponse() {
			int count = counter.incrementAndGet();
			if (null == currentLabel) {
				currentResponse = String.format("\"%s says hi for the %d time\"", getName(), count);
			} else {
				currentResponse = String.format("\"%s says %s for the %d time\"", getName(), currentLabel, count);
			}
			System.out.println("Resource " + getName() + " changed to " + currentResponse);
		}

	}

	private class CountingHandler implements CoapHandler {

		public AtomicInteger loadCalls = new AtomicInteger();
		public AtomicInteger errorCalls = new AtomicInteger();

		@Override
		public void onLoad(CoapResponse response) {
			int counter;
			synchronized (this) {
				counter = loadCalls.incrementAndGet();
				notifyAll();
			}
			System.out.println("Received " + counter + ". Notification: " + response.advanced());
		}

		@Override
		public void onError() {
			int counter;
			synchronized (this) {
				counter = errorCalls.incrementAndGet();
				notifyAll();
			}
			System.out.println(counter + " Errors!");
		}

		public boolean waitForLoadCalls(final int counter, final long timeout, final TimeUnit unit)
				throws InterruptedException {
			return waitForCalls(counter, timeout, unit, loadCalls);
		}

		private synchronized boolean waitForCalls(final int counter, final long timeout, final TimeUnit unit,
				AtomicInteger calls) throws InterruptedException {
			if (0 < timeout) {
				long end = System.nanoTime() + unit.toNanos(timeout);
				while (calls.get() < counter) {
					long left = TimeUnit.NANOSECONDS.toMillis(end - System.nanoTime());
					if (0 < left) {
						wait(left);
					} else {
						break;
					}
				}
			}
			return calls.get() >= counter;
		}
	}
}
