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
 *    Achim Kraus (Bosch Software Innovations GmbH) - use more general NatUtil
 *    Achim Kraus (Bosch Software Innovations GmbH) - add tests to ensure, that 
 *                                                    responses/notifies are 
 *                                                    dropped on the server side
 *    Achim Kraus (Bosch Software Innovations GmbH) - ensure, that session is resumed
 *                                                    before sending more notifications
 *                                                    When fixing issue #23, an 
 *                                                    additional test should be added.
 ******************************************************************************/
package org.eclipse.californium.integration.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertThat;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.eclipse.californium.core.network.EndpointContextMatcherFactory.MatcherMode;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapClient;
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
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.test.CountingHandler;
import org.eclipse.californium.elements.EndpointMismatchException;
import org.eclipse.californium.examples.NatUtil;
import org.eclipse.californium.integration.test.util.CoapsNetworkRule;
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
	public static CoapsNetworkRule network = new CoapsNetworkRule(CoapsNetworkRule.Mode.DIRECT,
			CoapsNetworkRule.Mode.NATIVE);

	static final int TIMEOUT_IN_MILLIS = 2000;
	static final int REPEATS = 3;
	static final String TARGET = "resource";
	static final String RESPONSE = "hi";
	static final String IDENITITY = "client1";
	static final String KEY = "key1";

	private NatUtil nat;
	private CoapServer server;
	private TestUtilPskStore pskStore;
	private DTLSConnector serverConnector;
	private DTLSConnector clientConnector;
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

		createSecureServer(MatcherMode.STRICT);

		CoapClient client = new CoapClient(uri);
		CountingHandler handler = new CountingHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);

		assertFalse("Observe relation not established!", rel.isCanceled());

		// onLoad is called asynchronous to returning the response
		// therefore wait for one onLoad
		assertTrue(handler.waitForLoadCalls(1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		assertFalse("Response not received", rel.isCanceled());
		assertNotNull("Response not received", rel.getCurrent());
		assertEquals("\"resource says hi for the 1 time\"", rel.getCurrent().getResponseText());

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies", handler.waitForLoadCalls(REPEATS + 1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));
		assertThat("sending response missing", resource.getCurrentResponse(), is(notNullValue()));
		assertThat(resource.getCurrentResponse().getPayloadString(), is("\"resource says client for the " + (REPEATS + 1) +" time\""));
		assertThat("sending response caused error", resource.getCurrentResponse().getSendError(), is(nullValue()));
	}

	@Test(expected = RuntimeException.class)
	public void testSecureGetWithNewSession() throws Exception {

		createSecureServer(MatcherMode.STRICT);

		CoapClient client = new CoapClient(uri);
		CoapResponse response = client.get();

		assertEquals("\"resource says hi for the 1 time\"", response.getResponseText());

		clientConnector.clearConnectionState();

		// new handshake with already set endpoint context => exception 
		response = client.get();
	}

	/**
	 * Test observe using a DTLS connection with new session.
	 * After the new handshake, the server is intended not to send notifies.
	 */
	@Test
	public void testSecureObserveWithNewSession() throws Exception {

		createSecureServer(MatcherMode.STRICT);

		CoapClient client = new CoapClient(uri);
		CountingHandler handler = new CountingHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);

		assertFalse("Observe relation not established!", rel.isCanceled());

		// onLoad is called asynchronous to returning the response
		// therefore wait for one onLoad
		assertTrue(handler.waitForLoadCalls(1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		assertFalse("Response not received", rel.isCanceled());
		assertNotNull("Response not received", rel.getCurrent());
		assertEquals("\"resource says hi for the 1 time\"", rel.getCurrent().getResponseText());

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies", handler.waitForLoadCalls(REPEATS + 1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));
		assertThat("sending response missing", resource.getCurrentResponse(), is(notNullValue()));
		assertThat(resource.getCurrentResponse().getPayloadString(), is("\"resource says client for the " + (REPEATS + 1) +" time\""));
		assertThat("sending response caused error", resource.getCurrentResponse().getSendError(), is(nullValue()));

		// clean up session and endpoint context => force new session
		clientConnector.clearConnectionState();
		client.setDestinationContext(null);

		// new handshake
		CoapResponse response = client.get();
		assertNotNull("Response not received", response);

		// notify (in scope of old DTLS session) should be rejected by the server 
		resource.changed("new client");

		assertFalse("Unexpected notify", handler.waitForLoadCalls(REPEATS + 2, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));
		assertThat("sending response missing", resource.getCurrentResponse(), is(notNullValue()));
		assertThat(resource.getCurrentResponse().getPayloadString(), is("\"resource says new client for the " + (REPEATS + 2) +" time\""));
		assertThat("sending response misses error", resource.getCurrentResponse().getSendError(),
				is(instanceOf(EndpointMismatchException.class)));
	}

	/**
	 * Test observe using a DTLS connection when the observed server changed the
	 * address and resumed the DTLS session. Though the number of the epoch
	 * after resume will still be 1, this is not detected by the (current)
	 * STRICT matcher.
	 */
	@Test
	public void testSecureObserveServerAddressChangedWithResume() throws Exception {

		createSecureServer(MatcherMode.STRICT);

		createInverseNat();

		CoapClient client = new CoapClient(uri);
		CountingHandler handler = new CountingHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);

		assertFalse("Observe relation not established!", rel.isCanceled());

		// onLoad is called asynchronous to returning the response
		// therefore wait for one onLoad
		assertTrue(handler.waitForLoadCalls(1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		assertFalse("Response not received", rel.isCanceled());
		assertNotNull("Response not received", rel.getCurrent());
		assertEquals("\"resource says hi for the 1 time\"", rel.getCurrent().getResponseText());

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies", handler.waitForLoadCalls(REPEATS + 1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		nat.reassignLocalAddresses();
		serverConnector.forceResumeAllSessions();

		// trigger handshake
		resource.changed("client");
		// wait for established session
		assertTrue("Missing notifies", handler.waitForLoadCalls(REPEATS + 2, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies after address changed",
				handler.waitForLoadCalls(REPEATS + REPEATS + 2, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));
		assertThat("sending response missing", resource.getCurrentResponse(), is(notNullValue()));
		assertThat("sending response caused error", resource.getCurrentResponse().getSendError(), is(nullValue()));
	}

	/**
	 * Test observe using a DTLS connection when the observed server changed the
	 * address and a new DTLS session is established using the RELAXED response
	 * matching.
	 */
	@Test
	public void testSecureObserveServerAddressChangedWithNewSessionRelaxedMatching() throws Exception {
		createSecureServer(MatcherMode.RELAXED);
		createInverseNat();

		CoapClient client = new CoapClient(uri);
		CountingHandler handler = new CountingHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);

		assertFalse("Observe relation not established!", rel.isCanceled());

		// onLoad is called asynchronous to returning the response
		// therefore wait for one onLoad
		assertTrue(handler.waitForLoadCalls(1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		assertFalse("Response not received", rel.isCanceled());
		assertNotNull("Response not received", rel.getCurrent());
		assertEquals("\"resource says hi for the 1 time\"", rel.getCurrent().getResponseText());

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies", handler.waitForLoadCalls(REPEATS + 1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		nat.reassignLocalAddresses();
		serverConnector.clearConnectionState();
		resource.changed("client");

		assertFalse("Unexpected notifies after address changed",
				handler.waitForLoadCalls(REPEATS + 2, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));
		assertThat("sending response missing", resource.getCurrentResponse(), is(notNullValue()));
		assertThat("sending response misses error", resource.getCurrentResponse().getSendError(),
				is(instanceOf(EndpointMismatchException.class)));

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertFalse("Unexpected notifies after address changed",
				handler.waitForLoadCalls(REPEATS + 2, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));
		assertThat("sending response missing", resource.getCurrentResponse(), is(notNullValue()));
		assertThat("sending response misses error", resource.getCurrentResponse().getSendError(),
				is(instanceOf(EndpointMismatchException.class)));
	}

	/**
	 * Test observe using a DTLS connection when the observed server changed the
	 * address and a new DTLS session is established using the PRINCIPAL
	 * matching.
	 */
	@Test
	public void testSecureObserveServerAddressChangedWithNewSessionPrincipalMatching() throws Exception {
		createSecureServer(MatcherMode.PRINCIPAL);
		createInverseNat();

		CoapClient client = new CoapClient(uri);
		CountingHandler handler = new CountingHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);

		assertFalse("Observe relation not established!", rel.isCanceled());

		// onLoad is called asynchronous to returning the response
		// therefore wait for one onLoad
		assertTrue(handler.waitForLoadCalls(1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		assertFalse("Response not received", rel.isCanceled());
		assertNotNull("Response not received", rel.getCurrent());
		assertEquals("\"resource says hi for the 1 time\"", rel.getCurrent().getResponseText());

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies", handler.waitForLoadCalls(REPEATS + 1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		nat.reassignLocalAddresses();
		serverConnector.clearConnectionState();
		resource.changed("client");

		assertTrue("Missing notifies", handler.waitForLoadCalls(REPEATS + 2, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies after address changed",
				handler.waitForLoadCalls(REPEATS + REPEATS + 2, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));
		assertThat("sending response missing", resource.getCurrentResponse(), is(notNullValue()));
		assertThat("sending response caused error", resource.getCurrentResponse().getSendError(), is(nullValue()));
	}

	/**
	 * Test observe using a DTLS connection when the observed server changed the
	 * address and a new DTLS session is established using a different
	 * PRINCIPAL.
	 */
	@Test
	public void testObserveServerAddressChangedWithNewSessionAndPrincipal() throws Exception {
		createSecureServer(MatcherMode.PRINCIPAL);
		createInverseNat();

		CoapClient client = new CoapClient(uri);
		CountingHandler handler = new CountingHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);

		assertFalse("Observe relation not established!", rel.isCanceled());

		// onLoad is called asynchronous to returning the response
		// therefore wait for one onLoad
		assertTrue(handler.waitForLoadCalls(1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		assertFalse("Response not received", rel.isCanceled());
		assertNotNull("Response not received", rel.getCurrent());
		assertEquals("\"resource says hi for the 1 time\"", rel.getCurrent().getResponseText());

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies", handler.waitForLoadCalls(REPEATS + 1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		nat.reassignLocalAddresses();
		serverConnector.clearConnectionState();
		// change principal
		pskStore.set("stranger", "danger".getBytes());
		resource.changed("client");

		assertFalse("Unexpected notifies after address and principal changed",
				handler.waitForLoadCalls(REPEATS + 2, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertFalse("Unexpected notifies after address and principal changed",
				handler.waitForLoadCalls(REPEATS + 2, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));
		assertThat("sending response missing", resource.getCurrentResponse(), is(notNullValue()));
		assertThat("sending response misses error", resource.getCurrentResponse().getSendError(),
				is(instanceOf(EndpointMismatchException.class)));
	}

	private void createSecureServer(MatcherMode mode) {
		pskStore = new TestUtilPskStore(IDENITITY, KEY.getBytes());
		DtlsConnectorConfig dtlsConfig = new DtlsConnectorConfig.Builder()
				.setAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
				.setReceiverThreadCount(2)
				.setConnectionThreadCount(2)
				.setPskStore(pskStore).build();
		// retransmit constantly all 200 milliseconds
		NetworkConfig config = network.createTestConfig().setInt(Keys.ACK_TIMEOUT, 200)
				.setFloat(Keys.ACK_RANDOM_FACTOR, 1f).setFloat(Keys.ACK_TIMEOUT_SCALE, 1f)
				.setLong(Keys.EXCHANGE_LIFETIME, 10 * 1000L) // set response
																// timeout
																// (indirect) to
																// 10s
				.setString(Keys.RESPONSE_MATCHING, mode.name());
		serverConnector = new DTLSConnector(dtlsConfig);
		CoapEndpoint.CoapEndpointBuilder builder = new CoapEndpoint.CoapEndpointBuilder();
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
				.setReceiverThreadCount(2)
				.setConnectionThreadCount(2)
				.setPskStore(pskStore).build();
		clientConnector = new DTLSConnector(clientdtlsConfig);
		builder = new CoapEndpoint.CoapEndpointBuilder();
		builder.setConnector(clientConnector);
		builder.setNetworkConfig(config);
		clientEndpoint = builder.build();
		EndpointManager.getEndpointManager().setDefaultEndpoint(clientEndpoint);
	}

	private void createInverseNat() throws Exception {
		nat = new NatUtil(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), clientEndpoint.getAddress());
		int port = nat.assignLocalAddress(serverEndpoint.getAddress());
		String natURI = uri.replace(":" + serverEndpoint.getAddress().getPort() + "/", ":" + port + "/");
		System.out.println("URI: change " + uri + " to " + natURI);
		uri = natURI;
	}

	private static class MyResource extends CoapResource {

		private volatile Type type = Type.NON;
		private volatile String currentLabel;
		private volatile String currentResponsePayload;
		private volatile Response currentResponse;
		private AtomicInteger counter = new AtomicInteger();

		public MyResource(String name) {
			super(name);
			prepareResponsePayload();
			setObservable(true);
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			Response response = new Response(ResponseCode.CONTENT);
			response.setPayload(currentResponsePayload);
			response.setType(type);
			currentResponse = response;
			exchange.respond(response);
		}

		@Override
		public void changed() {
			prepareResponsePayload();
			super.changed();
		}

		public void changed(String label) {
			currentLabel = label;
			changed();
		}

		public void prepareResponsePayload() {
			int count = counter.incrementAndGet();
			if (null == currentLabel) {
				currentResponsePayload = String.format("\"%s says hi for the %d time\"", getName(), count);
			} else {
				currentResponsePayload = String.format("\"%s says %s for the %d time\"", getName(), currentLabel,
						count);
			}
			System.out.println("Resource " + getName() + " changed to " + currentResponsePayload);
		}

		public Response getCurrentResponse() {
			return currentResponse;
		}
	}
}
