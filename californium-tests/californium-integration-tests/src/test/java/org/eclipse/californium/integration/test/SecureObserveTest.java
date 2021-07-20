/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.net.InetSocketAddress;
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
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.config.CoapConfig.MatcherMode;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.test.CountingCoapHandler;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.PrincipalEndpointContextMatcher;
import org.eclipse.californium.elements.category.NativeDatagramSocketImplRequired;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.exception.EndpointMismatchException;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.integration.test.util.CoapsNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.ConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.SingleNodeConnectionIdGenerator;
import org.eclipse.californium.util.nat.NioNatUtil;
import org.junit.After;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(NativeDatagramSocketImplRequired.class)
public class SecureObserveTest {

	@ClassRule
	public static CoapsNetworkRule network = new CoapsNetworkRule(CoapsNetworkRule.Mode.NATIVE);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	static final int TIMEOUT_IN_MILLIS = 2000;
	static final int REPEATS = 3;
	static final String TARGET = "resource";
	static final String RESPONSE = "hi";
	static final String IDENITITY = "client1";
	static final String KEY = "key1";

	private NioNatUtil nat;
	private TestUtilPskStore clientPskStore;
	private TestUtilPskStore serverPskStore;
	private DTLSConnector serverConnector;
	private DTLSConnector clientConnector;
	private CoapEndpoint serverEndpoint;
	private CoapEndpoint clientEndpoint;
	private MyResource resource;

	private String uri;

	@After
	public void shutdownServer() {
		if (nat != null) {
			nat.stop();
		}
	}

	/**
	 * Test observe using a DTLS connection.
	 */
	@Test
	public void testSecureObserve() throws Exception {

		createSecureServer(MatcherMode.STRICT, null);

		CoapClient client = new CoapClient(uri);
		CountingCoapHandler handler = new CountingCoapHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);

		assertFalse("Observe relation not established!", rel.isCanceled());

		// onLoad is called asynchronous to returning the response
		// therefore wait for one onLoad
		assertTrue(handler.waitOnLoadCalls(1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		assertFalse("Response not received", rel.isCanceled());
		assertThat("Response not received", rel.getCurrent(), is(notNullValue()));
		assertEquals("\"resource says hi for the 1 time\"", rel.getCurrent().getResponseText());

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies", handler.waitOnLoadCalls(REPEATS + 1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));
		assertThat("sending response missing", resource.getCurrentResponse(), is(notNullValue()));
		assertThat(resource.getCurrentResponse().getPayloadString(), is("\"resource says client for the " + (REPEATS + 1) +" time\""));
		assertThat("sending response caused error", resource.getCurrentResponse().getSendError(), is(nullValue()));
		client.shutdown();
	}

	@Test(expected = ConnectorException.class)
	public void testSecureGetWithNewSession() throws Exception {

		createSecureServer(MatcherMode.STRICT, null);

		CoapClient client = new CoapClient(uri);
		try {
			CoapResponse response = client.get();

			assertEquals("\"resource says hi for the 1 time\"", response.getResponseText());

			clientConnector.clearConnectionState();

			// new handshake with already set endpoint context => exception 
			response = client.get();
		} finally {
			client.shutdown();
		}
	}

	/**
	 * Test observe using a DTLS connection with new session.
	 * After the new handshake, the server is intended not to send notifies.
	 */
	@Test
	public void testSecureObserveWithNewSession() throws Exception {

		createSecureServer(MatcherMode.STRICT, null);

		CoapClient client = new CoapClient(uri);
		CountingCoapHandler handler = new CountingCoapHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);

		assertFalse("Observe relation not established!", rel.isCanceled());

		// onLoad is called asynchronous to returning the response
		// therefore wait for one onLoad
		assertTrue(handler.waitOnLoadCalls(1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		assertFalse("Response not received", rel.isCanceled());
		assertThat("Response not received", rel.getCurrent(), is(notNullValue()));
		assertEquals("\"resource says hi for the 1 time\"", rel.getCurrent().getResponseText());

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies", handler.waitOnLoadCalls(REPEATS + 1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));
		assertThat("sending response missing", resource.getCurrentResponse(), is(notNullValue()));
		assertThat(resource.getCurrentResponse().getPayloadString(), is("\"resource says client for the " + (REPEATS + 1) +" time\""));
		assertThat("sending response caused error", resource.getCurrentResponse().getSendError(), is(nullValue()));

		// clean up session and endpoint context => force new session
		clientConnector.clearConnectionState();
		client.setDestinationContext(null);

		// new handshake
		CoapResponse response = client.get();
		assertThat("Response not received", response, is(notNullValue()));

		// notify (in scope of old DTLS session) should be rejected by the server 
		resource.changed("new client");

		assertFalse("Unexpected notify", handler.waitOnLoadCalls(REPEATS + 2, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));
		assertThat("sending response missing", resource.getCurrentResponse(), is(notNullValue()));
		assertThat(resource.getCurrentResponse().getPayloadString(), is("\"resource says new client for the " + (REPEATS + 2) +" time\""));
		assertThat("sending response misses error", resource.getCurrentResponse().getSendError(),
				is(instanceOf(EndpointMismatchException.class)));
		client.shutdown();
	}

	/**
	 * Test observe using a DTLS connection when the observed server changed the
	 * address using a dtls connection id.
	 */
	@Test
	public void testSecureObserveServerAddressChangedWithCid() throws Exception {

		createSecureServer(MatcherMode.STRICT, new SingleNodeConnectionIdGenerator(6));

		createInverseNat();

		CoapClient client = new CoapClient(uri);
		CountingCoapHandler handler = new CountingCoapHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);

		assertFalse("Observe relation not established!", rel.isCanceled());

		// onLoad is called asynchronous to returning the response
		// therefore wait for one onLoad
		assertTrue(handler.waitOnLoadCalls(1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		assertFalse("Response not received", rel.isCanceled());
		assertThat("Response not received", rel.getCurrent(), is(notNullValue()));
		assertEquals("\"resource says hi for the 1 time\"", rel.getCurrent().getResponseText());
		EndpointContext context1 = rel.getCurrent().advanced().getSourceContext();
		assertThat("context-1 missing", context1, is(notNullValue()));

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies", handler.waitOnLoadCalls(REPEATS + 1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		nat.reassignNewLocalAddresses();

		// trigger handshake
		resource.changed("client");
		// wait for established session
		assertTrue("Missing notifies", handler.waitOnLoadCalls(REPEATS + 2, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies after address changed",
				handler.waitOnLoadCalls(REPEATS + REPEATS + 2, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));
		assertThat("sending response missing", resource.getCurrentResponse(), is(notNullValue()));
		assertThat("sending response caused error", resource.getCurrentResponse().getSendError(), is(nullValue()));

		EndpointContext context2 = rel.getCurrent().advanced().getSourceContext();
		assertThat("context-2 missing", context2, is(notNullValue()));
		assertThat(context2.get(DtlsEndpointContext.KEY_HANDSHAKE_TIMESTAMP),
				is(context1.get(DtlsEndpointContext.KEY_HANDSHAKE_TIMESTAMP)));

		String natURI = uri.replace(":" + context1.getPeerAddress().getPort() + "/", ":" + context2.getPeerAddress().getPort() + "/");
		System.out.println("URI: change " + uri + " to " + natURI);
		
		client.setURI(natURI);
		CoapResponse coapResponse = client.get();
		assertThat("response missing", coapResponse, is(notNullValue()));
		client.shutdown();
	}

	/**
	 * Test observe using a DTLS connection when the observed server changed the
	 * address and resumed the DTLS session. Though the number of the epoch
	 * after resume will still be 1, this is not detected by the (current)
	 * STRICT matcher.
	 */
	@Test
	public void testSecureObserveServerAddressChangedWithResume() throws Exception {

		createSecureServer(MatcherMode.STRICT, null);

		createInverseNat();

		CoapClient client = new CoapClient(uri);
		CountingCoapHandler handler = new CountingCoapHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);

		assertFalse("Observe relation not established!", rel.isCanceled());

		// onLoad is called asynchronous to returning the response
		// therefore wait for one onLoad
		assertTrue(handler.waitOnLoadCalls(1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		assertFalse("Response not received", rel.isCanceled());
		assertThat("Response not received", rel.getCurrent(), is(notNullValue()));
		assertEquals("\"resource says hi for the 1 time\"", rel.getCurrent().getResponseText());
		EndpointContext context1 = rel.getCurrent().advanced().getSourceContext();
		assertThat("context-1 missing", context1, is(notNullValue()));

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies", handler.waitOnLoadCalls(REPEATS + 1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		nat.reassignNewLocalAddresses();
		serverConnector.forceResumeAllSessions();

		// trigger handshake
		resource.changed("client");
		// wait for established session
		assertTrue("Missing notifies", handler.waitOnLoadCalls(REPEATS + 2, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies after address changed",
				handler.waitOnLoadCalls(REPEATS + REPEATS + 2, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));
		assertThat("sending response missing", resource.getCurrentResponse(), is(notNullValue()));
		assertThat("sending response caused error", resource.getCurrentResponse().getSendError(), is(nullValue()));

		EndpointContext context2 = rel.getCurrent().advanced().getSourceContext();
		assertThat("context-2 missing", context2, is(notNullValue()));
		assertThat(context2.get(DtlsEndpointContext.KEY_HANDSHAKE_TIMESTAMP),
				not(context1.get(DtlsEndpointContext.KEY_HANDSHAKE_TIMESTAMP)));
		client.shutdown();
	}

	/**
	 * Test observe using a DTLS connection when the observed server changed the
	 * address and a new DTLS session is established using the RELAXED response
	 * matching.
	 */
	@Test
	public void testSecureObserveServerAddressChangedWithNewSessionRelaxedMatching() throws Exception {
		createSecureServer(MatcherMode.RELAXED, null);
		createInverseNat();

		CoapClient client = new CoapClient(uri);
		CountingCoapHandler handler = new CountingCoapHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);

		assertFalse("Observe relation not established!", rel.isCanceled());

		// onLoad is called asynchronous to returning the response
		// therefore wait for one onLoad
		assertTrue(handler.waitOnLoadCalls(1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		assertFalse("Response not received", rel.isCanceled());
		assertThat("Response not received", rel.getCurrent(), is(notNullValue()));
		assertEquals("\"resource says hi for the 1 time\"", rel.getCurrent().getResponseText());

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies", handler.waitOnLoadCalls(REPEATS + 1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		nat.reassignNewLocalAddresses();
		serverConnector.clearConnectionState();
		resource.changed("client");

		assertFalse("Unexpected notifies after address changed",
				handler.waitOnLoadCalls(REPEATS + 2, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));
		assertThat("sending response missing", resource.getCurrentResponse(), is(notNullValue()));
		assertThat("sending response misses error", resource.getCurrentResponse().getSendError(),
				is(instanceOf(EndpointMismatchException.class)));

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertFalse("Unexpected notifies after address changed",
				handler.waitOnLoadCalls(REPEATS + 2, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));
		assertThat("sending response missing", resource.getCurrentResponse(), is(notNullValue()));
		assertThat("sending response misses error", resource.getCurrentResponse().getSendError(),
				is(instanceOf(EndpointMismatchException.class)));
		client.shutdown();
	}

	/**
	 * Test observe using a DTLS connection when the observed server changed the
	 * address and a new DTLS session is established using the PRINCIPAL
	 * matching.
	 */
	@Test
	public void testSecureObserveServerAddressChangedWithNewSessionPrincipalMatching() throws Exception {
		createSecureServer(MatcherMode.PRINCIPAL, null);
		createInverseNat();

		CoapClient client = new CoapClient(uri);
		CountingCoapHandler handler = new CountingCoapHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);

		assertFalse("Observe relation not established!", rel.isCanceled());

		// onLoad is called asynchronous to returning the response
		// therefore wait for one onLoad
		assertTrue(handler.waitOnLoadCalls(1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		assertFalse("Response not received", rel.isCanceled());
		assertThat("Response not received", rel.getCurrent(), is(notNullValue()));
		assertEquals("\"resource says hi for the 1 time\"", rel.getCurrent().getResponseText());

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies", handler.waitOnLoadCalls(REPEATS + 1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		nat.reassignNewLocalAddresses();
		serverConnector.clearConnectionState();
		resource.changed("client");

		assertTrue("Missing notifies", handler.waitOnLoadCalls(REPEATS + 2, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies after address changed",
				handler.waitOnLoadCalls(REPEATS + REPEATS + 2, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));
		assertThat("sending response missing", resource.getCurrentResponse(), is(notNullValue()));
		assertThat("sending response caused error", resource.getCurrentResponse().getSendError(), is(nullValue()));
		client.shutdown();
	}

	/**
	 * Test observe using a DTLS connection when the observed server changed the
	 * address and a new DTLS session is established using a different
	 * PRINCIPAL.
	 */
	@Test
	public void testObserveServerAddressChangedWithNewSessionAndPrincipal() throws Exception {
		createSecureServer(MatcherMode.PRINCIPAL, null);
		createInverseNat();

		CoapClient client = new CoapClient(uri);
		CountingCoapHandler handler = new CountingCoapHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);

		assertFalse("Observe relation not established!", rel.isCanceled());

		// onLoad is called asynchronous to returning the response
		// therefore wait for one onLoad
		assertTrue(handler.waitOnLoadCalls(1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		assertFalse("Response not received", rel.isCanceled());
		assertThat("Response not received", rel.getCurrent(), is(notNullValue()));
		assertEquals("\"resource says hi for the 1 time\"", rel.getCurrent().getResponseText());

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertTrue("Missing notifies", handler.waitOnLoadCalls(REPEATS + 1, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		nat.reassignNewLocalAddresses();
		serverConnector.clearConnectionState();
		// change principal
		setPskCredentials("stranger", "danger");
		resource.changed("client");

		assertFalse("Unexpected notifies after address and principal changed",
				handler.waitOnLoadCalls(REPEATS + 2, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		for (int i = 0; i < REPEATS; ++i) {
			resource.changed("client");
			Thread.sleep(50);
		}

		assertFalse("Unexpected notifies after address and principal changed",
				handler.waitOnLoadCalls(REPEATS + 2, TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));
		assertThat("sending response missing", resource.getCurrentResponse(), is(notNullValue()));
		assertThat("sending response misses error", resource.getCurrentResponse().getSendError(),
				is(instanceOf(EndpointMismatchException.class)));
		client.shutdown();
	}

	private void createSecureServer(MatcherMode mode, ConnectionIdGenerator cidGenerator) {
		serverPskStore = new TestUtilPskStore();

		Configuration config = network.createTestConfig()
				// retransmit constantly all 200 milliseconds
				.set(CoapConfig.ACK_TIMEOUT, 200, TimeUnit.MILLISECONDS)
				.set(CoapConfig.ACK_INIT_RANDOM, 1f)
				.set(CoapConfig.ACK_TIMEOUT_SCALE, 1f)
				// set response timeout (indirect) to 10s
				.set(CoapConfig.EXCHANGE_LIFETIME, 10, TimeUnit.SECONDS)
				.set(CoapConfig.RESPONSE_MATCHING, mode)
				.set(DtlsConfig.DTLS_RECEIVER_THREAD_COUNT, 2)
				.set(DtlsConfig.DTLS_CONNECTOR_THREAD_COUNT, 2);

		DtlsConnectorConfig dtlsConfig = DtlsConnectorConfig.builder(config)
				.setAddress(TestTools.LOCALHOST_EPHEMERAL)
				.setLoggingTag("server")
				.setConnectionIdGenerator(cidGenerator)
				.setAdvancedPskStore(serverPskStore).build();


		serverConnector = new DTLSConnector(dtlsConfig);
		CoapEndpoint.Builder builder = CoapEndpoint.builder();
		builder.setConnector(serverConnector);
		if (mode == MatcherMode.PRINCIPAL) {
			builder.setEndpointContextMatcher(new PrincipalEndpointContextMatcher(true));
		}
		builder.setConfiguration(config);
		serverEndpoint = builder.build();

		CoapServer server = new CoapServer();
		server.addEndpoint(serverEndpoint);
		resource = new MyResource(TARGET);
		server.add(resource);
		server.start();
		cleanup.add(server);

		uri = TestTools.getUri(serverEndpoint, TARGET);

		// prepare secure client endpoint
		clientPskStore = new TestUtilPskStore();
		DtlsConnectorConfig clientdtlsConfig = DtlsConnectorConfig.builder(config)
				.setAddress(TestTools.LOCALHOST_EPHEMERAL)
				.setLoggingTag("client")
				.setConnectionIdGenerator(cidGenerator)
				.setAdvancedPskStore(clientPskStore).build();
		clientConnector = new DTLSConnector(clientdtlsConfig);
		builder = new CoapEndpoint.Builder();
		builder.setConnector(clientConnector);
		builder.setConfiguration(config);
		clientEndpoint = builder.build();
		EndpointManager.getEndpointManager().setDefaultEndpoint(clientEndpoint);
		setPskCredentials(IDENITITY, KEY);
		System.out.println("coap-server " + uri);
		System.out.println("coap-client " + clientEndpoint.getUri());
	}

	private void setPskCredentials(String identity, String key) {
		clientPskStore.set(identity, key.getBytes());
		serverPskStore.set(identity, key.getBytes());
	}

	private void createInverseNat() throws Exception {
		nat = new NioNatUtil(TestTools.LOCALHOST_EPHEMERAL, clientEndpoint.getAddress());
		InetSocketAddress address = serverEndpoint.getAddress();
		int port = nat.assignLocalAddress(address);
		String natURI = uri.replace(":" + address.getPort() + "/", ":" + port + "/");
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
			response.setProtectFromOffload();
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
