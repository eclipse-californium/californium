/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial creation
 *                                                    Based on the original test
 *                                                    in DTLSConnectorTest.
 *                                                    Updated to use ConnectorHelper
 ******************************************************************************/
package org.eclipse.californium.scandium;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;
import static org.eclipse.californium.scandium.ConnectorHelper.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.scandium.ConnectorHelper.LatchDecrementingRawDataChannel;
import org.eclipse.californium.scandium.category.Medium;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.ClientSessionCache;
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.InMemoryClientSessionCache;
import org.eclipse.californium.scandium.dtls.InMemoryConnectionStore;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.SessionId;
import org.eclipse.californium.scandium.rule.DtlsNetworkRule;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies behavior of {@link DTLSConnector}.
 * <p>
 * Mainly contains integration test cases verifying the correct interaction
 * between a client and a server during resumption handshakes.
 */
@Category(Medium.class)
public class DTLSConnectorResumeTest {

	public static final Logger LOGGER = LoggerFactory.getLogger(DTLSConnectorResumeTest.class.getName());

	@ClassRule
	public static DtlsNetworkRule network = new DtlsNetworkRule(DtlsNetworkRule.Mode.DIRECT,
			DtlsNetworkRule.Mode.NATIVE);

	@Rule
	public TestNameLoggerRule names = new TestNameLoggerRule();

	private static final int CLIENT_CONNECTION_STORE_CAPACITY = 5;
	private static final int MAX_TIME_TO_WAIT_SECS = 2;

	static ConnectorHelper serverHelper;

	static ExecutorService executor;

	DTLSConnector client;
	InMemoryConnectionStore clientConnectionStore;
	List<Record> lastReceivedFlight;

	@BeforeClass
	public static void loadKeys() throws IOException, GeneralSecurityException {
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setSniEnabled(true);
		serverHelper = new ConnectorHelper();
		serverHelper.startServer(builder);
		executor = Executors.newFixedThreadPool(2);
	}

	@AfterClass
	public static void tearDown() {
		serverHelper.destroyServer();
		executor.shutdownNow();
	}

	@Before
	public void setUp() throws Exception {
		clientConnectionStore = new InMemoryConnectionStore(CLIENT_CONNECTION_STORE_CAPACITY, 60);
		clientConnectionStore.setTag("client");
		InetSocketAddress clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
		DtlsConnectorConfig.Builder builder = newStandardClientConfigBuilder(clientEndpoint)
				.setSniEnabled(true)
				.setMaxConnections(CLIENT_CONNECTION_STORE_CAPACITY);
		DtlsConnectorConfig clientConfig = builder.build();

		client = new DTLSConnector(clientConfig, clientConnectionStore);
		client.setExecutor(executor);
	}

	@After
	public void cleanUp() {
		if (client != null) {
			client.destroy();
		}
		lastReceivedFlight = null;
		serverHelper.cleanUpServer();
	}

	private void autoResumeSetUp(long timeout) throws Exception {
		cleanUp();
		serverHelper.serverSessionCache.establishedSessionCounter.set(0);
		clientConnectionStore = new InMemoryConnectionStore(CLIENT_CONNECTION_STORE_CAPACITY, 60);
		clientConnectionStore.setTag("client");
		InetSocketAddress clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
		DtlsConnectorConfig.Builder clientConfigBuilder = newStandardClientConfigBuilder(clientEndpoint);
		clientConfigBuilder.setAutoResumptionTimeoutMillis(timeout);
		DtlsConnectorConfig clientConfig = clientConfigBuilder.build();
		client = new DTLSConnector(clientConfig, clientConnectionStore);
		client.setExecutor(executor);
	}

	@Test
	public void testConnectorResumesSessionFromNewConnection() throws Exception {
		ClientSessionCache sessions = new InMemoryClientSessionCache();
		clientConnectionStore = new InMemoryConnectionStore(CLIENT_CONNECTION_STORE_CAPACITY, 60, sessions);
		clientConnectionStore.setTag("client-before");
		InetSocketAddress clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 10000);
		DtlsConnectorConfig clientConfig = newStandardClientConfig(clientEndpoint);

		client = new DTLSConnector(clientConfig, clientConnectionStore);
		client.setExecutor(executor);

		serverHelper.givenAnEstablishedSession(client);
		client.stop();
		byte[] sessionId = serverHelper.establishedServerSession.getSessionIdentifier().getBytes();

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverHelper.serverEndpoint);
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getBytes());
		long time = connection.getEstablishedSession().getCreationTime();

		// create a new client with different inetAddress but with the same session store.
		clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 10001);
		clientConfig = newStandardClientConfig(clientEndpoint);
		clientConnectionStore = new InMemoryConnectionStore(CLIENT_CONNECTION_STORE_CAPACITY, 60, sessions);
		clientConnectionStore.setTag("client-after");
		client = new DTLSConnector(clientConfig, clientConnectionStore);
		LatchDecrementingRawDataChannel clientRawDataChannel = new LatchDecrementingRawDataChannel(client);
		client.setRawDataReceiver(clientRawDataChannel);
		client.start();

		// Prepare message sending
		final String msg = "Hello Again";
		CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);
		assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getBytes());
		assertThat(time, is(connection.getEstablishedSession().getCreationTime()));
		assertClientIdentity(RawPublicKeyIdentity.class);
	}

	@Test
	public void testConnectorAutoResumesSession() throws Exception {

		autoResumeSetUp(500);

		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, false);

		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		byte[] sessionId = connection.getSession().getSessionIdentifier().getBytes();
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));
		assertThat(connection.isAutoResumptionRequired(500L), is(false));

		Thread.sleep(1000);

		assertThat(connection.isAutoResumptionRequired(500L), is(true));
		
		// Prepare message sending
		final String msg = "Hello Again";
		CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);
		assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getBytes());
		assertClientIdentity(RawPublicKeyIdentity.class);

		// check, if session is established again
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(2));
	}

	@Test
	public void testConnectorNoAutoResumesSession() throws Exception {

		autoResumeSetUp(1000);

		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, false);

		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));
		assertThat(connection.isAutoResumptionRequired(1000L), is(false));
		Thread.sleep(750);
		// Prepare message sending
		final String msg = "Hello Again";
		CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);
		assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		Thread.sleep(750);

		assertThat(connection.isAutoResumptionRequired(1000L), is(false));
		// check, if session is established again
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));
	}

	@Test
	public void testConnectorForceAutoResumesSession() throws Exception {
		autoResumeSetUp(1000);

		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, false);

		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		byte[] sessionId = connection.getSession().getSessionIdentifier().getBytes();
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));

		Thread.sleep(500);

		// Prepare message sending
		final String msg = "Hello Again";
		CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);

		// send message
		EndpointContext context = new MapBasedEndpointContext(serverHelper.serverEndpoint, null, DtlsEndpointContext.KEY_RESUMPTION_TIMEOUT, "0");
		RawData data = RawData.outbound(msg.getBytes(), context, null, false);
		client.send(data);
		assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getBytes());
		assertClientIdentity(RawPublicKeyIdentity.class);

		// check, if session is established again
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(2));
	}

	@Test
	public void testConnectorSupressAutoResumesSession() throws Exception {
		autoResumeSetUp(500);

		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, false);

		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		byte[] sessionId = connection.getSession().getSessionIdentifier().getBytes();
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));

		Thread.sleep(1000);

		// Prepare message sending
		final String msg = "Hello Again";
		CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);

		// send message
		EndpointContext context = new MapBasedEndpointContext(serverHelper.serverEndpoint, null, DtlsEndpointContext.KEY_RESUMPTION_TIMEOUT, "");
		RawData data = RawData.outbound(msg.getBytes(), context, null, false);
		client.send(data);
		assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getBytes());
		assertClientIdentity(RawPublicKeyIdentity.class);

		// check, if session is established again
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));
	}

	@Test
	public void testConnectorChangedAutoResumesSession() throws Exception {
		autoResumeSetUp(500);

		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, false);

		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		byte[] sessionId = connection.getSession().getSessionIdentifier().getBytes();
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));
		assertThat(connection.isAutoResumptionRequired(500L), is(false));

		Thread.sleep(1000);

		// Prepare message sending
		final String msg = "Hello Again";
		CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);

		// send message
		EndpointContext context = new MapBasedEndpointContext(serverHelper.serverEndpoint, null, DtlsEndpointContext.KEY_RESUMPTION_TIMEOUT, "10000");
		RawData data = RawData.outbound(msg.getBytes(), context, null, false);
		client.send(data);
		assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getBytes());
		assertClientIdentity(RawPublicKeyIdentity.class);

		// check, if session is established again
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));
	}

	@Test
	public void testConnectorResumesSessionFromSharedSessionTicket() throws Exception {
		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client);
		InetSocketAddress clientAddress = clientRawDataChannel.getAddress();
		SessionId establishedSessionId = serverHelper.establishedServerSession.getSessionIdentifier();

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverHelper.serverEndpoint);
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(establishedSessionId));
		client.start();

		// remove connection from server's connection store and add ticket to session cache
		// to mimic a fail over from another node
		serverHelper.remove(clientAddress, true);
		assertThat(serverHelper.serverSessionCache.get(establishedSessionId), is(nullValue()));
		serverHelper.serverSessionCache.put(establishedSessionId, serverHelper.establishedServerSession.getSessionTicket());

		// Prepare message sending
		final String msg = "Hello Again";
		CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);
		assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(establishedSessionId));
		assertClientIdentity(RawPublicKeyIdentity.class);
	}

	@Test
	public void testConnectorResumesSessionFromExistingConnection() throws Exception {
		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client);
		byte[] sessionId = serverHelper.establishedServerSession.getSessionIdentifier().getBytes();

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverHelper.serverEndpoint);
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getBytes());
		client.start();

		// Prepare message sending
		final String msg = "Hello Again";
		CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);
		assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getBytes());
		assertClientIdentity(RawPublicKeyIdentity.class);
	}

	@Test
	public void testConnectorPerformsFullHandshakeWhenResumingNonExistingSession() throws Exception {
		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client);
		InetSocketAddress clientAddress = clientRawDataChannel.getAddress();
		byte[] sessionId = serverHelper.establishedServerSession.getSessionIdentifier().getBytes();

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverHelper.serverEndpoint);
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getBytes());
		client.start();

		// Prepare message sending
		final String msg = "Hello Again";
		CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);

		// remove session from server
		serverHelper.remove(clientAddress, true);
		
		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);
		assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check session id was not equals
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(sessionId, not(equalTo(connection.getEstablishedSession().getSessionIdentifier().getBytes())));
		assertClientIdentity(RawPublicKeyIdentity.class);
	}

	@Test
	public void testConnectorPerformsFullHandshakeWhenResumingWithDifferentSni() throws Exception {
		// Do a first handshake
		RawData raw = RawData.outbound("Hello World".getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint, "server.one", null), null, false);
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, raw, true);
		byte[] sessionId = serverHelper.establishedServerSession.getSessionIdentifier().getBytes();

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverHelper.serverEndpoint);
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getBytes());
		client.start();

		// Prepare message sending
		final String msg = "Hello Again";
		CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint, "server.two", null), null, false);
		client.send(data);
		assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check session id was not equals
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(sessionId, not(equalTo(connection.getEstablishedSession().getSessionIdentifier().getBytes())));
		assertClientIdentity(RawPublicKeyIdentity.class);
	}

	@Test
	public void testConnectorPerformsFullHandshakeWhenResumingWithEmptySessionId() throws Exception {
		ConnectorHelper serverWithoutSessionId = new ConnectorHelper();
		try {
			DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
			builder.setNoServerSessionId(true);
			serverWithoutSessionId.startServer(builder);

			// Do a first handshake
			RawData raw = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(serverWithoutSessionId.serverEndpoint, "server.no", null), null, false);
			LatchDecrementingRawDataChannel clientRawDataChannel = serverWithoutSessionId
					.givenAnEstablishedSession(client, raw, true);
			SessionId sessionId = serverWithoutSessionId.establishedServerSession.getSessionIdentifier();
			assertTrue("session id must be empty", sessionId.isEmpty());
			
			// Force a resume session the next time we send data
			client.forceResumeSessionFor(serverWithoutSessionId.serverEndpoint);
			Connection connection = clientConnectionStore.get(serverWithoutSessionId.serverEndpoint);
			assertTrue(connection.getEstablishedSession().getSessionIdentifier().isEmpty());
			long time = connection.getEstablishedSession().getCreationTime();
			client.start();

			// Prepare message sending
			final String msg = "Hello Again";
			CountDownLatch latch = new CountDownLatch(1);
			clientRawDataChannel.setLatch(latch);

			// send message
			RawData data = RawData.outbound(msg.getBytes(),
					new AddressEndpointContext(serverWithoutSessionId.serverEndpoint, "server.no", null), null, false);
			client.send(data);
			assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// check session id was not equals
			connection = clientConnectionStore.get(serverWithoutSessionId.serverEndpoint);
			assertTrue(connection.getEstablishedSession().getSessionIdentifier().isEmpty());
			assertThat(time, is(not(connection.getEstablishedSession().getCreationTime())));
		} finally {
			serverWithoutSessionId.destroyServer();
		}
	}

	private void assertClientIdentity(final Class<?> principalType) {

		// assert that client identity is of given type
		if (principalType == null) {
			assertThat(serverHelper.serverRawDataProcessor.getClientEndpointContext().getPeerIdentity(), is(nullValue()));
		} else {
			assertThat(serverHelper.serverRawDataProcessor.getClientEndpointContext().getPeerIdentity(), instanceOf(principalType));
		}
	}
}
