/*******************************************************************************
 * Copyright (c) 2018 - 2019 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial creation
 *                                                    Based on the original test
 *                                                    in DTLSConnectorTest.
 *                                                    Updated to use ConnectorHelper
 ******************************************************************************/
package org.eclipse.californium.scandium;

import static org.eclipse.californium.scandium.ConnectorHelper.newStandardClientConfig;
import static org.eclipse.californium.scandium.ConnectorHelper.newStandardClientConfigBuilder;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.auth.AdditionalInfo;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.rule.ThreadsRule;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.SimpleMessageCallback;
import org.eclipse.californium.elements.util.TestThreadFactory;
import org.eclipse.californium.scandium.ConnectorHelper.LatchDecrementingRawDataChannel;
import org.eclipse.californium.scandium.auth.ApplicationLevelInfoSupplier;
import org.eclipse.californium.scandium.category.Medium;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.ClientSessionCache;
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.InMemoryClientSessionCache;
import org.eclipse.californium.scandium.dtls.InMemoryConnectionStore;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.SessionId;
import org.eclipse.californium.scandium.dtls.SessionTicket;
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

	@ClassRule
	public static ThreadsRule cleanup = new ThreadsRule();

	static ConnectorHelper serverHelper;

	static ExecutorService executor;

	private static final int CLIENT_CONNECTION_STORE_CAPACITY = 5;
	private static final int MAX_TIME_TO_WAIT_SECS = 2;
	private static final String DEVICE_ID = "the-device";
	private static final String KEY_DEVICE_ID = "device-id";

	@Rule
	public TestNameLoggerRule names = new TestNameLoggerRule();

	DTLSConnector client;
	InMemoryConnectionStore clientConnectionStore;
	List<Record> lastReceivedFlight;

	/**
	 * Starts the server side DTLS connector.
	 * 
	 * @throws Exception if the connector cannot be started.
	 */
	@BeforeClass
	public static void startServer() throws Exception {

		Map<String, Object> info = new HashMap<>();
		info.put(KEY_DEVICE_ID, DEVICE_ID);
		final AdditionalInfo applicationLevelInfo = AdditionalInfo.from(info);

		ApplicationLevelInfoSupplier supplier = new ApplicationLevelInfoSupplier() {

			@Override
			public AdditionalInfo getInfo(Principal clientIdentity) {
				return applicationLevelInfo;
			}
		};
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setSniEnabled(true)
				.setApplicationLevelInfoSupplier(supplier);
		serverHelper = new ConnectorHelper();
		serverHelper.startServer(builder);
		executor = ExecutorsUtil.newFixedThreadPool(2, new TestThreadFactory("DTLS-RESUME-"));
	}

	@AfterClass
	public static void tearDown() {
		serverHelper.destroyServer();
		ExecutorsUtil.shutdownExecutorGracefully(100, executor);
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

	private void autoResumeSetUp(Long timeout) throws Exception {
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
		SessionId sessionId = serverHelper.establishedServerSession.getSessionIdentifier();

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverHelper.serverEndpoint);
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		long time = sessions.get(sessionId).getTimestamp();

		// create a new client with different inetAddress but with the same session store.
		clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 10001);
		clientConfig = newStandardClientConfig(clientEndpoint);
		clientConnectionStore = new InMemoryConnectionStore(CLIENT_CONNECTION_STORE_CAPACITY, 60, sessions);
		clientConnectionStore.setTag("client-after");
		client = new DTLSConnector(clientConfig, clientConnectionStore);
		LatchDecrementingRawDataChannel clientRawDataChannel = new LatchDecrementingRawDataChannel(1);
		client.setRawDataReceiver(clientRawDataChannel);
		client.start();

		// Prepare message sending
		final String msg = "Hello Again";

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		assertThat(time, is(connection.getEstablishedSession().getCreationTime()));
		assertClientIdentity(RawPublicKeyIdentity.class);
	}

	@Test
	public void testConnectorAutoResumesSession() throws Exception {

		autoResumeSetUp(500L);

		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, false);

		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		SessionId sessionId = connection.getSession().getSessionIdentifier();
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));
		assertThat(connection.isAutoResumptionRequired(500L), is(false));

		Thread.sleep(1000);

		assertThat(connection.isAutoResumptionRequired(500L), is(true));
		
		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		assertClientIdentity(RawPublicKeyIdentity.class);

		// check, if session is established again
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(2));
	}

	@Test
	public void testConnectorNoAutoResumesSession() throws Exception {

		autoResumeSetUp(1000L);

		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, false);

		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));
		assertThat(connection.isAutoResumptionRequired(1000L), is(false));
		Thread.sleep(750);
		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		Thread.sleep(750);

		assertThat(connection.isAutoResumptionRequired(1000L), is(false));
		// check, if session is established again
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));
	}

	@Test
	public void testConnectorSupressAutoResumesSession() throws Exception {
		autoResumeSetUp(500L);

		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, false);

		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		SessionId sessionId = connection.getSession().getSessionIdentifier();
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));

		Thread.sleep(1000);

		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		EndpointContext context = new MapBasedEndpointContext(serverHelper.serverEndpoint, null, DtlsEndpointContext.KEY_RESUMPTION_TIMEOUT, "");
		RawData data = RawData.outbound(msg.getBytes(), context, null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		assertClientIdentity(RawPublicKeyIdentity.class);

		// check, if session is established again
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));
	}

	@Test
	public void testConnectorChangedAutoResumesSession() throws Exception {
		autoResumeSetUp(500L);

		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, false);

		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		SessionId sessionId = connection.getSession().getSessionIdentifier();
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));
		assertThat(connection.isAutoResumptionRequired(500L), is(false));

		Thread.sleep(1000);

		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		EndpointContext context = new MapBasedEndpointContext(serverHelper.serverEndpoint, null, DtlsEndpointContext.KEY_RESUMPTION_TIMEOUT, "10000");
		RawData data = RawData.outbound(msg.getBytes(), context, null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
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

		// save session ticket
		SessionTicket sessionTicket = serverHelper.establishedServerSession.getSessionTicket();
		assertThat(sessionTicket, is(notNullValue()));
		// remove connection from server's connection store
		serverHelper.remove(clientAddress, true);
		assertThat(serverHelper.serverSessionCache.get(establishedSessionId), is(nullValue()));
		// add ticket to session cache to mimic a fail over from another node
		serverHelper.serverSessionCache.put(establishedSessionId, sessionTicket);

		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(establishedSessionId));
		assertClientIdentity(RawPublicKeyIdentity.class);
	}

	@Test
	public void testConnectorResumesSessionFromExistingConnection() throws Exception {
		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client);
		SessionId sessionId = serverHelper.establishedServerSession.getSessionIdentifier();

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverHelper.serverEndpoint);
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		client.start();

		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		assertClientIdentity(RawPublicKeyIdentity.class);
	}

	@Test
	public void testConnectorResumesSessionFromHiddenConnection() throws Exception {
		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client);
		InetSocketAddress clientAddress = clientRawDataChannel.getAddress();
		SessionId sessionId = serverHelper.establishedServerSession.getSessionIdentifier();
		int remainingCapacity = serverHelper.serverConnectionStore.remainingCapacity();

		// second client with same address
		InMemoryConnectionStore clientConnectionStore2 = new InMemoryConnectionStore(CLIENT_CONNECTION_STORE_CAPACITY, 60);
		clientConnectionStore2.setTag("client-2");
		DtlsConnectorConfig.Builder builder2 = newStandardClientConfigBuilder(clientAddress)
				.setSniEnabled(true)
				.setMaxConnections(CLIENT_CONNECTION_STORE_CAPACITY);
		DtlsConnectorConfig clientConfig2 = builder2.build();

		DTLSConnector client2 = new DTLSConnector(clientConfig2, clientConnectionStore2);
		client2.setExecutor(executor);
		serverHelper.givenAnEstablishedSession(client2);
		int remainingCapacity2 = serverHelper.serverConnectionStore.remainingCapacity();
		assertThat(remainingCapacity2, is(remainingCapacity - 1));

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverHelper.serverEndpoint);
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		client.start();

		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		assertClientIdentity(RawPublicKeyIdentity.class);
		remainingCapacity2 = serverHelper.serverConnectionStore.remainingCapacity();
		assertThat(remainingCapacity2, is(remainingCapacity - 1));
	}

	public void testConnectorResumesSessionFromClosedConnection() throws Exception {
		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, false);
		SessionId sessionId = serverHelper.establishedServerSession.getSessionIdentifier();
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		String lastHandshakeTime = connection.getEstablishedSession().getLastHandshakeTime();
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));

		// send close notify, close connection
		client.close(serverHelper.serverEndpoint);

		// close is asynchronous, wait for execution completed.
		for (int loop = 0; loop < 20 && !connection.isResumptionRequired(); ++loop) {
			Thread.sleep(100);
		}
		assertThat(connection.isResumptionRequired(), is(true));

		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		assertClientIdentity(RawPublicKeyIdentity.class);
		assertThat(lastHandshakeTime, is(not(connection.getEstablishedSession().getLastHandshakeTime())));
	}

	@Test
	public void testConnectorForceResumeSession() throws Exception {
		autoResumeSetUp(null);

		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, false);

		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		SessionId sessionId = connection.getSession().getSessionIdentifier();
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));

		Thread.sleep(500);

		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		EndpointContext context = new MapBasedEndpointContext(serverHelper.serverEndpoint, null,
				DtlsEndpointContext.KEY_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_FORCE);
		RawData data = RawData.outbound(msg.getBytes(), context, null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		assertClientIdentity(RawPublicKeyIdentity.class);

		// check, if session is established again
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(2));
	}

	@Test
	public void testConnectorForceFullHandshake() throws Exception {
		autoResumeSetUp(null);

		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, false);

		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		SessionId sessionId = connection.getSession().getSessionIdentifier();
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));

		Thread.sleep(500);

		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		EndpointContext context = new MapBasedEndpointContext(serverHelper.serverEndpoint, null,
				DtlsEndpointContext.KEY_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_FORCE_FULL);
		RawData data = RawData.outbound(msg.getBytes(), context, null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), not(equalTo(sessionId)));
		assertClientIdentity(RawPublicKeyIdentity.class);

		// check, if session is established again
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(2));
	}

	@Test
	public void testConnectorPerformsFullHandshakeWhenResumingNonExistingSession() throws Exception {
		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client);
		InetSocketAddress clientAddress = clientRawDataChannel.getAddress();
		SessionId sessionId = serverHelper.establishedServerSession.getSessionIdentifier();

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverHelper.serverEndpoint);
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		client.start();

		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// remove session from server
		serverHelper.remove(clientAddress, true);
		
		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check session id was not equals
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), not(equalTo(sessionId)));
		assertClientIdentity(RawPublicKeyIdentity.class);
	}

	@Test
	public void testConnectorPerformsFullHandshakeWhenResumingWithDifferentSni() throws Exception {
		// Do a first handshake
		RawData raw = RawData.outbound("Hello World".getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint, "server.one", null), null, false);
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, raw, true);
		SessionId sessionId = serverHelper.establishedServerSession.getSessionIdentifier();

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverHelper.serverEndpoint);
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		client.start();

		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint, "server.two", null), null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check session id was not equals
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), not(equalTo(sessionId)));
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
			clientRawDataChannel.setLatchCount(1);

			// send message
			RawData data = RawData.outbound(msg.getBytes(),
					new AddressEndpointContext(serverWithoutSessionId.serverEndpoint, "server.no", null), null, false);
			client.send(data);
			assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// check session id was not equals
			connection = clientConnectionStore.get(serverWithoutSessionId.serverEndpoint);
			assertTrue(connection.getEstablishedSession().getSessionIdentifier().isEmpty());
			assertThat(time, is(not(connection.getEstablishedSession().getCreationTime())));
		} finally {
			serverWithoutSessionId.destroyServer();
		}
	}

	@Test
	public void testConnectorSupressHandshake() throws Exception {
		autoResumeSetUp(null);

		// suppress handshake
		SimpleMessageCallback callback = new SimpleMessageCallback(1, false);
		EndpointContext context = new MapBasedEndpointContext(serverHelper.serverEndpoint, null,
				DtlsEndpointContext.KEY_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_NONE);
		RawData raw = RawData.outbound("Hello World".getBytes(), context, callback, false);

		client.start();
		client.send(raw);
		assertNotNull(callback.getError(TimeUnit.SECONDS.toMillis(MAX_TIME_TO_WAIT_SECS)));
		Connection con = serverHelper.serverConnectionStore.get(client.getAddress());
		assertNull(con);
	}

	@Test
	public void testConnectorRequiresResumptionSupressHandshake() throws Exception {
		// Do a first handshake
		serverHelper.givenAnEstablishedSession(client);
		SessionId sessionId = serverHelper.establishedServerSession.getSessionIdentifier();

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverHelper.serverEndpoint);
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));

		// suppress handshake
		SimpleMessageCallback callback = new SimpleMessageCallback(1, false);
		EndpointContext context = new MapBasedEndpointContext(serverHelper.serverEndpoint, null,
				DtlsEndpointContext.KEY_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_NONE);
		RawData raw = RawData.outbound("Hello World".getBytes(), context, callback, false);
		client.start();
		client.send(raw);
		assertNotNull(callback.getError(TimeUnit.SECONDS.toMillis(MAX_TIME_TO_WAIT_SECS)));
		Connection con = serverHelper.serverConnectionStore.get(client.getAddress());
		assertNull(con);
	}

	private void assertClientIdentity(final Class<?> principalType) {

		Principal clientIdentity = serverHelper.serverRawDataProcessor.getClientEndpointContext().getPeerIdentity();
		// assert that client identity is of given type
		if (principalType == null) {
			assertThat(clientIdentity, is(nullValue()));
		} else {
			assertThat(clientIdentity, instanceOf(principalType));
			ConnectorHelper.assertPrincipalHasAdditionalInfo(clientIdentity, KEY_DEVICE_ID, DEVICE_ID);
		}
	}
}
