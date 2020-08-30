/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *                                                    Update to use ConnectorHelper
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce waitForFlightReceived
 *                                                    with additional retransmission
 *                                                    compensation for faster timeouts
 *    Achim Kraus (Bosch Software Innovations GmbH) - add test for timeout of handshaker
 *                                                    with stopped retransmission
 ******************************************************************************/
package org.eclipse.californium.scandium;

import static org.eclipse.californium.scandium.ConnectorHelper.CLIENT_IDENTITY;
import static org.eclipse.californium.scandium.ConnectorHelper.CLIENT_IDENTITY_SECRET;
import static org.eclipse.californium.scandium.ConnectorHelper.SCOPED_CLIENT_IDENTITY;
import static org.eclipse.californium.scandium.ConnectorHelper.SCOPED_CLIENT_IDENTITY_SECRET;
import static org.eclipse.californium.scandium.ConnectorHelper.SERVERNAME;
import static org.eclipse.californium.scandium.ConnectorHelper.newStandardClientConfigBuilder;
import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.SecretKey;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.rule.TestTimeRule;
import org.eclipse.californium.elements.rule.ThreadsRule;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.SerialExecutor;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.elements.util.TestConditionTools;
import org.eclipse.californium.elements.util.TestScheduledExecutorService;
import org.eclipse.californium.elements.util.TestScope;
import org.eclipse.californium.elements.util.TestThreadFactory;
import org.eclipse.californium.scandium.ConnectorHelper.LatchSessionListener;
import org.eclipse.californium.scandium.ConnectorHelper.RecordCollectorDataHandler;
import org.eclipse.californium.scandium.ConnectorHelper.SessionState;
import org.eclipse.californium.scandium.ConnectorHelper.UdpConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AdversaryClientHandshaker;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.ApplicationMessage;
import org.eclipse.californium.scandium.dtls.ClientHandshaker;
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.ConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.ContentType;
import org.eclipse.californium.scandium.dtls.DTLSMessage;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.DtlsHandshakeTimeoutException;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.Handshaker;
import org.eclipse.californium.scandium.dtls.InMemoryConnectionStore;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.RecordLayer;
import org.eclipse.californium.scandium.dtls.ResumingClientHandshaker;
import org.eclipse.californium.scandium.dtls.ResumingServerHandshaker;
import org.eclipse.californium.scandium.dtls.ServerHandshaker;
import org.eclipse.californium.scandium.dtls.SingleNodeConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.cipher.RandomManager;
import org.eclipse.californium.scandium.dtls.pskstore.AsyncInMemoryPskStore;
import org.eclipse.californium.scandium.dtls.pskstore.InMemoryPskStore;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.eclipse.californium.scandium.rule.DtlsNetworkRule;
import org.eclipse.californium.scandium.util.ServerNames;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies behavior of {@link DTLSConnector}.
 * <p>
 * Mainly contains integration test cases verifying the correct interaction
 * between a client and a server during handshakes including unusual message
 * order and timeouts.
 */
@RunWith(Parameterized.class)
@Category(Medium.class)
public class DTLSConnectorAdvancedTest {

	public static final Logger LOGGER = LoggerFactory.getLogger(DTLSConnectorAdvancedTest.class);

	@ClassRule
	public static DtlsNetworkRule network = new DtlsNetworkRule(DtlsNetworkRule.Mode.DIRECT,
			DtlsNetworkRule.Mode.NATIVE);

	@ClassRule
	public static ThreadsRule cleanup = new ThreadsRule();

	@Rule
	public TestNameLoggerRule names = new TestNameLoggerRule();

	@Rule
	public TestTimeRule time = new TestTimeRule();

	private static final int CLIENT_CONNECTION_STORE_CAPACITY = 5;
	private static final int MAX_TIME_TO_WAIT_SECS = 2;
	private static final int RETRANSMISSION_TIMEOUT_MS = 400;
	private static final int MAX_RETRANSMISSIONS = 2;

	static AsyncInMemoryPskStore aPskStore;
	static int aPskStoreResponses = 1;
	static ConnectorHelper serverHelper;
	static DtlsHealthLogger serverHealth;
	static DtlsHealthLogger clientHealth;

	static TestScheduledExecutorService timer;
	static ExecutorService executor;
	static ConnectionIdGenerator serverCidGenerator;
	static DtlsConnectorConfig serverConfigSingleRecord;

	ConnectorHelper alternativeServerHelper;
	DtlsConnectorConfig clientConfig;
	DtlsConnectorConfig clientConfigSingleRecord;
	DTLSConnector client;
	InMemoryConnectionStore clientConnectionStore;
	List<Record> lastReceivedFlight;
	List<Record> lastSentFlight;

	@BeforeClass
	public static void loadKeys() throws IOException, GeneralSecurityException {
		serverHealth = new DtlsHealthLogger("server");
		serverCidGenerator = new SingleNodeConnectionIdGenerator(6);
		InMemoryPskStore pskStore = new InMemoryPskStore();
		pskStore.setKey(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes());
		pskStore.setKey(SCOPED_CLIENT_IDENTITY, SCOPED_CLIENT_IDENTITY_SECRET.getBytes(), SERVERNAME);
		aPskStore = new AsyncInMemoryPskStore(pskStore) {

			@Override
			public PskSecretResult requestPskSecretResult(final ConnectionId cid, final ServerNames serverNames,
					final PskPublicInformation identity, final String hmacAlgorithm, SecretKey otherSecret,
					byte[] seed) {
				for (int index = 0; index < aPskStoreResponses; ++index) {
					super.requestPskSecretResult(cid, serverNames, identity, hmacAlgorithm, otherSecret, seed);
				}
				return null;
			}
		};
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setRetransmissionTimeout(RETRANSMISSION_TIMEOUT_MS)
				.setMaxRetransmissions(MAX_RETRANSMISSIONS)
				.setConnectionIdGenerator(serverCidGenerator)
				.setHealthHandler(serverHealth)
				.setAdvancedPskStore(aPskStore);
		serverHelper = new ConnectorHelper();
		serverHelper.startServer(builder);
		serverConfigSingleRecord = new DtlsConnectorConfig.Builder(serverHelper.serverConfig)
				.setEnableMultiRecordMessages(false).build();
		executor = ExecutorsUtil.newFixedThreadPool(2, new TestThreadFactory("DTLS-ADVANCED-"));
		timer = new TestScheduledExecutorService();
		clientHealth = new DtlsHealthLogger("client");
	}

	@AfterClass
	public static void tearDown() {
		if (aPskStore != null) {
			aPskStore.shutdown();
			aPskStore = null;
		}
		serverHelper.destroyServer();
		timer.shutdown();
		ExecutorsUtil.shutdownExecutorGracefully(100, executor);
	}

	/**
	 * Actual cipher suite.
	 */
	@Parameter
	public ConnectionIdGenerator clientCidGenerator;

	/**
	 * @return List of cipher suites.
	 */
	@Parameters(name = "cid = {0}")
	public static Iterable<ConnectionIdGenerator> cidParams() {
		if (TestScope.enableIntensiveTests()) {
			return Arrays.asList((ConnectionIdGenerator) null
			, new SingleNodeConnectionIdGenerator(0) {

				public String toString() {
					return "cid supported";
				}
			}, new SingleNodeConnectionIdGenerator(5) {

				public String toString() {
					return "cid used";
				}
			});
		} else {
			return Arrays.asList((ConnectionIdGenerator) null);
		}
	}

	@Before
	public void setUp() throws Exception {
		aPskStoreResponses = 1;
		clientConnectionStore = new InMemoryConnectionStore(CLIENT_CONNECTION_STORE_CAPACITY, 60);
		clientConnectionStore.setTag("client");
		InetSocketAddress clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
		DtlsConnectorConfig.Builder builder = newStandardClientConfigBuilder(clientEndpoint)
				.setRetransmissionTimeout(RETRANSMISSION_TIMEOUT_MS)
				.setMaxRetransmissions(MAX_RETRANSMISSIONS)
				.setMaxConnections(CLIENT_CONNECTION_STORE_CAPACITY)
				.setConnectionIdGenerator(clientCidGenerator)
				.setHealthHandler(clientHealth);
		clientConfig = builder.build();
		clientConfigSingleRecord = new DtlsConnectorConfig.Builder(clientConfig)
				.setEnableMultiRecordMessages(false)
				.setLoggingTag("client")
				.build();
		client = serverHelper.createClient(clientConfig, clientConnectionStore);
		client.setExecutor(executor);
		clientHealth.reset();
	}

	@After
	public void cleanUp() {
		timer.cancelAll();
		if (alternativeServerHelper != null) {
			alternativeServerHelper.destroyServer();
		}
		if (client != null) {
			client.destroy();
		}
		lastReceivedFlight = null;
		serverHelper.cleanUpServer();
		TestConditionTools.assertStatisticCounter("server", serverHealth, "dropped received records", is(0L));
		TestConditionTools.assertStatisticCounter("server", serverHealth, "dropped sending records", is(0L));
		TestConditionTools.assertStatisticCounter("client", clientHealth, "dropped received records", is(0L));
		TestConditionTools.assertStatisticCounter("client", clientHealth, "dropped sending records", is(0L));
		clientHealth.reset();
		serverHealth.reset();
	}

	@Test
	public void testServerReceivingMessagesInBadOrderDuringHandshake() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(0, collector);
		try {

			// Start connector
			rawClient.start();

			// Create handshaker with ReverseRecordLayer
			// to send message in bad order.
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(new DTLSSession(serverHelper.serverEndpoint),
					new TestRecordLayer(rawClient, true), timer, createClientConnection(), clientConfigSingleRecord,
					false);
			clientHandshaker.addSessionListener(sessionListener);
			// Start handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer (FINISHED, CHANGE CIPHER SPEC, ...,CERTIFICATE)
			processAll(clientHandshaker, rs);

			// Wait to receive response (should be CHANGE CIPHER SPEC, FINISHED)
			rs = waitForFlightReceived("flight 6", collector, 2);
			// Handle it
			processAll(clientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("server", rawClient, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
		} finally {
			rawClient.stop();
		}
	}

	@Test
	public void testLimitedServerReceivingMessagesInBadOrderDuringHandshake() throws Exception {
		alternativeServerHelper = new ConnectorHelper();

		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setRetransmissionTimeout(RETRANSMISSION_TIMEOUT_MS * 2)
				.setMaxRetransmissions(MAX_RETRANSMISSIONS * 2)
				.setMaxDeferredProcessedIncomingRecordsSize(96)
				.setHealthHandler(serverHealth)
				.setConnectionIdGenerator(serverCidGenerator);

		DtlsConnectorConfig clientConfigSingleRecord = new DtlsConnectorConfig.Builder(this.clientConfigSingleRecord)
				.setMaxRetransmissions(MAX_RETRANSMISSIONS * 2).build();

		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(0, collector);
		TestRecordLayer recordLayer = new TestRecordLayer(rawClient, true);
		try {
			// create limited server
			alternativeServerHelper.startServer(builder);

			// Start connector
			rawClient.start();

			// Create handshaker with ReverseRecordLayer
			// to send message in bad order.
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(
					new DTLSSession(alternativeServerHelper.serverEndpoint), recordLayer, timer, createClientConnection(),
					clientConfigSingleRecord, false);
			clientHandshaker.addSessionListener(sessionListener);
			// Start handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);
			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(0L));

			// Handle and answer, reverse order (FINISHED, CHANGE CIPHER SPEC, ..., CERTIFICATE)
			processAll(clientHandshaker, rs);

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(2L), MAX_TIME_TO_WAIT_SECS,
					TimeUnit.SECONDS);

			List<Record> records = collector.waitForRecords(500, TimeUnit.MILLISECONDS);
			assertThat("unexpected messages!", records, is(nullValue()));

			// retransmit reverse flight
			assertThat(timer.executeJobs(), is(1));

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(4L), MAX_TIME_TO_WAIT_SECS,
					TimeUnit.SECONDS);

			records = collector.waitForRecords(500, TimeUnit.MILLISECONDS);
			assertThat("unexpected messages!", records, is(nullValue()));

			// retransmit reverse flight again
			assertThat(timer.executeJobs(), is(1));
			// Wait to receive response (should be CHANGE CIPHER SPEC, FINISHED)
			rs = waitForFlightReceived("flight 6", collector, 2);
			// Handle it
			processAll(clientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("server", rawClient, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(7L), MAX_TIME_TO_WAIT_SECS,
					TimeUnit.SECONDS);
		} finally {
			rawClient.stop();
			alternativeServerHelper.destroyServer();
			serverHealth.reset();
		}
	}

	@Test
	public void testClientReceivingMessagesInBadOrderDuringHandshake() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(0, collector);

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			client.start();
			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(0, new DTLSSession(client.getAddress(), 1),
					new TestRecordLayer(rawServer, true), timer, createServerConnection(), serverConfigSingleRecord);
			serverHandshaker.addSessionListener(sessionListener);

			// Wait to receive response (should be CLIENT HELLO, flight 3)
			List<Record> rs = waitForFlightReceived("flight 3", collector, 1);
			// Handle and answer
			// (SERVER_HELLO, CERTIFICATE, ... SERVER HELLO DONE, flight 4)
			processAll(serverHandshaker, rs);

			LatchSessionListener clientSessionListener = getSessionListenerForEndpoint("client", rawServer);

			// Wait for receive response (CERTIFICATE, ... , FINISHED, flight 5)
			rs = waitForFlightReceived("flight 5", collector, 5);
			// Handle and answer (should be CCS, FINISHED, flight 6)
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			assertTrue("client handshake failed",
					clientSessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		} finally {
			rawServer.stop();
		}
	}

	@Test
	public void testServerResumeReceivingMessagesInBadOrderDuringHandshake() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(0, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient, true);
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			Connection clientConnection = createClientConnection();
			DTLSSession clientSession = new DTLSSession(serverHelper.serverEndpoint);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(clientSession, clientRecordLayer, timer,
					clientConnection, clientConfigSingleRecord, false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			processAll(clientHandshaker, rs);

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED)
			rs = waitForFlightReceived("flight 6", collector, 2);
			// Handle (CHANGE CIPHER SPEC, FINISHED)
			processAll(clientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// Create resume handshaker
			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(clientSession.getSessionIdentifier(),
					serverHelper.serverEndpoint, clientSession.getSessionTicket(), 0);
			ResumingClientHandshaker resumingClientHandshaker = new ResumingClientHandshaker(resumableSession,
					clientRecordLayer, timer, clientConnection, clientConfigSingleRecord, false);
			resumingClientHandshaker.addSessionListener(sessionListener);

			// Start resuming handshake (Send CLIENT HELLO, additional flight)
			resumingClientHandshaker.startHandshake();

			// Wait to receive response
			// (SERVER_HELLO, CHANGE CIPHER SPEC, FINISHED, flight 2)
			rs = waitForFlightReceived("flight 2", collector, 3);

			// create server session listener to ensure,
			// that server finish also the handshake
			LatchSessionListener serverSessionListener = getSessionListenerForEndpoint("server", rawClient);

			// Handle and answer ( CHANGE CIPHER SPEC, FINISHED, flight 3)
			processAll(resumingClientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertTrue("server handshake failed",
					serverSessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		} finally {
			rawClient.stop();
		}
	}

	@Test
	public void testClientResumeReceivingMessagesInBadOrderDuringHandshake() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(0, collector);
		TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer, true);

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			client.start();
			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			DTLSSession serverSession = new DTLSSession(client.getAddress(), 1);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(0, serverSession, serverRecordLayer, timer,
					createServerConnection(), serverConfigSingleRecord);
			serverHandshaker.addSessionListener(sessionListener);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer (should be SERVER_HELLO, CERTIFICATE, ...
			// SERVER HELLO DONE)
			processAll(serverHandshaker, rs);

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3", collector, 5);
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(0L));

			// application data
			rs = waitForFlightReceived("app data", collector, 1);

			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(serverSession.getSessionIdentifier(), client.getAddress(),
					serverSession.getSessionTicket(), 0);
			ResumingServerHandshaker resumingServerHandshaker = new ResumingServerHandshaker(0, resumableSession,
					serverRecordLayer, timer, createServerConnection(), serverConfigSingleRecord);
			resumingServerHandshaker.addSessionListener(sessionListener);

			// force resuming handshake
			EndpointContext context = new MapBasedEndpointContext(rawServer.getAddress(), null,
					DtlsEndpointContext.KEY_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_FORCE);
			data = RawData.outbound("Hello World, Again!".getBytes(), context, null, false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer
			// (SERVER HELLO, CCS, FINISHED, flight 2).
			processAll(resumingServerHandshaker, rs);

			// Wait to receive response
			// (CCS, client FINISHED, flight 3) + (application data)
			List<Record> drops = waitForFlightReceived("flight 3 + app data", collector, 3);
			// remove application data, not retransmitted!
			drops.remove(2);

			// drop last flight 3, server resends flight 2
			assertThat(timer.executeJobs(), is(1));

			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(2L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			// Wait to receive response (CCS, client FINISHED, flight 3)
			// ("application data" doesn't belong to flight)
			rs = waitForFlightReceived("flight 3", collector, 2);
			assertFlightRecordsRetransmitted(drops, rs);
			processAll(resumingServerHandshaker, rs);

			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("client", rawServer, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(2L));
		} finally {
			rawServer.stop();
			clientHealth.reset();
		}
	}

	@Test
	public void testClientProbesResume() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(0, collector);
		TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			client.start();
			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			DTLSSession serverSession = new DTLSSession(client.getAddress(), 1);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(0, serverSession, serverRecordLayer, timer,
					createServerConnection(), serverHelper.serverConfig);
			serverHandshaker.addSessionListener(sessionListener);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer (should be SERVER_HELLO, CERTIFICATE, ...
			// SERVER HELLO DONE)
			processAll(serverHandshaker, rs);

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3", collector, 5);
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// application data
			rs = waitForFlightReceived("app data", collector, 1);

			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(serverSession.getSessionIdentifier(), client.getAddress(),
					serverSession.getSessionTicket(), 0);
			ResumingServerHandshaker resumingServerHandshaker = new ResumingServerHandshaker(0, resumableSession,
					serverRecordLayer, timer, createServerConnection(), serverHelper.serverConfig);
			resumingServerHandshaker.addSessionListener(sessionListener);

			// force resuming handshake
			EndpointContext context = new MapBasedEndpointContext(rawServer.getAddress(), null,
					DtlsEndpointContext.KEY_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_PROBE);
			data = RawData.outbound("Hello World, Again!".getBytes(), context, null, false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer
			// (SERVER HELLO, CCS, FINISHED, flight 2).
			processAll(resumingServerHandshaker, rs);

			// Wait to receive response
			// (CCS, client FINISHED, flight 3) + (application data)
			List<Record> drops = waitForFlightReceived("flight 3 + app data", collector, 3);
			// remove application data, not retransmitted!
			drops.remove(2);

			// drop last flight 3, server resends flight 2
			assertThat(timer.executeJobs(), is(1));

			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(2L), MAX_TIME_TO_WAIT_SECS,
					TimeUnit.SECONDS);

			// Wait to receive response (CCS, client FINISHED, flight 3)
			// ("application data" doesn't belong to flight)
			rs = waitForFlightReceived("flight 3", collector, 2);
			assertFlightRecordsRetransmitted(drops, rs);
			processAll(resumingServerHandshaker, rs);

			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("client", rawServer, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(2L));

		} finally {
			rawServer.stop();
			clientHealth.reset();
		}
	}

	@Test
	public void testClientProbesFull() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(0, collector);
		TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);

		DtlsConnectorConfig serverConfig = new DtlsConnectorConfig.Builder(serverHelper.serverConfig)
				.setNoServerSessionId(true).build();

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			client.start();
			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			DTLSSession serverSession = new DTLSSession(client.getAddress(), 1);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(0, serverSession, serverRecordLayer, timer,
					createServerConnection(), serverConfig);
			serverHandshaker.addSessionListener(sessionListener);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer (should be SERVER_HELLO, CERTIFICATE, ... SERVER HELLO DONE)
			processAll(serverHandshaker, rs);

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3", collector, 5);
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// application data
			rs = waitForFlightReceived("app data", collector, 1);

			sessionListener = new LatchSessionListener();
			DTLSSession newSession = new DTLSSession(client.getAddress(), 1);
			ServerHandshaker resumingServerHandshaker = new ServerHandshaker(0, newSession,
					serverRecordLayer, timer, createServerConnection(), serverConfig);
			resumingServerHandshaker.addSessionListener(sessionListener);

			// force resuming handshake
			EndpointContext context = new MapBasedEndpointContext(rawServer.getAddress(), null,
					DtlsEndpointContext.KEY_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_PROBE);
			data = RawData.outbound("Hello World, Again!".getBytes(), context, null, false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer (should be SERVER_HELLO, CERTIFICATE, ... SERVER HELLO DONE)
			processAll(resumingServerHandshaker, rs);

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3 + app data", collector, 5);
			processAll(resumingServerHandshaker, rs);

			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("client", rawServer, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
		} finally {
			rawServer.stop();
		}
	}

	@Test
	public void testClientProbesResumeReceivingMessagesInBadOrderDuringHandshake() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(0, collector);
		TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer, true);

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			client.start();
			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			DTLSSession serverSession = new DTLSSession(client.getAddress(), 1);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(0, serverSession, serverRecordLayer, timer,
					createServerConnection(), serverConfigSingleRecord);
			serverHandshaker.addSessionListener(sessionListener);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer (should be SERVER_HELLO, CERTIFICATE, ...
			// SERVER HELLO DONE)
			processAll(serverHandshaker, rs);

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3", collector, 5);
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// application data
			rs = waitForFlightReceived("app data", collector, 1);

			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(0L));

			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(serverSession.getSessionIdentifier(), client.getAddress(),
					serverSession.getSessionTicket(), 0);
			ResumingServerHandshaker resumingServerHandshaker = new ResumingServerHandshaker(0, resumableSession,
					serverRecordLayer, timer, createServerConnection(), serverConfigSingleRecord);
			resumingServerHandshaker.addSessionListener(sessionListener);

			// force resuming handshake
			EndpointContext context = new MapBasedEndpointContext(rawServer.getAddress(), null,
					DtlsEndpointContext.KEY_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_PROBE);
			data = RawData.outbound("Hello World, Again!".getBytes(), context, null, false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer
			// (SERVER HELLO, CCS, FINISHED, flight 2).
			processAll(resumingServerHandshaker, rs);

			List<Record> records = collector.waitForRecords(500, TimeUnit.MILLISECONDS);
			assertThat("unexpected messages!", records, is(nullValue()));

			// FINISH dropped
			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(1L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			// probing would drop the FINISH epoch 1, therefore resend flight
			assertThat(timer.executeJobs(), is(1));

			// Wait to receive response
			// (CCS, client FINISHED, flight 3) + (application data)
			List<Record> drops = waitForFlightReceived("flight 3 + app data", collector, 3);
			// remove application data, not retransmitted!
			drops.remove(2);

			// retransmission dropped SERVER_HELLO and CCS
			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(3L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			// drop last flight 3, server resends flight 2
			assertThat(timer.executeJobs(), is(1));


			// Wait to receive response (CCS, client FINISHED, flight 3)
			// ("application data" doesn't belong to flight)
			rs = waitForFlightReceived("flight 3", collector, 2);
			assertFlightRecordsRetransmitted(drops, rs);
			processAll(resumingServerHandshaker, rs);

			// retransmission drops SERVER_HELLO and CCS again
			// but FINISH is processed to trigger retransmission of last server flight
			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(5L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("client", rawServer, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

		} finally {
			rawServer.stop();
			clientHealth.reset();
		}
	}

	@Test
	public void testClientProbesResumeTimeout() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(0, collector);
		TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			client.start();
			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			DTLSSession serverSession = new DTLSSession(client.getAddress(), 1);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(0, serverSession, serverRecordLayer, timer,
					createServerConnection(), serverHelper.serverConfig);
			serverHandshaker.addSessionListener(sessionListener);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer (should be SERVER_HELLO, CERTIFICATE, ...
			// SERVER HELLO DONE)
			processAll(serverHandshaker, rs);

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3", collector, 5);
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// application data
			rs = waitForFlightReceived("app data", collector, 1);

			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(serverSession.getSessionIdentifier(), client.getAddress(),
					serverSession.getSessionTicket(), 0);
			ResumingServerHandshaker resumingServerHandshaker = new ResumingServerHandshaker(0, resumableSession,
					serverRecordLayer, timer, createServerConnection(), serverHelper.serverConfig);
			resumingServerHandshaker.addSessionListener(sessionListener);

			// force resuming handshake
			EndpointContext context = new MapBasedEndpointContext(rawServer.getAddress(), null,
					DtlsEndpointContext.KEY_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_PROBE);
			data = RawData.outbound("Hello World, Again!".getBytes(), context, null, false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1", collector, 1);
			// drop it
			// Wait to re-receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1 (retransmit 1)", collector, 1);
			// drop it
			// Wait to re-receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1 (retransmit 2)", collector, 1);
			// drop it

			assertSessionState("client", rawServer, SessionState.FAILED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			// probe handshake failed without receiving data
			context = new AddressEndpointContext(rawServer.getAddress());
			data = RawData.outbound("Hello World, next again!".getBytes(), context, null, false);
			client.send(data);

			rs = waitForFlightReceived("app data", collector, 1);
			Record record = rs.get(0);
			assertThat(record.getEpoch(), is(1));
			assertThat(record.getType(), anyOf(is(ContentType.APPLICATION_DATA), is(ContentType.TLS12_CID)));

		} finally {
			rawServer.stop();
		}
	}

	@Test
	public void testClientProbesFullTimeout() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(0, collector);
		TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);

		DtlsConnectorConfig serverConfig = new DtlsConnectorConfig.Builder(serverHelper.serverConfig)
				.setNoServerSessionId(true).build();

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			client.start();
			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			DTLSSession serverSession = new DTLSSession(client.getAddress(), 1);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(0, serverSession, serverRecordLayer, timer,
					createServerConnection(), serverConfig);
			serverHandshaker.addSessionListener(sessionListener);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer (should be SERVER_HELLO, CERTIFICATE, ... SERVER HELLO DONE)
			processAll(serverHandshaker, rs);

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3", collector, 5);
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// application data
			rs = waitForFlightReceived("app data", collector, 1);

			sessionListener = new LatchSessionListener();
			DTLSSession newSession = new DTLSSession(client.getAddress(), 1);
			ServerHandshaker resumingServerHandshaker = new ServerHandshaker(0, newSession,
					serverRecordLayer, timer, createServerConnection(), serverConfig);
			resumingServerHandshaker.addSessionListener(sessionListener);

			// force resuming handshake
			EndpointContext context = new MapBasedEndpointContext(rawServer.getAddress(), null,
					DtlsEndpointContext.KEY_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_PROBE);
			data = RawData.outbound("Hello World, Again!".getBytes(), context, null, false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1", collector, 1);
			// drop it
			// Wait to re-receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1 (retransmit 1)", collector, 1);
			// drop it
			// Wait to re-receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1 (retransmit 2)", collector, 1);
			// drop it
			assertSessionState("client", rawServer, SessionState.FAILED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			// probe handshake failed without receiving data
			context = new AddressEndpointContext(rawServer.getAddress());
			data = RawData.outbound("Hello World, next again!".getBytes(), context, null, false);
			client.send(data);

			rs = waitForFlightReceived("app data", collector, 1);
			Record record = rs.get(0);
			assertThat(record.getEpoch(), is(1));
			assertThat(record.getType(), anyOf(is(ContentType.APPLICATION_DATA), is(ContentType.TLS12_CID)));
		} finally {
			rawServer.stop();
			clientHealth.reset();
		}
	}

	/**
	 * Test retransmission of last flight.
	 * 
	 * RFC6347, section 4.2.4, fig. 2
	 * 
	 * "testFinishedMessageRetransmission" drops the first transmission of
	 * flight 5 to test, if flight 5 is retransmitted. But flight 5 is just
	 * usual retransmission, the special case is flight 6. Therefore this test
	 * drops the 1. transmission of flight 6 to check, if retransmission of
	 * flight 5 triggers the retransmission of flight 6.
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testServerFinishedMessageRetransmission() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(0, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(new DTLSSession(serverHelper.serverEndpoint),
					clientRecordLayer, timer, createClientConnection(), clientConfig, false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start handshake (Send CLIENT HELLO, flight 1)
			clientHandshaker.startHandshake();

			// Wait to receive response
			// (HELLO VERIFY REQUEST, flight 2)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie, flight 3)
			processAll(clientHandshaker, rs);

			// Wait for response
			// (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE, flight 4)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED, flight 5)
			processAll(clientHandshaker, rs);

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED, flight 6)
			List<Record> drops = waitForFlightReceived("flight 6", collector, 2);

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(0L));

			// Ignore the receive response, client resends flight 5
			assertThat(timer.executeJobs(), is(1));

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(4L), MAX_TIME_TO_WAIT_SECS,
					TimeUnit.SECONDS);

			// Wait for retransmission
			// (CHANGE CIPHER SPEC, FINISHED, flight 6)
			rs = waitForFlightReceived("flight 6", collector, 2);
			assertFlightRecordsRetransmitted(drops, rs);
			processAll(clientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("server", rawClient, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

		} finally {
			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(4L));
			rawClient.stop();
			serverHealth.reset();
		}
	}

	/**
	 * Test back-off retransmission of flight.
	 * 
	 * RFC6347, section 4.1.1.1, page 12
	 * 
	 * "If repeated retransmissions do not result in a response, and the
	 * PMTU is unknown, subsequent retransmissions SHOULD back off to a
	 * smaller record size, fragmenting the handshake message as
	 * appropriate. This standard does not specify an exact number of
	 * retransmits to attempt before backing off, but 2-3 seems
	 * appropriate."
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testClientBackOffRetransmission() throws Exception {
		alternativeServerHelper = new ConnectorHelper();

		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setRetransmissionTimeout(RETRANSMISSION_TIMEOUT_MS * 2)
				.setMaxRetransmissions(MAX_RETRANSMISSIONS * 2)
				.setEnableMultiRecordMessages(false)
				.setHealthHandler(serverHealth)
				.setConnectionIdGenerator(serverCidGenerator);

		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(0, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);

		try {
			// create limited server
			alternativeServerHelper.startServer(builder);

			// Start connector
			rawClient.start();

			// Create handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(new DTLSSession(alternativeServerHelper.serverEndpoint),
					clientRecordLayer, timer, createClientConnection(), clientConfig, false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start handshake (Send CLIENT HELLO, flight 1)
			clientHandshaker.startHandshake();

			// Wait to receive response
			// (HELLO VERIFY REQUEST, flight 2)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie, flight 3)
			processAll(clientHandshaker, rs);

			// Wait for response
			// (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE, flight 4)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED, flight 5)
			processAll(clientHandshaker, rs);

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED, flight 6)
			List<Record> drops = waitForFlightReceived("flight 6", collector, 2);

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(0L));

			// Ignore the receive response, client resends flight 5
			assertThat(timer.executeJobs(), is(1));

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(4L), MAX_TIME_TO_WAIT_SECS,
					TimeUnit.SECONDS);

			// Wait for retransmission
			// (CHANGE CIPHER SPEC, FINISHED, flight 6)
			rs = waitForFlightReceived("flight 6", collector, 2);
			assertFlightRecordsRetransmitted(drops, rs);

			assertThat(clientRecordLayer.getLastSentDatagrams(), is(1));

			// Ignore the receive response, client resends flight 5
			assertThat(timer.executeJobs(), is(1));

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(8L), MAX_TIME_TO_WAIT_SECS,
					TimeUnit.SECONDS);

			// Wait for retransmission
			// (CHANGE CIPHER SPEC, FINISHED, flight 6)
			rs = waitForFlightReceived("flight 6", collector, 2);
			assertFlightRecordsRetransmitted(drops, rs);

			assertThat(clientRecordLayer.getLastSentDatagrams(), is(4));

			processAll(clientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("server", rawClient, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

		} finally {
			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(8L));
			rawClient.stop();
			alternativeServerHelper.destroyServer();
			serverHealth.reset();
		}
	}

	/**
	 * Test back-off retransmission of server flight 4.
	 * 
	 * RFC6347, section 4.1.1.1, page 12
	 * 
	 * "If repeated retransmissions do not result in a response, and the
	 * PMTU is unknown, subsequent retransmissions SHOULD back off to a
	 * smaller record size, fragmenting the handshake message as
	 * appropriate. This standard does not specify an exact number of
	 * retransmits to attempt before backing off, but 2-3 seems
	 * appropriate."
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testServerBackOffRetransmission() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(0, collector);

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			client.start();
			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(0, new DTLSSession(client.getAddress(), 1),
					serverRecordLayer, timer, createServerConnection(), serverHelper.serverConfig);
			serverHandshaker.addSessionListener(sessionListener);

			// Wait to receive response (should be CLIENT HELLO, flight 3)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer
			// (SERVER_HELLO, CERTIFICATE, ... SERVER HELLO DONE, flight 4)
			processAll(serverHandshaker, rs);

			// Ignore transmission (CERTIFICATE, ... , FINISHED, flight 5)
			List<Record> drops = waitForFlightReceived("flight 3", collector, 5);
			// server retransmission

			assertThat(serverRecordLayer.getLastSentDatagrams(), is(1));

			timer.executeJobs();

			// Wait for retransmission (CERTIFICATE, ... , FINISHED, flight 5)
			rs = waitForFlightReceived("flight 3", collector, 5);
			assertFlightRecordsRetransmitted(drops, rs);

			assertThat(serverRecordLayer.getLastSentDatagrams(), is(1));

			timer.executeJobs();
			
			// Wait for retransmission (CERTIFICATE, ... , FINISHED, flight 5)
			rs = waitForFlightReceived("flight 3", collector, 5);
			assertFlightRecordsRetransmitted(drops, rs);

			assertThat(serverRecordLayer.getLastSentDatagrams(), is(5));

			// Handle and answer (should be CCS, FINISHED, flight 6)
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("client", rawServer, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
		} finally {
			rawServer.stop();
		}
	}

	/**
	 * Test processing close notify after session is established, but not
	 * completed.
	 */
	@Test
	public void testServerCloseAfterFinishedMessage() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(0, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			Connection clientConnection = createClientConnection();
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(new DTLSSession(serverHelper.serverEndpoint),
					clientRecordLayer, timer, clientConnection, clientConfig, false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start handshake (Send CLIENT HELLO, flight 1)
			clientHandshaker.startHandshake();

			// Wait to receive response
			// (HELLO VERIFY REQUEST, flight 2)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie, flight 3)
			processAll(clientHandshaker, rs);

			// Wait for response
			// (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE, flight 4)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED, flight 5)
			processAll(clientHandshaker, rs);

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED, flight 6)
			rs = waitForFlightReceived("flight 6", collector, 2);
			processAll(clientHandshaker, rs);

			serverHealth.reset();

			AlertMessage close = new AlertMessage(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY,
					serverHelper.serverEndpoint);
			send(clientConnection, clientRecordLayer, close);
			// Wait to receive response from server
			// (CLOSE_NOTIFY, flight 8)
			rs = waitForFlightReceived("flight 8", collector, 1);

			// send close again
			send(clientConnection, clientRecordLayer, close);

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(1L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			TestConditionTools.assertStatisticCounter(serverHealth, "handshakes succeeded", is(1L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		} finally {
			rawClient.stop();
			serverHealth.reset();
		}
	}

	/**
	 * Test processing close notify after session is established, but not
	 * completed.
	 */
	@Test
	public void testServerDecodesAfterUnorderedClose() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(0, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			Connection clientConnection = createClientConnection();
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(new DTLSSession(serverHelper.serverEndpoint),
					clientRecordLayer, timer, clientConnection, clientConfig, false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start handshake (Send CLIENT HELLO, flight 1)
			clientHandshaker.startHandshake();

			// Wait to receive response
			// (HELLO VERIFY REQUEST, flight 2)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie, flight 3)
			processAll(clientHandshaker, rs);

			// Wait for response
			// (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE, flight 4)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED, flight 5)
			processAll(clientHandshaker, rs);

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED, flight 6)
			rs = waitForFlightReceived("flight 6", collector, 2);
			processAll(clientHandshaker, rs);

			serverHealth.reset();

			ApplicationMessage app = new ApplicationMessage("hi".getBytes(), serverHelper.serverEndpoint);
			send(clientConnection, clientRecordLayer, app);

			// app response
			rs = waitForFlightReceived("response", collector, 1);

			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			TestConditionTools.assertStatisticCounter(serverHealth, "sending records", is(1L), MAX_TIME_TO_WAIT_SECS,
					TimeUnit.SECONDS);
			TestConditionTools.assertStatisticCounter(serverHealth, "handshakes succeeded", is(1L));
			TestConditionTools.assertStatisticCounter(serverHealth, "handshakes failed", is(0L));
			TestConditionTools.assertStatisticCounter(serverHealth, "dropped sending records", is(0L));
			TestConditionTools.assertStatisticCounter(serverHealth, "received records", is(1L));
			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(0L));

			serverHealth.reset();

			app = new ApplicationMessage("hi, again".getBytes(), serverHelper.serverEndpoint);
			AlertMessage close = new AlertMessage(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY,
					serverHelper.serverEndpoint);

			clientRecordLayer.setReverse(true);
			send(clientConnection, clientRecordLayer, app, close);

			// (CLOSE_NOTIFY)
			rs = waitForFlightReceived("close", collector, 1);

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped sending records", is(1L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			TestConditionTools.assertStatisticCounter(serverHealth, "sending records", is(2L));
			TestConditionTools.assertStatisticCounter(serverHealth, "received records", is(2L));
			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(0L));

			app = new ApplicationMessage("bye".getBytes(), serverHelper.serverEndpoint);
			send(clientConnection, clientRecordLayer, app);

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(1L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			TestConditionTools.assertStatisticCounter(serverHealth, "received records", is(3L));

		} finally {
			rawClient.stop();
			serverHealth.reset();
		}
	}

	/**
	 * Test retransmission of last flight of resuming handshake.
	 * 
	 * RFC6347, section 4.2.4, fig. 2
	 * 
	 * "testResumeFinishedMessageRetransmission" drops the first transmission of
	 * flight 2 to test, if flight 2 is retransmitted. But flight 2 is just
	 * usual retransmission, the special case is flight 3. Therefore this test
	 * drops the 1. transmission of flight 3 to check, if retransmission of
	 * flight 2 triggers the retransmission of flight 3.
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testResumeClientFinishedMessageRetransmission() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(0, collector);
		TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			client.start();
			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			DTLSSession serverSession = new DTLSSession(client.getAddress(), 1);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(0, serverSession, serverRecordLayer, timer,
					createServerConnection(), serverHelper.serverConfig);
			serverHandshaker.addSessionListener(sessionListener);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer (should be CERTIFICATE, ... SERVER HELLO DONE)
			processAll(serverHandshaker, rs);

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3", collector, 5);
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// application data
			rs = waitForFlightReceived("app data", collector, 1);

			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(serverSession.getSessionIdentifier(), client.getAddress(),
					serverSession.getSessionTicket(), 0);
			ResumingServerHandshaker resumingServerHandshaker = new ResumingServerHandshaker(0, resumableSession,
					serverRecordLayer, timer, createServerConnection(), serverHelper.serverConfig);
			resumingServerHandshaker.addSessionListener(sessionListener);

			// force resuming handshake
			EndpointContext context = new MapBasedEndpointContext(rawServer.getAddress(), null,
					DtlsEndpointContext.KEY_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_FORCE);
			data = RawData.outbound("Hello World, Again!".getBytes(), context, null, false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer
			// (SERVER HELLO, CCS, FINISHED, VERIFY REQUEST, flight 2).
			processAll(resumingServerHandshaker, rs);

			// Wait to receive response
			// (CCS, client FINISHED, flight 3) + (application data)
			List<Record> drops = waitForFlightReceived("flight 3", collector, 3);
			// remove application data, not retransmitted!
			drops.remove(2);

			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(0L));

			// drop last flight 3, server resends flight 2
			assertThat(timer.executeJobs(), is(1));

			// Wait to receive response (CCS, client FINISHED, flight 3)
			// ("application data" doesn't belong to flight)
			rs = waitForFlightReceived("flight 3", collector, 2);
			assertFlightRecordsRetransmitted(drops, rs);
			processAll(resumingServerHandshaker, rs);
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("client", rawServer, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(2L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

		} finally {
			rawServer.stop();
			clientHealth.reset();
		}
	}

	@Test
	public void testResumeClientCloseAfterFinishedMessage() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(0, collector);
		TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			client.start();
			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			DTLSSession serverSession = new DTLSSession(client.getAddress(), 1);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(0, serverSession, serverRecordLayer, timer,
					createServerConnection(), serverHelper.serverConfig);
			serverHandshaker.addSessionListener(sessionListener);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer (should be CERTIFICATE, ... SERVER HELLO DONE)
			processAll(serverHandshaker, rs);

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3", collector, 5);
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// application data
			rs = waitForFlightReceived("app data", collector, 1);

			sessionListener = new LatchSessionListener();
			Connection serverConnection = createServerConnection();
			DTLSSession resumableSession = new DTLSSession(serverSession.getSessionIdentifier(), client.getAddress(),
					serverSession.getSessionTicket(), 0);
			ResumingServerHandshaker resumingServerHandshaker = new ResumingServerHandshaker(0, resumableSession,
					serverRecordLayer, timer, serverConnection, serverHelper.serverConfig);
			resumingServerHandshaker.addSessionListener(sessionListener);

			// force resuming handshake
			EndpointContext context = new MapBasedEndpointContext(rawServer.getAddress(), null,
					DtlsEndpointContext.KEY_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_FORCE);
			data = RawData.outbound("Hello World, Again!".getBytes(), context, null, false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer
			// (SERVER HELLO, CCS, FINISHED, flight 2).
			processAll(resumingServerHandshaker, rs);

			// Wait to receive response
			// (CCS, client FINISHED, flight 3) + (application data)
			rs = waitForFlightReceived("flight 3", collector, 3);
			// remove application data,
			// prevent resuming client handshaker from completion
			rs.remove(2);
			processAll(resumingServerHandshaker, rs);

			clientHealth.reset();

			AlertMessage close = new AlertMessage(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY,
					client.getAddress());
			send(serverConnection, serverRecordLayer, close);

			// Wait to receive response from server
			// (CLOSE_NOTIFY, flight 5)
			rs = waitForFlightReceived("flight 5", collector, 1);

			send(serverConnection, serverRecordLayer, close);

			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(1L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			TestConditionTools.assertStatisticCounter(clientHealth, "handshakes succeeded", is(1L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("client", rawServer, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

		} finally {
			rawServer.stop();
			clientHealth.reset();
		}
	}

	/**
	 * Test retransmission of flight before last flight.
	 * 
	 * RFC6347, section 4.2.4, fig. 2
	 * 
	 * Drops the first transmission of flight 5 to test, if flight 5 is
	 * retransmitted. Usual retransmission, the special case is flight 6, see
	 * "testServerFinishedMessageRetransmission".
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testFinishedMessageRetransmission() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(0, collector);

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			client.start();
			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(0, new DTLSSession(client.getAddress(), 1),
					new TestRecordLayer(rawServer), timer, createServerConnection(), serverHelper.serverConfig);
			serverHandshaker.addSessionListener(sessionListener);

			// Wait to receive response (should be CLIENT HELLO, flight 3)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer
			// (CERTIFICATE, ... SERVER HELLO DONE, flight 4)
			processAll(serverHandshaker, rs);

			// Ignore transmission (CERTIFICATE, ... , FINISHED, flight 5)
			List<Record> drops = waitForFlightReceived("flight 3", collector, 5);

			// Wait for retransmission (CERTIFICATE, ... , FINISHED, flight 5)
			rs = waitForFlightReceived("flight 3", collector, 5);
			assertFlightRecordsRetransmitted(drops, rs);
			// Handle and answer (should be CCS, FINISHED, flight 6)
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("client", rawServer, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

		} finally {
			rawServer.stop();
		}
	}

	/**
	 * Test retransmission of flight before last flight of resuming handshake.
	 * 
	 * RFC6347, section 4.2.4, fig. 2
	 * 
	 * Drops the first transmission of flight 2 to test, if flight 2 is
	 * retransmitted. Flight 2 is just usual retransmission, the special case is
	 * flight 3, see "testResumeClientFinishedMessageRetransmission". Note:
	 * scandium uses a additional HELLO VERIFY REQUEST. May be optimized in the
	 * future.
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testResumeFinishedMessageRetransmission() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(0, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			Connection clientConnection = createClientConnection();
			DTLSSession clientSession = new DTLSSession(serverHelper.serverEndpoint);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(clientSession, clientRecordLayer, timer,
					clientConnection, clientConfig, false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			processAll(clientHandshaker, rs);

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED)
			rs = waitForFlightReceived("flight 6", collector, 2);
			// Handle (CHANGE CIPHER SPEC, FINISHED)
			processAll(clientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// Create resume handshaker
			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(clientSession.getSessionIdentifier(),
					serverHelper.serverEndpoint, clientSession.getSessionTicket(), 0);
			ResumingClientHandshaker resumingClientHandshaker = new ResumingClientHandshaker(resumableSession,
					clientRecordLayer, timer, clientConnection, clientConfig, false);
			resumingClientHandshaker.addSessionListener(sessionListener);

			// Start resuming handshake (Send CLIENT HELLO, additional flight)
			resumingClientHandshaker.startHandshake();

			// Wait to receive response
			// (SERVER_HELLO, CHANGE CIPHER SPEC, FINISHED, fight 2)
			List<Record> drops = waitForFlightReceived("flight 2", collector, 3);

			// drop it, force retransmission
			// (SERVER_HELLO, CHANGE CIPHER SPEC, FINISHED, fight 2)
			rs = waitForFlightReceived("flight 2", collector, 3);
			assertFlightRecordsRetransmitted(drops, rs);
			// Handle and answer ( CHANGE CIPHER SPEC, FINISHED, flight 3)
			processAll(resumingClientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("server", rawClient, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

		} finally {
			rawClient.stop();
		}
	}

	/**
	 * Test the server resuming handshake fails, if clients FINISH is dropped.
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testServerResumeTimeout() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(0, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		int remain = serverHelper.serverConnectionStore.remainingCapacity();
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			Connection clientConnection = createClientConnection();
			DTLSSession clientSession = new DTLSSession(serverHelper.serverEndpoint);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(clientSession, clientRecordLayer, timer,
					clientConnection, clientConfig, false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			processAll(clientHandshaker, rs);

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED)
			rs = waitForFlightReceived("flight 6", collector, 2);
			// Handle (CHANGE CIPHER SPEC, FINISHED)
			processAll(clientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// Create resume handshaker
			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(clientSession.getSessionIdentifier(),
					serverHelper.serverEndpoint, clientSession.getSessionTicket(), 0);
			ResumingClientHandshaker resumingClientHandshaker = new ResumingClientHandshaker(resumableSession,
					clientRecordLayer, timer, clientConnection, clientConfigSingleRecord, false);
			resumingClientHandshaker.addSessionListener(sessionListener);

			// Start resuming handshake (Send CLIENT HELLO, additional flight)
			resumingClientHandshaker.startHandshake();

			// Wait to receive response
			// (SERVER_HELLO, CHANGE CIPHER SPEC, FINISHED, fight 2)
			rs = waitForFlightReceived("flight 2", collector, 3);

			// create server session listener to ensure,
			// that server finish also the handshake
			LatchSessionListener serverSessionListener = getSessionListenerForEndpoint("server", rawClient);

			// Handle and answer
			// (CHANGE CIPHER SPEC, FINISHED (drop), flight 3)
			clientRecordLayer.setDrop(-1);
			processAll(resumingClientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 1));
			Throwable error = serverSessionListener.waitForSessionFailed(timeout, TimeUnit.MILLISECONDS);
			assertNotNull("server handshake not failed", error);
			assertThat(error, instanceOf(DtlsHandshakeTimeoutException.class));
			assertThat(serverHelper.serverConnectionStore.remainingCapacity(), is(remain));
		} finally {
			rawClient.stop();
		}
	}

	/**
	 * Test the server handshake fails, if clients FINISH is dropped.
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testServerTimeout() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(0, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		int remain = serverHelper.serverConnectionStore.remainingCapacity();
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			DTLSSession clientSession = new DTLSSession(serverHelper.serverEndpoint);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(clientSession, clientRecordLayer, timer,
					createClientConnection(), clientConfigSingleRecord, false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);

			// create server session listener to ensure,
			// that server finish also the handshake
			LatchSessionListener serverSessionListener = getSessionListenerForEndpoint("server", rawClient);

			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			clientRecordLayer.setDrop(-1);
			processAll(clientHandshaker, rs);

			// Ensure handshake failed
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));
			Throwable error = serverSessionListener.waitForSessionFailed(timeout, TimeUnit.MILLISECONDS);
			assertNotNull("server handshake not failed", error);
			assertThat(error, instanceOf(DtlsHandshakeTimeoutException.class));
			assertThat(serverHelper.serverConnectionStore.remainingCapacity(), is(remain));
		} finally {
			rawClient.stop();
		}
	}

	@Test
	public void testClientResumeTimeout() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(0, collector);
		TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);
		int remain = clientConnectionStore.remainingCapacity();

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			client.start();
			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			DTLSSession serverSession = new DTLSSession(client.getAddress(), 1);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(0, serverSession, serverRecordLayer, timer,
					createServerConnection(), serverHelper.serverConfig);
			serverHandshaker.addSessionListener(sessionListener);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer (should be CERTIFICATE, ... SERVER HELLO DONE)
			processAll(serverHandshaker, rs);

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3", collector, 5);
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// application data
			rs = waitForFlightReceived("app data", collector, 1);

			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(serverSession.getSessionIdentifier(), client.getAddress(),
					serverSession.getSessionTicket(), 0);
			ResumingServerHandshaker resumingServerHandshaker = new ResumingServerHandshaker(0, resumableSession,
					serverRecordLayer, timer, createServerConnection(), serverConfigSingleRecord);
			resumingServerHandshaker.addSessionListener(sessionListener);

			// force resuming handshake
			EndpointContext context = new MapBasedEndpointContext(rawServer.getAddress(), null,
					DtlsEndpointContext.KEY_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_FORCE);
			data = RawData.outbound("Hello World, Again!".getBytes(), context, null, false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1", collector, 1);

			LatchSessionListener clientSessionListener = getSessionListenerForEndpoint("client", rawServer);

			// Handle and answer
			// (SERVER HELLO, CCS, FINISHED drop, flight 2).
			serverRecordLayer.setDrop(-1);
			processAll(resumingServerHandshaker, rs);

			// Ensure handshake failed
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));
			Throwable error = clientSessionListener.waitForSessionFailed(timeout, TimeUnit.MILLISECONDS);
			assertNotNull("client handshake not failed", error);
			assertThat(error, instanceOf(DtlsHandshakeTimeoutException.class));
			assertThat(clientConnectionStore.remainingCapacity(), is(remain));
		} finally {
			rawServer.stop();
		}
	}

	@Test
	public void testClientTimeout() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(0, collector);
		int remain = clientConnectionStore.remainingCapacity();

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			client.start();
			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(0, new DTLSSession(client.getAddress(), 1),
					serverRecordLayer, timer, createServerConnection(), serverConfigSingleRecord);
			serverHandshaker.addSessionListener(sessionListener);

			// Wait to receive response (should be CLIENT HELLO, flight 3)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer
			// (CERTIFICATE, ... SERVER HELLO DONE, flight 4)
			processAll(serverHandshaker, rs);

			LatchSessionListener clientSessionListener = getSessionListenerForEndpoint("client", rawServer);

			// Wait for transmission (CERTIFICATE, ... , FINISHED, flight 5)
			rs = waitForFlightReceived("flight 3", collector, 5);
			// Handle and answer (should be CCS, FINISHED (drop), flight 6)
			serverRecordLayer.setDrop(-1);
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			// Ensure handshake failed
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));
			Throwable error = clientSessionListener.waitForSessionFailed(timeout, TimeUnit.MILLISECONDS);
			assertNotNull("client handshake not failed", error);
			assertThat(error, instanceOf(DtlsHandshakeTimeoutException.class));
			assertThat(clientConnectionStore.remainingCapacity(), is(remain));
		} finally {
			rawServer.stop();
		}
	}

	@Test
	public void testClientExpires() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(0, collector);
		int remain = clientConnectionStore.remainingCapacity();
		int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			client.start();
			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(0, new DTLSSession(client.getAddress(), 1),
					serverRecordLayer, timer, createServerConnection(), serverConfigSingleRecord);
			serverHandshaker.addSessionListener(sessionListener);

			// Wait to receive response (should be CLIENT HELLO, flight 3)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer
			// (CERTIFICATE, ... SERVER HELLO DONE, flight 4)
			processAll(serverHandshaker, rs);

			LatchSessionListener clientSessionListener = getSessionListenerForEndpoint("client", rawServer);

			// Wait for transmission (CERTIFICATE, ... , FINISHED, flight 5)
			rs = waitForFlightReceived("flight 3", collector, 5);

			clientHealth.reset();

			// Handle and answer (should be CCS, FINISHED (drop), flight 6)
			serverRecordLayer.setDrop(-1);
			processAll(serverHandshaker, rs);

			TestConditionTools.assertStatisticCounter(clientHealth, "received records", is(1L), MAX_TIME_TO_WAIT_SECS,
					TimeUnit.SECONDS);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// the CCS must be processed before the time shift ... otherwise it may get discarded
			Thread.sleep(500);
			time.addTestTimeShift(timeout * 2, TimeUnit.MILLISECONDS);

			// Ensure handshake failed before retransmissions timeout
			Throwable error = clientSessionListener.waitForSessionFailed(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("client handshake not failed", error);
			assertTrue(error.getMessage(), error.getMessage().contains("expired"));
			assertThat(clientConnectionStore.remainingCapacity(), is(remain));
		} finally {
			rawServer.stop();
		}
	}

	@Test
	public void testResumeWithVerify() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(0, collector);

		RecordCollectorDataHandler alt1Collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawAlt1Client = new UdpConnector(0, alt1Collector);

		RecordCollectorDataHandler alt2Collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawAlt2Client = new UdpConnector(0, alt2Collector);

		DTLSSession clientSession = new DTLSSession(serverHelper.serverEndpoint);
		try {
			// Start connector
			rawClient.start();

			// Create handshaker
			Connection clientConnection = createClientConnection();
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(clientSession, new TestRecordLayer(rawClient),
					timer, clientConnection, clientConfig, false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			processAll(clientHandshaker, rs);

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED)
			rs = waitForFlightReceived("flight 6", collector, 2);
			// Handle (CHANGE CIPHER SPEC, FINISHED)
			processAll(clientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// Create 1. resume handshaker
			rawAlt1Client.start();
			LatchSessionListener alt1SessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(clientSession.getSessionIdentifier(),
					serverHelper.serverEndpoint, clientSession.getSessionTicket(), 0);
			ResumingClientHandshaker resumingClientHandshaker = new ResumingClientHandshaker(resumableSession,
					new TestRecordLayer(rawAlt1Client), timer, clientConnection, clientConfig, false);
			resumingClientHandshaker.addSessionListener(alt1SessionListener);

			// Start resuming handshake (Send CLIENT HELLO, additional flight)
			resumingClientHandshaker.startHandshake();

			// Wait to receive response
			// (SERVER_HELLO, CHANGE CIPHER SPEC, FINISHED, fight 4)
			rs = waitForFlightReceived("flight 4", alt1Collector, 3);

			// Create 2. resume handshaker
			rawAlt2Client.start();
			LatchSessionListener alt2SessionListener = new LatchSessionListener();
			resumableSession = new DTLSSession(clientSession.getSessionIdentifier(), serverHelper.serverEndpoint,
					clientSession.getSessionTicket(), 0);
			resumingClientHandshaker = new ResumingClientHandshaker(resumableSession,
					new TestRecordLayer(rawAlt2Client), timer, clientConnection, clientConfig, false);
			resumingClientHandshaker.addSessionListener(alt2SessionListener);

			// Start resuming handshake (Send CLIENT HELLO, additional flight)
			resumingClientHandshaker.startHandshake();

			// Wait to receive response
			// (HELLO_VERIFY_REQUEST, fight 2)
			rs = waitForFlightReceived("flight 2", alt2Collector, 1);

			// Send CLIENT HELLO with cookie, flight 3
			processAll(resumingClientHandshaker, rs);

			// Wait to receive response
			// (SERVER_HELLO, CHANGE CIPHER SPEC, FINISHED, fight 4)
			rs = waitForFlightReceived("flight 4", alt2Collector, 3);

			// create server session listener to ensure,
			// that server finish also the handshake
			serverHelper.serverConnectionStore.dump();

			processAll(resumingClientHandshaker, rs);

			assertTrue("client 2. resumed handshake failed",
					alt2SessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("server", rawAlt2Client, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));
			assertSessionState("server", rawAlt1Client, SessionState.FAILED, timeout, TimeUnit.MILLISECONDS);

		} finally {
			rawClient.stop();
			rawAlt1Client.stop();
			rawAlt2Client.stop();
		}
	}

	@Test
	public void testServerNoCCS() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(0, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		int remain = serverHelper.serverConnectionStore.remainingCapacity();
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			DTLSSession clientSession = new DTLSSession(serverHelper.serverEndpoint);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(clientSession, clientRecordLayer, timer,
					createClientConnection(), clientConfigSingleRecord, false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);

			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			clientRecordLayer.setDrop(-2); // drop CCS
			processAll(clientHandshaker, rs);

			// Ensure handshake failed
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));

			assertSessionState("server", rawClient, SessionState.FAILED, timeout, TimeUnit.MILLISECONDS);

			assertThat(serverHelper.serverConnectionStore.remainingCapacity(), is(remain));
		} finally {
			rawClient.stop();
		}
	}

	@Test
	public void testClientNoCCS() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(0, collector);
		int remain = clientConnectionStore.remainingCapacity();

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			client.start();
			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(0, new DTLSSession(client.getAddress(), 1),
					serverRecordLayer, timer, createServerConnection(), serverConfigSingleRecord);
			serverHandshaker.addSessionListener(sessionListener);

			// Wait to receive response (should be CLIENT HELLO, flight 3)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer
			// (CERTIFICATE, ... SERVER HELLO DONE, flight 4)
			processAll(serverHandshaker, rs);

			// Wait for transmission (CERTIFICATE, ... , FINISHED, flight 5)
			rs = waitForFlightReceived("flight 3", collector, 5);
			// Handle and answer (should be CCS (drop), FINISHED, flight 6)
			serverRecordLayer.setDrop(-2);
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			// Ensure handshake failed
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));
			assertSessionState("client", rawServer, SessionState.FAILED, timeout, TimeUnit.MILLISECONDS);
			assertThat(clientConnectionStore.remainingCapacity(), is(remain));
		} finally {
			rawServer.stop();
		}
	}

	@Test
	public void testServerAdverseryClient() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(0, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		int remain = serverHelper.serverConnectionStore.remainingCapacity();
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			DTLSSession clientSession = new DTLSSession(serverHelper.serverEndpoint);
			LatchSessionListener sessionListener = new LatchSessionListener();
			AdversaryClientHandshaker clientHandshaker = new AdversaryClientHandshaker(clientSession, clientRecordLayer,
					timer, createClientConnection(), clientConfig);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);

			// create server session listener to ensure,
			// that server finish also the handshake
			LatchSessionListener serverSessionListener = getSessionListenerForEndpoint("server", rawClient);

			// Handle and answer
			// (CERTIFICATE, (NO CHANGE CIPHER SPEC), ..., FINISHED)
			processAll(clientHandshaker, rs);

			// Ensure handshake failed
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));
			Throwable error = serverSessionListener.waitForSessionFailed(timeout, TimeUnit.MILLISECONDS);

			if (error == null) {

				rs = waitForFlightReceived("flight 5", collector, 2);
				processAll(clientHandshaker, rs);

				clientHandshaker.sendApplicationData("Hello".getBytes());

				rs = waitForFlightReceived("flight 6 (app data)", collector, 1);
				for (Record data : rs) {
					data.applySession(clientHandshaker.getSession());
					System.out.println(data);
					DTLSMessage message = data.getFragment();
					byte[] array = message.toByteArray();
					System.out.println(StringUtil.byteArray2Hex(array) + " / " + new String(array));
				}

				RawData message = serverHelper.serverRawDataProcessor.getLatestInboundMessage();
				System.out
						.println(StringUtil.byteArray2Hex(message.getBytes()) + " / " + new String(message.getBytes()));
			}
			assertNotNull("server handshake not failed", error);
			assertThat(serverHelper.serverConnectionStore.remainingCapacity(), is(remain));
		} finally {
			rawClient.stop();
		}
	}

	/**
	 * Test the server handshake fails, if the PSK secret result is not received
	 * in time.
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testServerPskTimeout() throws Exception {
		// Configure and create UDP connector
		aPskStoreResponses = 0; // no psk response
		InetSocketAddress clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder().setLoggingTag("client")
				.setAddress(clientEndpoint).setReceiverThreadCount(1).setConnectionThreadCount(2)
				.setRetransmissionTimeout(RETRANSMISSION_TIMEOUT_MS).setMaxRetransmissions(MAX_RETRANSMISSIONS)
				.setMaxConnections(CLIENT_CONNECTION_STORE_CAPACITY).setConnectionIdGenerator(clientCidGenerator)
				.setPskStore(new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()))
				.setHealthHandler(clientHealth);
		DtlsConnectorConfig clientConfig = builder.build();
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(0, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		int remain = serverHelper.serverConnectionStore.remainingCapacity();
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			DTLSSession clientSession = new DTLSSession(serverHelper.serverEndpoint);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(clientSession, clientRecordLayer, timer,
					createClientConnection(), clientConfig, false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, SERVER_KEY_EXCHANGE,
			// SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 3);

			// create server session listener to ensure,
			// that server finish also the handshake
			LatchSessionListener serverSessionListener = getSessionListenerForEndpoint("server", rawClient);

			// Handle and answer
			// (CLIENT_KEY_EXCHANGE, CHANGE CIPHER SPEC, ..., FINISHED)
			processAll(clientHandshaker, rs);

			// Ensure handshake failed
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));
			Throwable error = serverSessionListener.waitForSessionFailed(timeout, TimeUnit.MILLISECONDS);
			assertNotNull("server handshake not failed", error);
			assertThat(error, instanceOf(DtlsHandshakeTimeoutException.class));
			assertThat(serverHelper.serverConnectionStore.remainingCapacity(), is(remain));
		} finally {
			rawClient.stop();
		}
	}

	/**
	 * Test the server handshake succeeds, if the PSK secret result is received
	 * twice.
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testServerPskDoubleResponse() throws Exception {
		// Configure and create UDP connector
		aPskStoreResponses = 2; // two psk responses
		InetSocketAddress clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder().setLoggingTag("client")
				.setAddress(clientEndpoint).setReceiverThreadCount(1).setConnectionThreadCount(2)
				.setRetransmissionTimeout(RETRANSMISSION_TIMEOUT_MS).setMaxRetransmissions(MAX_RETRANSMISSIONS)
				.setMaxConnections(CLIENT_CONNECTION_STORE_CAPACITY).setConnectionIdGenerator(clientCidGenerator)
				.setPskStore(new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()))
				.setHealthHandler(clientHealth);
		DtlsConnectorConfig clientConfig = builder.build();
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(0, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			DTLSSession clientSession = new DTLSSession(serverHelper.serverEndpoint);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(clientSession, clientRecordLayer, timer,
					createClientConnection(), clientConfig, false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, SERVER_KEY_EXCHANGE,
			// SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 3);

			// Handle and answer
			// (CLIENT_KEY_EXCHANGE, CHANGE CIPHER SPEC, ..., FINISHED)
			processAll(clientHandshaker, rs);

			// Ensure handshake succeeded
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));
			assertSessionState("server", rawClient, SessionState.ESTABLISHED, timeout, TimeUnit.MILLISECONDS);
		} finally {
			rawClient.stop();
		}
	}

	private void send(Connection connection, TestRecordLayer recordLayer, DTLSMessage... messages)
			throws GeneralSecurityException, IOException {
		List<DatagramPacket> datagrams = encode(connection, messages);
		recordLayer.sendFlight(datagrams);
	}

	private List<DatagramPacket> encode(Connection connection, DTLSMessage... messages)
			throws GeneralSecurityException, IOException {
		List<DatagramPacket> datagrams = new ArrayList<>();
		DTLSSession session = connection.getEstablishedSession();
		if (session == null && connection.hasOngoingHandshake()) {
			session = connection.getOngoingHandshake().getSession();
		}
		InetSocketAddress peerAddress = session.getPeer();
		for (DTLSMessage message : messages) {
			Record record = new Record(message.getContentType(), session.getWriteEpoch(), session.getSequenceNumber(),
					message, session, true, 0);
			byte[] data = record.toByteArray();
			DatagramPacket datagram = new DatagramPacket(data, data.length, peerAddress.getAddress(),
					peerAddress.getPort());
			datagrams.add(datagram);
		}
		return datagrams;
	}

	private void processAll(final Handshaker handshaker, final List<Record> records)
			throws GeneralSecurityException, HandshakeException {
		final CountDownLatch ready = new CountDownLatch(1);
		Runnable run = new Runnable() {

			@Override
			public void run() {
				try {
					DTLSSession session = handshaker.getSession();
					for (Record record : records) {
						record.applySession(session);
						handshaker.processMessage(record);
					}
				} catch (Throwable t) {
					LOGGER.error("process handshake", t);
				}
				ready.countDown();
			}
		};
		SerialExecutor serialExecutor = handshaker.getConnection().getExecutor();
		if (serialExecutor != null) {
			serialExecutor.execute(run);
			try {
				// sometimes the flight is intended to be resend,
				// so the serialized execution must have finished.
				ready.await();
			} catch (InterruptedException e) {
			}
		} else {
			run.run();
		}
	}

	private List<Record> waitForFlightReceived(String description, RecordCollectorDataHandler collector, int records)
			throws InterruptedException {
		List<Record> rs = collector.waitForFlight(records, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
		if (records == 0 && rs == null) {
			return Collections.emptyList();
		}
		assertNotNull(description + " timeout", rs);
		if (rs.size() != records && lastReceivedFlight != null && lastReceivedFlight.size() <= rs.size()) {
			// check for retransmission
			int index = 0;
			int lastSize = lastReceivedFlight.size();
			for (; index < lastSize; ++index) {
				Record record1 = lastReceivedFlight.get(index);
				Record record2 = rs.get(index);
				if (record2.getEpoch() != record1.getEpoch()) {
					break;
				}
				if (record2.getType() != record1.getType()) {
					break;
				}
				if (record2.getFragmentLength() != record1.getFragmentLength()) {
					break;
				}
				if (record2.getSequenceNumber() > record1.getSequenceNumber()) {
					break;
				}
			}
			if (index == lastSize) {
				// retransmission
				if (lastSize == rs.size()) {
					// wait for next flight
					rs = collector.waitForFlight(records, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
					assertNotNull(description + " timeout", rs);
				} else {
					// drop records of retransmitted flight
					List<Record> newFlight = new ArrayList<Record>();
					for (; index < rs.size(); ++index) {
						newFlight.add(rs.get(index));
					}
					rs = newFlight;
				}
			}
		}
		if (rs.size() != records) {
			for (Record record : rs) {
				if (record.getEpoch() == 0) {
					try {
						record.applySession(null);
						record.getFragment();
					} catch (GeneralSecurityException e) {
						LOGGER.error("", e);
					} catch (HandshakeException e) {
						LOGGER.error("", e);
					}
				}
				LOGGER.info(" {}", record);
			}
			if (rs.size() < records) {
				assertThat(description + " missing records", rs.size(), is(records));
			} else {
				assertThat(description + " extra records", rs.size(), is(records));
			}
		}
		lastReceivedFlight = rs;
		return rs;
	}

	private void assertFlightRecordsRetransmitted(final List<Record> flight1, final List<Record> flight2) {

		assertThat("retransmitted flight has different number of records", flight2.size(), is(flight1.size()));
		for (int index = 0; index < flight1.size(); ++index) {
			Record record1 = flight1.get(index);
			Record record2 = flight2.get(index);
			assertThat("retransmitted flight record has different epoch", record2.getEpoch(), is(record1.getEpoch()));
			assertThat("retransmitted flight record has different type", record2.getType(), is(record1.getType()));
			assertThat("retransmitted flight record has different lenght", record2.getFragmentLength(),
					is(record1.getFragmentLength()));
			assertThat("retransmitted flight record has no newer seqn", record2.getSequenceNumber(),
					is(greaterThan(record1.getSequenceNumber())));
		}
	}

	private void assertSessionState(String side, UdpConnector endpoint, SessionState state, long timeout, TimeUnit unit)
			throws InterruptedException {
		LatchSessionListener sessionListener = getSessionListenerForEndpoint(side, endpoint);
		switch (state) {
		case ESTABLISHED:
			assertTrue(side + " handshake failed", sessionListener.waitForSessionEstablished(timeout, unit));
			break;
		case COMPLETED:
			if (sessionListener.waitForSessionEstablished(timeout, unit)) {
				assertTrue(side + " handshake not completed", sessionListener.waitForSessionCompleted(timeout, unit));
			} else {
				fail(side + " handshake failed");
			}
			break;
		case FAILED:
			assertNotNull(side + " handshake succeded", sessionListener.waitForSessionFailed(timeout, unit));
			break;
		}
	}

	private LatchSessionListener getSessionListenerForEndpoint(String side, UdpConnector endpoint) {
		InetSocketAddress address = endpoint.getAddress();
		LatchSessionListener sessionListener = serverHelper.sessionListenerMap.get(address);
		if (sessionListener == null && alternativeServerHelper != null) {
			sessionListener = alternativeServerHelper.sessionListenerMap.get(address);
		}
		assertNotNull("missing " + side + "-side session listener for " + address, sessionListener);
		return sessionListener;
	}

	private Connection createServerConnection() {
		Connection connection = new Connection(client.getAddress(), new SerialExecutor(executor));
		connection.setConnectionId(serverCidGenerator.createConnectionId());
		return connection;
	}

	private Connection createClientConnection() {
		ConnectionId cid = clientCidGenerator != null ? clientCidGenerator.createConnectionId() : null;
		if (cid == null) {
			// dummy cid as used by connection store
			byte[] cidBytes = new byte[4];
			RandomManager.currentRandom().nextBytes(cidBytes);
			cid = new ConnectionId(cidBytes);
		}
		Connection connection = new Connection(serverHelper.serverEndpoint, new SerialExecutor(executor));
		connection.setConnectionId(cid);
		return connection;
	}

	public static class TestRecordLayer implements RecordLayer {

		private final AtomicInteger droppedRecords = new AtomicInteger();
		private final AtomicBoolean reverse = new AtomicBoolean();
		private final AtomicInteger drop = new AtomicInteger(0);
		private final AtomicInteger lastSentDatagrams = new AtomicInteger(0);
		protected final UdpConnector connector;

		public TestRecordLayer(UdpConnector connector) {
			this.connector = connector;
		}

		public TestRecordLayer(UdpConnector connector, boolean reverse) {
			this.connector = connector;
			setReverse(reverse);
		}

		public void setDrop(int drop) {
			this.drop.set(drop);
		}

		public void setReverse(boolean reverse) {
			this.reverse.set(reverse);
		}

		public int getLastSentDatagrams() {
			return lastSentDatagrams.get();
		}

		@Override
		public void sendFlight(List<DatagramPacket> flight) throws IOException {
			lastSentDatagrams.set(0);
			for (DatagramPacket datagram : getMessagesOfFlight(flight)) {
				connector.send(datagram);
				lastSentDatagrams.incrementAndGet();
			}
		}

		private List<DatagramPacket> getMessagesOfFlight(List<DatagramPacket> flight) {
			List<DatagramPacket> messages = flight;
			int drop = this.drop.get();
			if (drop != 0) {
				int index;
				if (drop < 0) {
					index = messages.size() + drop;
				} else {
					index = drop - 1;
				}
				if (0 <= index && index < messages.size()) {
					LOGGER.debug("Drop message {}, {} bytes.", index, messages.get(index).getLength());
					messages = new ArrayList<DatagramPacket>(flight);
					messages.remove(index);
				} else {
					LOGGER.warn("Can't drop message {}, out of range [0-{}].", drop, messages.size() - 1);
				}
			}
			if (this.reverse.get()) {
				if (messages.size() > 1) {
					LOGGER.debug("Reverse {} messages.", messages.size());
					messages = new ArrayList<DatagramPacket>(messages);
					Collections.reverse(messages);
				}
			}
			return messages;
		}

		@Override
		public void processRecord(Record record, Connection connection) {
			// records are fetched with getMessagesOfFlight and
			// handed over to the handshaker within the test
		}

		@Override
		public boolean isRunning() {
			return connector.running.get();
		}

		@Override
		public int getMaxDatagramSize(boolean ipv6) {
			return DEFAULT_IPV6_MTU - IPV6_HEADER_LENGTH;
		}

		@Override
		public void dropReceivedRecord(Record record) {
			droppedRecords.incrementAndGet();
		}
	};
}
