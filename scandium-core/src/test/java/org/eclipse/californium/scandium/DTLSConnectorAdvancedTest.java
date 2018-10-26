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
 *                                                    Update to use ConnectorHelper
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce waitForFlightReceived
 *                                                    with additional retransmission
 *                                                    compensation for faster timeouts
 *    Achim Kraus (Bosch Software Innovations GmbH) - add test for timeout of handshaker
 *                                                    with stopped retransmission
 ******************************************************************************/
package org.eclipse.californium.scandium;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.junit.Assert.*;
import static org.eclipse.californium.scandium.ConnectorHelper.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.scandium.category.Medium;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.ClientHandshaker;
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.DTLSFlight;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.Handshaker;
import org.eclipse.californium.scandium.dtls.InMemoryConnectionStore;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.RecordLayer;
import org.eclipse.californium.scandium.dtls.ResumingClientHandshaker;
import org.eclipse.californium.scandium.dtls.ResumingServerHandshaker;
import org.eclipse.californium.scandium.dtls.ServerHandshaker;
import org.eclipse.californium.scandium.dtls.SessionAdapter;
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
 * between a client and a server.
 */
@Category(Medium.class)
public class DTLSConnectorAdvancedTest {

	public static final Logger LOGGER = LoggerFactory.getLogger(DTLSConnectorAdvancedTest.class.getName());

	@ClassRule
	public static DtlsNetworkRule network = new DtlsNetworkRule(DtlsNetworkRule.Mode.DIRECT,
			DtlsNetworkRule.Mode.NATIVE);

	@Rule
	public TestNameLoggerRule names = new TestNameLoggerRule();

	private static final int CLIENT_CONNECTION_STORE_CAPACITY = 5;
	private static final int MAX_TIME_TO_WAIT_SECS = 2;
	private static final int RETRANSMISSION_TIMEOUT_MS = 400;
	private static final int MAX_RETRANSMISSIONS = 2;

	static ConnectorHelper serverHelper;

	static ExecutorService executor;

	DtlsConnectorConfig clientConfig;
	DTLSConnector client;
	InetSocketAddress clientEndpoint;
	SimpleRawDataChannel clientRawDataChannel;
	DTLSSession establishedClientSession;
	InMemoryConnectionStore clientConnectionStore;
	List<Record> lastReceivedFlight; 
	
	@BeforeClass
	public static void loadKeys() throws IOException, GeneralSecurityException {
		serverHelper = new ConnectorHelper();
		serverHelper.startServer(RETRANSMISSION_TIMEOUT_MS, MAX_RETRANSMISSIONS);
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
		clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
		DtlsConnectorConfig.Builder builder = newStandardClientConfigBuilder(clientEndpoint);
		builder.setRetransmissionTimeout(RETRANSMISSION_TIMEOUT_MS);
		builder.setMaxRetransmissions(MAX_RETRANSMISSIONS);
		clientConfig = builder.build();

		client = new DTLSConnector(clientConfig, clientConnectionStore);
		client.setExecutor(executor);

		clientRawDataChannel = new SimpleRawDataChannel(client);
	}

	@After
	public void cleanUp() {
		if (client != null) {
			client.destroy();
		}
		lastReceivedFlight = null;
		serverHelper.cleanUpServer();
	}

	@Test
	public void testServerReceivingMessagesInBadOrderDuringHandshake() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler();
		UdpConnector rawClient = new UdpConnector(clientEndpoint, collector);
		try {

			// Start connector
			rawClient.start();
			clientEndpoint = new InetSocketAddress(rawClient.socket.getLocalAddress(), rawClient.socket.getLocalPort());
			LatchSessionListener sessionListener = new LatchSessionListener();

			// Create handshaker with ReverseRecordLayer
			// to send message in bad order.
			ClientHandshaker clientHandshaker = new ClientHandshaker(new DTLSSession(serverHelper.serverEndpoint, true),
					new ReverseRecordLayer(rawClient), sessionListener, clientConfig, 1280);

			// Start handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer (FINISHED, CHANGE CIPHER SPEC, ...,CERTIFICATE)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Wait to receive response (should be CHANGE CIPHER SPEC, FINISHED)
			rs = waitForFlightReceived("flight 6", collector, 2);
			// Handle it
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Ensure handshake is successfully done
			assertTrue("handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		} finally {
			rawClient.stop();
		}
	}

	@Test
	public void testClientReceivingMessagesInBadOrderDuringHandshake() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler();
		UdpConnector rawServer = new UdpConnector(new InetSocketAddress(0), collector);

		try {
			// Start connector (Server)
			rawServer.start();
			InetSocketAddress rawServerEndpoint = new InetSocketAddress("localhost", rawServer.socket.getLocalPort());
			LatchSessionListener sessionListener = new LatchSessionListener();

			// Start the client
			client.setRawDataReceiver(clientRawDataChannel);
			client.start();
			clientEndpoint = client.getAddress();
			RawData data = RawData.outbound("Hello World".getBytes(), new AddressEndpointContext(rawServerEndpoint),
					null, false);
			client.send(data);

			// Create server handshaker
			ServerHandshaker serverHandshaker = new ServerHandshaker(new DTLSSession(clientEndpoint, false, 1),
					new ReverseRecordLayer(rawServer), sessionListener, serverHelper.serverConfig, 1280);

			// Wait to receive response (should be CLIENT HELLO, flight 3)
			List<Record> rs = waitForFlightReceived("flight 3", collector, 1);
			// Handle and answer
			// (SERVER_HELLO, CERTIFICATE, ... SERVER HELLO DONE, flight 4)
			for (Record r : rs) {
				serverHandshaker.processMessage(r);
			}

			// Wait for receive response (CERTIFICATE, ... , FINISHED, flight 5)
			rs = waitForFlightReceived("flight 5", collector, 5);
			// Handle and answer (should be CCS, FINISHED, flight 6)
			for (Record r : rs) {
				serverHandshaker.processMessage(r);
			}

			// Ensure handshake is successfully done
			assertTrue("handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		} finally {
			rawServer.stop();
		}
	}

	@Test
	public void testServerResumeReceivingMessagesInBadOrderDuringHandshake() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler();
		UdpConnector rawClient = new UdpConnector(clientEndpoint, collector);
		ReverseRecordLayer clientRecordLayer = new ReverseRecordLayer(rawClient);
		DTLSSession clientSession = new DTLSSession(serverHelper.serverEndpoint, true);
		try {

			// Start connector
			rawClient.start();
			clientEndpoint = new InetSocketAddress(rawClient.socket.getLocalAddress(), rawClient.socket.getLocalPort());
			LatchSessionListener sessionListener = new LatchSessionListener();

			// Create handshaker
			ClientHandshaker clientHandshaker = new ClientHandshaker(clientSession, clientRecordLayer, sessionListener,
					clientConfig, 1280);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED)
			rs = waitForFlightReceived("flight 6", collector, 2);
			// Handle (CHANGE CIPHER SPEC, FINISHED)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Ensure handshake is successfully done
			assertTrue("handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// Create resume handshaker
			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(clientSession.getSessionIdentifier(),
					serverHelper.serverEndpoint, clientSession.getSessionTicket(), 0);
			ResumingClientHandshaker resumingClientHandshaker = new ResumingClientHandshaker(resumableSession,
					clientRecordLayer, sessionListener, clientConfig, 1280);

			// Start resuming handshake (Send CLIENT HELLO, additional flight)
			resumingClientHandshaker.startHandshake();

			// Wait to receive response
			// (SERVER_HELLO, CHANGE CIPHER SPEC, FINISHED, flight 2)
			rs = waitForFlightReceived("flight 2", collector, 3);

			// create server session listener to ensure, 
			// that server finish also the handshake
			Connection con = serverHelper.serverConnectionStore.get(clientEndpoint);
			assertNotNull(con);
			Handshaker handshaker = con.getOngoingHandshake();
			assertNotNull(handshaker);
			LatchSessionListener serverSessionListener = new LatchSessionListener();
			handshaker.addSessionListener(serverSessionListener);

			// Handle and answer ( CHANGE CIPHER SPEC, FINISHED, flight 3)
			for (Record r : rs) {
				resumingClientHandshaker.processMessage(r);
			}

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
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler();
		UdpConnector rawServer = new UdpConnector(new InetSocketAddress(0), collector);
		ReverseRecordLayer serverRecordLayer = new ReverseRecordLayer(rawServer);

		try {
			// Start connector (Server)
			rawServer.start();

			InetSocketAddress rawServerEndpoint = new InetSocketAddress("localhost", rawServer.socket.getLocalPort());
			LatchSessionListener sessionListener = new LatchSessionListener();

			// Start the client
			client.setRawDataReceiver(clientRawDataChannel);
			client.start();
			clientEndpoint = client.getAddress();
			RawData data = RawData.outbound("Hello World".getBytes(), new AddressEndpointContext(rawServerEndpoint),
					null, false);
			client.send(data);

			// Create server handshaker
			DTLSSession serverSession = new DTLSSession(clientEndpoint, false, 1);
			ServerHandshaker serverHandshaker = new ServerHandshaker(serverSession, serverRecordLayer, sessionListener,
					serverHelper.serverConfig, 1280);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer (should be SERVER_HELLO, CERTIFICATE, ... SERVER HELLO DONE)
			for (Record r : rs) {
				serverHandshaker.processMessage(r);
			}

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3", collector, 5);
			for (Record r : rs) {
				serverHandshaker.processMessage(r);
			}

			// Ensure handshake is successfully done
			assertTrue("handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// application data
			rs = waitForFlightReceived("app data", collector, 1);

			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(serverSession.getSessionIdentifier(), clientEndpoint,
					serverSession.getSessionTicket(), 0);
			ResumingServerHandshaker resumingServerHandshaker = new ResumingServerHandshaker(0, resumableSession,
					serverRecordLayer, sessionListener, serverHelper.serverConfig, 1280);

			// force resuming handshake
			client.forceResumeSessionFor(rawServerEndpoint);
			data = RawData.outbound("Hello World, Again!".getBytes(), new AddressEndpointContext(rawServerEndpoint), null,
					false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer 
			// (SERVER HELLO, CCS, FINISHED, flight 2).
			for (Record r : rs) {
				resumingServerHandshaker.processMessage(r);
			}

			// Wait to receive response
			// (CCS, client FINISHED, flight 3) + (application data)
			List<Record> drops = waitForFlightReceived("flight 3 + app data", collector, 3);
			// remove application data, not retransmitted!
			drops.remove(2);

			// drop last flight 3, server resends flight 2
			serverRecordLayer.resendLastFlight();

			// Wait to receive response (CCS, client FINISHED, flight 3)
			// ("application data" doesn't belong to flight)
			rs = waitForFlightReceived("flight 3", collector, 2);
			for (Record r : rs) {
				resumingServerHandshaker.processMessage(r);
			}
			assertTrue("handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		} finally {
			rawServer.stop();
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
	 */
	@Test
	public void testServerFinishedMessageRetransmission() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler();
		UdpConnector rawClient = new UdpConnector(clientEndpoint, collector);
		BasicRecordLayer clientRecordLayer = new BasicRecordLayer(rawClient);
		try {

			// Start connector
			rawClient.start();
			clientEndpoint = new InetSocketAddress(rawClient.socket.getLocalAddress(), rawClient.socket.getLocalPort());
			LatchSessionListener sessionListener = new LatchSessionListener();

			// Create handshaker
			ClientHandshaker clientHandshaker = new ClientHandshaker(new DTLSSession(serverHelper.serverEndpoint, true),
					clientRecordLayer, sessionListener, clientConfig, 1280);

			// Start handshake (Send CLIENT HELLO, flight 1)
			clientHandshaker.startHandshake();

			// Wait to receive response
			// (HELLO VERIFY REQUEST, flight 2)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie, flight 3)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Wait for response
			// (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE, flight 4)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED, flight 5)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED, flight 6)
			List<Record> drops = waitForFlightReceived("flight 6", collector, 2);
			// Ignore the receive response, client resends flight 5
			clientRecordLayer.resendLastFlight();

			// Wait for retransmission
			// (CHANGE CIPHER SPEC, FINISHED, flight 6)
			rs = waitForFlightReceived("flight 6", collector, 2);
			assertFlightRecordsRetransmitted(drops, rs);
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Ensure handshake is successfully done
			assertTrue("handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		} finally {
			rawClient.stop();
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
	 */
	@Test
	public void testResumeClientFinishedMessageRetransmission() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler();
		UdpConnector rawServer = new UdpConnector(new InetSocketAddress(0), collector);
		BasicRecordLayer serverRecordLayer = new BasicRecordLayer(rawServer);

		try {
			// Start connector (Server)
			rawServer.start();

			InetSocketAddress rawServerEndpoint = new InetSocketAddress("localhost", rawServer.socket.getLocalPort());
			LatchSessionListener sessionListener = new LatchSessionListener();

			// Start the client
			client.setRawDataReceiver(clientRawDataChannel);
			client.start();
			clientEndpoint = client.getAddress();
			RawData data = RawData.outbound("Hello World".getBytes(), new AddressEndpointContext(rawServerEndpoint),
					null, false);
			client.send(data);

			// Create server handshaker
			DTLSSession serverSession = new DTLSSession(clientEndpoint, false, 1);
			ServerHandshaker serverHandshaker = new ServerHandshaker(serverSession, serverRecordLayer, sessionListener,
					serverHelper.serverConfig, 1280);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer (should be CERTIFICATE, ... SERVER HELLO DONE)
			for (Record r : rs) {
				serverHandshaker.processMessage(r);
			}

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3", collector, 5);
			for (Record r : rs) {
				serverHandshaker.processMessage(r);
			}

			// Ensure handshake is successfully done
			assertTrue("handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// application data
			rs = waitForFlightReceived("app data", collector, 1);

			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(serverSession.getSessionIdentifier(), clientEndpoint,
					serverSession.getSessionTicket(), 0);
			ResumingServerHandshaker resumingServerHandshaker = new ResumingServerHandshaker(0, resumableSession,
					serverRecordLayer, sessionListener, serverHelper.serverConfig, 1280);

			// force resuming handshake
			client.forceResumeSessionFor(rawServerEndpoint);
			data = RawData.outbound("Hello Again".getBytes(), new AddressEndpointContext(rawServerEndpoint), null,
					false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer
			// (SERVER HELLO, CCS, FINISHED, VERIFY REQUEST, flight 2).
			for (Record r : rs) {
				resumingServerHandshaker.processMessage(r);
			}

			// Wait to receive response
			// (CCS, client FINISHED, flight 3) + (application data)
			List<Record> drops = waitForFlightReceived("flight 3", collector, 3);
			// remove application data, not retransmitted!
			drops.remove(2);

			// drop last flight 3, server resends flight 2
			serverRecordLayer.resendLastFlight();

			// Wait to receive response (CCS, client FINISHED, flight 3)
			// ("application data" doesn't belong to flight)
			rs = waitForFlightReceived("flight 3", collector, 2);
			assertFlightRecordsRetransmitted(drops, rs);
			for (Record r : rs) {
				resumingServerHandshaker.processMessage(r);
			}
			assertTrue("handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		} finally {
			rawServer.stop();
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
	 */
	@Test
	public void testFinishedMessageRetransmission() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler();
		UdpConnector rawServer = new UdpConnector(new InetSocketAddress(0), collector);

		try {
			// Start connector (Server)
			rawServer.start();
			InetSocketAddress rawServerEndpoint = new InetSocketAddress("localhost", rawServer.socket.getLocalPort());
			LatchSessionListener sessionListener = new LatchSessionListener();

			// Start the client
			client.setRawDataReceiver(clientRawDataChannel);
			client.start();
			clientEndpoint = client.getAddress();
			RawData data = RawData.outbound("Hello World".getBytes(), new AddressEndpointContext(rawServerEndpoint),
					null, false);
			client.send(data);

			// Create server handshaker
			ServerHandshaker serverHandshaker = new ServerHandshaker(new DTLSSession(clientEndpoint, false, 1),
					new BasicRecordLayer(rawServer), sessionListener, serverHelper.serverConfig, 1280);

			// Wait to receive response (should be CLIENT HELLO, flight 3)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer
			// (CERTIFICATE, ... SERVER HELLO DONE, flight 4)
			for (Record r : rs) {
				serverHandshaker.processMessage(r);
			}

			// Ignore transmission (CERTIFICATE, ... , FINISHED, flight 5)
			List<Record> drops = waitForFlightReceived("flight 3", collector, 5);

			// Wait for retransmission (CERTIFICATE, ... , FINISHED, flight 5)
			rs = waitForFlightReceived("flight 3", collector, 5);
			assertFlightRecordsRetransmitted(drops, rs);
			// Handle and answer (should be CCS, FINISHED, flight 6)
			for (Record r : rs) {
				serverHandshaker.processMessage(r);
			}

			// Ensure handshake is successfully done
			assertTrue("handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
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
	 */
	@Test
	public void testResumeFinishedMessageRetransmission() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler();
		UdpConnector rawClient = new UdpConnector(clientEndpoint, collector);
		BasicRecordLayer clientRecordLayer = new BasicRecordLayer(rawClient);
		DTLSSession clientSession = new DTLSSession(serverHelper.serverEndpoint, true);
		try {

			// Start connector
			rawClient.start();
			clientEndpoint = new InetSocketAddress(rawClient.socket.getLocalAddress(), rawClient.socket.getLocalPort());
			LatchSessionListener sessionListener = new LatchSessionListener();

			// Create handshaker
			ClientHandshaker clientHandshaker = new ClientHandshaker(clientSession, clientRecordLayer, sessionListener,
					clientConfig, 1280);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED)
			rs = waitForFlightReceived("flight 6", collector, 2);
			// Handle (CHANGE CIPHER SPEC, FINISHED)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Ensure handshake is successfully done
			assertTrue("handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// Create resume handshaker
			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(clientSession.getSessionIdentifier(),
					serverHelper.serverEndpoint, clientSession.getSessionTicket(), 0);
			ResumingClientHandshaker resumingClientHandshaker = new ResumingClientHandshaker(resumableSession,
					clientRecordLayer, sessionListener, clientConfig, 1280);

			// Start resuming handshake (Send CLIENT HELLO, additional flight)
			resumingClientHandshaker.startHandshake();

			// Wait to receive response
			// (SERVER_HELLO, CHANGE CIPHER SPEC, FINISHED, fight 2)
			List<Record> drops = waitForFlightReceived("flight 2", collector, 3);

			// create server session listener to ensure, 
			// that server finish also the handshake
			Connection con = serverHelper.serverConnectionStore.get(clientEndpoint);
			assertNotNull(con);
			Handshaker handshaker = con.getOngoingHandshake();
			assertNotNull(handshaker);
			LatchSessionListener serverSessionListener = new LatchSessionListener();
			handshaker.addSessionListener(serverSessionListener);

			// drop it, force retransmission
			// (SERVER_HELLO, CHANGE CIPHER SPEC, FINISHED, fight 2)
			rs = waitForFlightReceived("flight 2", collector, 3);
			assertFlightRecordsRetransmitted(drops, rs);
			// Handle and answer ( CHANGE CIPHER SPEC, FINISHED, flight 3)
			for (Record r : rs) {
				resumingClientHandshaker.processMessage(r);
			}

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertTrue("server handshake failed",
					serverSessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		} finally {
			rawClient.stop();
		}
	}

	/**
	 * Test the server resuming handshake fails, if clients FINISH is dropped.
	 */
	@Test
	public void testServerResumeTimeout() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler();
		UdpConnector rawClient = new UdpConnector(clientEndpoint, collector);
		BasicRecordLayer clientRecordLayer = new BasicRecordLayer(rawClient);
		DTLSSession clientSession = new DTLSSession(serverHelper.serverEndpoint, true);
		try {

			// Start connector
			rawClient.start();
			clientEndpoint = new InetSocketAddress(rawClient.socket.getLocalAddress(), rawClient.socket.getLocalPort());
			LatchSessionListener sessionListener = new LatchSessionListener();

			// Create handshaker
			ClientHandshaker clientHandshaker = new ClientHandshaker(clientSession, clientRecordLayer, sessionListener,
					clientConfig, 1280);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED)
			rs = waitForFlightReceived("flight 6", collector, 2);
			// Handle (CHANGE CIPHER SPEC, FINISHED)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Ensure handshake is successfully done
			assertTrue("handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// Create resume handshaker
			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(clientSession.getSessionIdentifier(),
					serverHelper.serverEndpoint, clientSession.getSessionTicket(), 0);
			ResumingClientHandshaker resumingClientHandshaker = new ResumingClientHandshaker(resumableSession,
					clientRecordLayer, sessionListener, clientConfig, 1280);

			// Start resuming handshake (Send CLIENT HELLO, additional flight)
			resumingClientHandshaker.startHandshake();

			// Wait to receive response
			// (SERVER_HELLO, CHANGE CIPHER SPEC, FINISHED, fight 2)
			rs = waitForFlightReceived("flight 2", collector, 3);

			// create server session listener to ensure,
			// that server finish also the handshake
			Connection con = serverHelper.serverConnectionStore.get(clientEndpoint);
			assertNotNull(con);
			Handshaker handshaker = con.getOngoingHandshake();
			assertNotNull(handshaker);
			LatchSessionListener serverSessionListener = new LatchSessionListener();
			handshaker.addSessionListener(serverSessionListener);

			// Handle and answer
			// (CHANGE CIPHER SPEC, FINISHED (drop), flight 3)
			clientRecordLayer.setDrop(-1);
			for (Record r : rs) {
				resumingClientHandshaker.processMessage(r);
			}

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 1));
			Throwable error = serverSessionListener.waitForSessionFailed(timeout, TimeUnit.MILLISECONDS);
			assertNotNull("server handshake not failed", error);
		} finally {
			rawClient.stop();
		}
	}

	/**
	 * Test the server handshake fails, if clients FINISH is dropped.
	 */
	@Test
	public void testServerTimeout() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler();
		UdpConnector rawClient = new UdpConnector(clientEndpoint, collector);
		BasicRecordLayer clientRecordLayer = new BasicRecordLayer(rawClient);
		DTLSSession clientSession = new DTLSSession(serverHelper.serverEndpoint, true);
		try {

			// Start connector
			rawClient.start();
			clientEndpoint = new InetSocketAddress(rawClient.socket.getLocalAddress(), rawClient.socket.getLocalPort());
			LatchSessionListener sessionListener = new LatchSessionListener();

			// Create handshaker
			ClientHandshaker clientHandshaker = new ClientHandshaker(clientSession, clientRecordLayer, sessionListener,
					clientConfig, 1280);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);

			// create server session listener to ensure, 
			// that server finish also the handshake
			Connection con = serverHelper.serverConnectionStore.get(clientEndpoint);
			assertNotNull(con);
			Handshaker handshaker = con.getOngoingHandshake();
			assertNotNull(handshaker);
			LatchSessionListener serverSessionListener = new LatchSessionListener();
			handshaker.addSessionListener(serverSessionListener);

			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			clientRecordLayer.setDrop(-1);
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Ensure handshake failed
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));
			Throwable error = serverSessionListener.waitForSessionFailed(timeout, TimeUnit.MILLISECONDS);
			assertNotNull("server handshake not failed", error);
		} finally {
			rawClient.stop();
		}
	}

	@Test
	public void testClientResumeTimeout() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler();
		UdpConnector rawServer = new UdpConnector(new InetSocketAddress(0), collector);
		BasicRecordLayer serverRecordLayer = new BasicRecordLayer(rawServer);

		try {
			// Start connector (Server)
			rawServer.start();

			InetSocketAddress rawServerEndpoint = new InetSocketAddress("localhost", rawServer.socket.getLocalPort());
			LatchSessionListener sessionListener = new LatchSessionListener();

			// Start the client
			client.setRawDataReceiver(clientRawDataChannel);
			client.start();
			clientEndpoint = client.getAddress();
			RawData data = RawData.outbound("Hello World".getBytes(), new AddressEndpointContext(rawServerEndpoint),
					null, false);
			client.send(data);

			// Create server handshaker
			DTLSSession serverSession = new DTLSSession(clientEndpoint, false, 1);
			ServerHandshaker serverHandshaker = new ServerHandshaker(serverSession, serverRecordLayer, sessionListener,
					serverHelper.serverConfig, 1280);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer (should be CERTIFICATE, ... SERVER HELLO DONE)
			for (Record r : rs) {
				serverHandshaker.processMessage(r);
			}

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3", collector, 5);
			for (Record r : rs) {
				serverHandshaker.processMessage(r);
			}

			// Ensure handshake is successfully done
			assertTrue("handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// application data
			rs = waitForFlightReceived("app data", collector, 1);

			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(serverSession.getSessionIdentifier(), clientEndpoint,
					serverSession.getSessionTicket(), 0);
			ResumingServerHandshaker resumingServerHandshaker = new ResumingServerHandshaker(0, resumableSession,
					serverRecordLayer, sessionListener, serverHelper.serverConfig, 1280);

			// force resuming handshake
			client.forceResumeSessionFor(rawServerEndpoint);
			data = RawData.outbound("Hello Again".getBytes(), new AddressEndpointContext(rawServerEndpoint), null,
					false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1", collector, 1);

			Connection con = clientConnectionStore.get(rawServerEndpoint);
			assertNotNull(con);
			Handshaker handshaker = con.getOngoingHandshake();
			assertNotNull(handshaker);
			LatchSessionListener clientSessionListener = new LatchSessionListener();
			handshaker.addSessionListener(clientSessionListener);

			// Handle and answer
			// (SERVER HELLO, CCS, FINISHED drop, flight 2).
			serverRecordLayer.setDrop(-1);
			for (Record r : rs) {
				resumingServerHandshaker.processMessage(r);
			}

			// Ensure handshake failed
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));
			Throwable error = clientSessionListener.waitForSessionFailed(timeout, TimeUnit.MILLISECONDS);
			assertNotNull("client handshake not failed", error);
		} finally {
			rawServer.stop();
		}
	}

	@Test
	public void testClientTimeout() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler();
		UdpConnector rawServer = new UdpConnector(new InetSocketAddress(0), collector);

		try {
			// Start connector (Server)
			rawServer.start();
			InetSocketAddress rawServerEndpoint = new InetSocketAddress("localhost", rawServer.socket.getLocalPort());
			LatchSessionListener sessionListener = new LatchSessionListener();

			// Start the client
			client.setRawDataReceiver(clientRawDataChannel);
			client.start();
			clientEndpoint = client.getAddress();
			RawData data = RawData.outbound("Hello World".getBytes(), new AddressEndpointContext(rawServerEndpoint),
					null, false);
			client.send(data);

			// Create server handshaker
			BasicRecordLayer serverRecordLayer = new BasicRecordLayer(rawServer);
			ServerHandshaker serverHandshaker = new ServerHandshaker(new DTLSSession(clientEndpoint, false, 1),
					serverRecordLayer, sessionListener, serverHelper.serverConfig, 1280);

			// Wait to receive response (should be CLIENT HELLO, flight 3)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer
			// (CERTIFICATE, ... SERVER HELLO DONE, flight 4)
			for (Record r : rs) {
				serverHandshaker.processMessage(r);
			}

			Connection con = clientConnectionStore.get(rawServerEndpoint);
			assertNotNull(con);
			Handshaker handshaker = con.getOngoingHandshake();
			assertNotNull(handshaker);
			LatchSessionListener clientSessionListener = new LatchSessionListener();
			handshaker.addSessionListener(clientSessionListener);

			// Wait for transmission (CERTIFICATE, ... , FINISHED, flight 5)
			rs = waitForFlightReceived("flight 3", collector, 5);
			// Handle and answer (should be CCS, FINISHED (drop), flight 6)
			serverRecordLayer.setDrop(-1);
			for (Record r : rs) {
				serverHandshaker.processMessage(r);
			}

			// Ensure handshake is successfully done
			assertTrue("handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			// Ensure handshake failed
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));
			Throwable error = clientSessionListener.waitForSessionFailed(timeout, TimeUnit.MILLISECONDS);
			assertNotNull("client handshake not failed", error);
		} finally {
			rawServer.stop();
		}
	}

	private List<Record> waitForFlightReceived(String description, RecordCollectorDataHandler collector, int records)
			throws InterruptedException {
		List<Record> rs = collector.waitForFlight(records, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
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
				if (record2.getLength() != record1.getLength()) {
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
		assertThat(description, rs.size(), is(records));
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
			assertThat("retransmitted flight record has different lenght", record2.getLength(), is(record1.getLength()));
			assertThat("retransmitted flight record has no newer seqn", record2.getSequenceNumber(),
					is(greaterThan(record1.getSequenceNumber())));
		}
	}

	private static class LatchSessionListener extends SessionAdapter {

		private CountDownLatch established = new CountDownLatch(1);
		private CountDownLatch failed = new CountDownLatch(1);
		private AtomicReference<Throwable> error = new AtomicReference<Throwable>();

		@Override
		public void sessionEstablished(Handshaker handshaker, DTLSSession establishedSession)
				throws HandshakeException {
			established.countDown();
		}

		@Override
		public void handshakeFailed(Handshaker handshaker, Throwable error) {
			this.error.set(error);
			failed.countDown();
		}

		public boolean waitForSessionEstablished(long timeout, TimeUnit unit) throws InterruptedException {
			return established.await(timeout, unit);
		}

		public Throwable waitForSessionFailed(long timeout, TimeUnit unit) throws InterruptedException {
			if (failed.await(timeout, unit)) {
				return error.get();
			}
			return null;
		}
	};

	public static class BasicRecordLayer implements RecordLayer {

		private final AtomicInteger drop = new AtomicInteger(0);
		protected final UdpConnector connector;
		protected volatile DTLSFlight lastFlight;

		public BasicRecordLayer(UdpConnector connector) {
			this.connector = connector;
		}

		public void setDrop(int drop) {
			this.drop.set(drop);
		}

		@Override
		public void sendFlight(DTLSFlight flight) {
			lastFlight = flight;
			for (Record record : getMessagesOfFlight(flight)) {
				try {
					connector.sendRecord(record.getPeerAddress(), record.toByteArray());
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
		}

		public void resendLastFlight() throws GeneralSecurityException {
			DTLSFlight flight = lastFlight;
			if (null == flight) {
				throw new IllegalStateException("no last flight!");
			}
			flight.incrementTries();
			flight.setNewSequenceNumbers();
			sendFlight(flight);
		}

		public List<Record> getMessagesOfFlight(DTLSFlight flight) {
			List<Record> messages = flight.getMessages();
			int drop = this.drop.get();
			if (drop != 0) {
				int index = drop - 1;
				messages = new ArrayList<Record>(messages);
				if (drop < 0) {
					index = messages.size() + drop;
				}
				if (0 <= index && index < messages.size()) {
					messages.remove(index);
				}
			}
			return messages;
		}
	};

	public static class ReverseRecordLayer extends BasicRecordLayer {

		public ReverseRecordLayer(UdpConnector connector) {
			super(connector);
		}

		@Override
		public List<Record> getMessagesOfFlight(DTLSFlight flight) {
			List<Record> messages = super.getMessagesOfFlight(flight);
			if (messages.size() > 1) {
				List<Record> reverse = new ArrayList<Record>();
				for (int index = messages.size() - 1; index >= 0; index--) {
					reverse.add(messages.get(index));
				}
				messages = reverse;
			}
			return messages;
		}
	};
}
