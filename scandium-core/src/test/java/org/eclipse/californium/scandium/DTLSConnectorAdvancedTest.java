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
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

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
 * Mainly contains integration test cases verifying the correct interaction between a client and a server.
 */
@Category(Medium.class)
public class DTLSConnectorAdvancedTest {
	public static final Logger LOGGER = LoggerFactory.getLogger(DTLSConnectorAdvancedTest.class.getName());
	
	@ClassRule
	public static DtlsNetworkRule network = new DtlsNetworkRule(DtlsNetworkRule.Mode.DIRECT, DtlsNetworkRule.Mode.NATIVE);

	@Rule
	public TestNameLoggerRule names = new TestNameLoggerRule();

	private static final int CLIENT_CONNECTION_STORE_CAPACITY = 5;
	private static final int MAX_TIME_TO_WAIT_SECS = 2;

	static ConnectorHelper serverHelper;

	private static ExecutorService executor;

	DtlsConnectorConfig clientConfig;
	DTLSConnector client;
	InetSocketAddress clientEndpoint;
	SimpleRawDataChannel clientRawDataChannel;
	DTLSSession establishedClientSession;
	InMemoryConnectionStore clientConnectionStore;

	@BeforeClass
	public static void loadKeys() throws IOException, GeneralSecurityException {
		serverHelper = new ConnectorHelper();
		serverHelper.startServer();
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
		clientConfig = newStandardClientConfig(clientEndpoint);

		client = new DTLSConnector(clientConfig, clientConnectionStore);
		client.setExecutor(executor);

		clientRawDataChannel = new SimpleRawDataChannel(client);
	}

	@After
	public void cleanUp() {
		if (client != null) {
			client.destroy();
		}
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

			// Create handshaker with ReverseRecordLayer to send message in bad
			// order.
			ClientHandshaker clientHandshaker = new ClientHandshaker(new DTLSSession(serverHelper.serverEndpoint, true),
					new ReverseRecordLayer(rawClient), sessionListener, clientConfig, 1280);

			// Start handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs); // check there is no timeout
			// Handle and answer (CLIENT HELLO with cookie)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs);
			// Handle and answer (FINISHED, CHANGE CIPHER SPEC, ...,CERTIFICATE)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Wait to receive response (should be CHANGE CIPHER SPEC, FINISHED)
			rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs);
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
			RawData data = RawData.outbound("Hello World".getBytes(), new AddressEndpointContext(rawServerEndpoint), null, false);
			client.send(data);

			// Create server handshaker
			ServerHandshaker serverHandshaker = new ServerHandshaker(new DTLSSession(clientEndpoint, false, 1),
					new ReverseRecordLayer(rawServer), sessionListener, serverHelper.serverConfig, 1280);

			// Wait to receive response (should be CLIENT HELLO, flight 3)
			List<Record> rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs); // check there is no timeout
			// Handle and answer (should be CERTIFICATE, ... SERVER HELLO DONE, flight 4)
			for (Record r : rs) {
				serverHandshaker.processMessage(r);
			}

			// Wait for receive response (CERTIFICATE, ... , FINISHED, flight 5)
			rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs);
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
			List<Record> rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs); // check there is no timeout
			// Handle and answer (CLIENT HELLO with cookie)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs);
			// Handle and answer (CERTIFICATE, CHANGE CIPHER SPEC, ...,
			// FINISHED)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Wait to receive response from server (should be CHANGE CIPHER
			// SPEC, FINISHED)
			rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs);
			// Handle (CHANGE CIPHER SPEC, FINISHED)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Ensure handshake is successfully done
			assertTrue("handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// Create resume handshaker
			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(clientSession.getSessionIdentifier(), serverHelper.serverEndpoint,
					clientSession.getSessionTicket(), 0);
			ResumingClientHandshaker resumingClientHandshaker = new ResumingClientHandshaker(resumableSession,
					clientRecordLayer, sessionListener, clientConfig, 1280);


			// Start resuming handshake (Send CLIENT HELLO, additional flight)
			resumingClientHandshaker.startHandshake();

			// Wait to receive response (should be SERVER_HELLO, CHANGE CIPHER SPEC, FINISHED, flight 2)
			rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs); // check there is no timeout
			assertEquals(3, rs.size());

			// create server session listener to ensure, that server finish also the handshake
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
			RawData data = RawData.outbound("Hello World".getBytes(), new AddressEndpointContext(rawServerEndpoint), null, false);
			client.send(data);

			// Create server handshaker
			DTLSSession serverSession = new DTLSSession(clientEndpoint, false, 1);
			ServerHandshaker serverHandshaker = new ServerHandshaker(serverSession, serverRecordLayer, sessionListener,
					serverHelper.serverConfig, 1280);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs); // check there is no timeout
			// Handle and answer (should be CERTIFICATE, ... SERVER HELLO DONE)
			for (Record r : rs) {
				serverHandshaker.processMessage(r);
			}

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs);
			for (Record r : rs) {
				serverHandshaker.processMessage(r);
			}

			// Ensure handshake is successfully done
			assertTrue("handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// application data
			rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs);
			assertEquals(1, rs.size());

			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(serverSession.getSessionIdentifier(), clientEndpoint,
					serverSession.getSessionTicket(), 0);
			ResumingServerHandshaker resumingServerHandshaker = new ResumingServerHandshaker(0, resumableSession,
					serverRecordLayer, sessionListener, serverHelper.serverConfig, 1280);

			// force resuming handshake
			client.forceResumeSessionFor(rawServerEndpoint);
			data = RawData.outbound("Hello Again".getBytes(), new AddressEndpointContext(rawServerEndpoint), null, false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs);
			assertEquals(1, rs.size());
			// Handle and answer (should be SERVER HELLO, CCS, FINISHED, flight 2).
			// Note: additional flight used by scandium
			for (Record r : rs) {
				resumingServerHandshaker.processMessage(r);
			}

			// Wait to receive response (CCS, client FINISHED, flight 3) + (application data)
			List<Record> drops = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", drops);
			assertEquals(3, drops.size());
			// remove application data, not retransmitted!
			drops.remove(2); 
			
			// drop last flight 3, server resends flight 2
			serverRecordLayer.resendLastFlight();

			// Wait to receive response (CCS, client FINISHED, flight 3)
			// ("application data" doesn't belong to flight)
			rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs);
			assertEquals(2, rs.size());
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
		SimpleRecordLayer clientRecordLayer = new SimpleRecordLayer(rawClient);
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

			// Wait to receive response (should be HELLO VERIFY REQUEST, flight 2)
			List<Record> rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs); // check there is no timeout
			// Handle and answer (CLIENT HELLO with cookie, flight 3)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE, flight 4)
			rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs);
			// Handle and answer (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED, flight 5)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Wait to receive response from server (should be CHANGE CIPHER SPEC, FINISHED, flight 6)
			List<Record> drops = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", drops);
			// Ignore the receive response, client resends flight 5
			clientRecordLayer.resendLastFlight();

			// Wait for retransmission (should be CHANGE CIPHER SPEC, FINISHED, flight 6)
			rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs);
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
		SimpleRecordLayer serverRecordLayer = new SimpleRecordLayer(rawServer);

		try {
			// Start connector (Server)
			rawServer.start();

			InetSocketAddress rawServerEndpoint = new InetSocketAddress("localhost", rawServer.socket.getLocalPort());
			LatchSessionListener sessionListener = new LatchSessionListener();

			// Start the client
			client.setRawDataReceiver(clientRawDataChannel);
			client.start();
			clientEndpoint = client.getAddress();
			RawData data = RawData.outbound("Hello World".getBytes(), new AddressEndpointContext(rawServerEndpoint), null, false);
			client.send(data);

			// Create server handshaker
			DTLSSession serverSession = new DTLSSession(clientEndpoint, false, 1);
			ServerHandshaker serverHandshaker = new ServerHandshaker(serverSession, serverRecordLayer, sessionListener,
					serverHelper.serverConfig, 1280);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs); // check there is no timeout
			// Handle and answer (should be CERTIFICATE, ... SERVER HELLO DONE)
			for (Record r : rs) {
				serverHandshaker.processMessage(r);
			}

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs);
			for (Record r : rs) {
				serverHandshaker.processMessage(r);
			}

			// Ensure handshake is successfully done
			assertTrue("handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// application data
			rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs);
			assertEquals(1, rs.size());

			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(serverSession.getSessionIdentifier(), clientEndpoint,
					serverSession.getSessionTicket(), 0);
			ResumingServerHandshaker resumingServerHandshaker = new ResumingServerHandshaker(0, resumableSession,
					serverRecordLayer, sessionListener, serverHelper.serverConfig, 1280);

			// force resuming handshake
			client.forceResumeSessionFor(rawServerEndpoint);
			data = RawData.outbound("Hello Again".getBytes(), new AddressEndpointContext(rawServerEndpoint), null, false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs);
			assertEquals(1, rs.size());
			// Handle and answer (should be SERVER HELLO, CCS, FINISHED, VERIFY REQUEST, flight 2).
			// Note: additional flight used by scandium
			for (Record r : rs) {
				resumingServerHandshaker.processMessage(r);
			}

			// Wait to receive response (CCS, client FINISHED, flight 3) + (application data)
			List<Record> drops = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", drops);
			assertEquals(3, drops.size());
			// remove application data, not retransmitted!
			drops.remove(2); 
			
			// drop last flight 3, server resends flight 2
			serverRecordLayer.resendLastFlight();

			// Wait to receive response (CCS, client FINISHED, flight 3)
			// ("application data" doesn't belong to flight)
			rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs);
			assertEquals(2, rs.size());
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
	 * Drops the first transmission of flight 5 to test, if flight 5 is retransmitted.
	 * Usual retransmission, the special case is flight 6, see "testServerFinishedMessageRetransmission". 
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
			RawData data = RawData.outbound("Hello World".getBytes(), new AddressEndpointContext(rawServerEndpoint), null, false);
			client.send(data);

			// Create server handshaker
			ServerHandshaker serverHandshaker = new ServerHandshaker(new DTLSSession(clientEndpoint, false, 1),
					new SimpleRecordLayer(rawServer), sessionListener, serverHelper.serverConfig, 1280);

			// Wait to receive response (should be CLIENT HELLO, flight 3)
			List<Record> rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs); // check there is no timeout
			// Handle and answer (should be CERTIFICATE, ... SERVER HELLO DONE, flight 4)
			for (Record r : rs) {
				serverHandshaker.processMessage(r);
			}

			// Ignore transmission (CERTIFICATE, ... , FINISHED, flight 5)
			List<Record> drops = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", drops);

			// Wait for retransmission (CERTIFICATE, ... , FINISHED, flight 5)
			rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs);
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
		SimpleRecordLayer clientRecordLayer = new SimpleRecordLayer(rawClient);
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
			List<Record> rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs); // check there is no timeout
			// Handle and answer (CLIENT HELLO with cookie)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs);
			// Handle and answer (CERTIFICATE, CHANGE CIPHER SPEC, ...,
			// FINISHED)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Wait to receive response from server (should be CHANGE CIPHER
			// SPEC, FINISHED)
			rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs);
			// Handle (CHANGE CIPHER SPEC, FINISHED)
			for (Record r : rs) {
				clientHandshaker.processMessage(r);
			}

			// Ensure handshake is successfully done
			assertTrue("handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// Create resume handshaker
			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(clientSession.getSessionIdentifier(), serverHelper.serverEndpoint,
					clientSession.getSessionTicket(), 0);
			ResumingClientHandshaker resumingClientHandshaker = new ResumingClientHandshaker(resumableSession,
					clientRecordLayer, sessionListener, clientConfig, 1280);

			// Start resuming handshake (Send CLIENT HELLO, additional flight)
			resumingClientHandshaker.startHandshake();

			// Wait to receive response (should be SERVER_HELLO, CHANGE CIPHER SPEC, FINISHED, fight 2)
			List<Record> drops = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", drops); // check there is no timeout
			assertEquals(3, drops.size());

			// create server session listener to ensure, that server finish also the handshake
			Connection con = serverHelper.serverConnectionStore.get(clientEndpoint);
			assertNotNull(con);
			Handshaker handshaker = con.getOngoingHandshake();
			assertNotNull(handshaker);
			LatchSessionListener serverSessionListener = new LatchSessionListener();
			handshaker.addSessionListener(serverSessionListener);
			
			// drop it, force retransmission (should be SERVER_HELLO, CHANGE CIPHER SPEC, FINISHED, fight 2)
			rs = collector.waitForFlight(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs); // check there is no timeout
			assertEquals(3, rs.size());
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

	private void assertFlightRecordsRetransmitted(final List<Record> flight1, final List<Record> flight2) {

		// assert that flights contains the same number of records.
		assertThat("retransmitted flight has different number of records", flight2.size(), is(flight1.size()));
		for (int index=0; index < flight1.size(); ++index) {
			Record record1 = flight1.get(index);
			Record record2 = flight2.get(index);
			assertThat("retransmitted flight record has different epoch", record2.getEpoch(), is(record1.getEpoch()));
			assertThat("retransmitted flight record has different type", record2.getType(), is(record1.getType()));
			assertThat("retransmitted flight record has no newer seqn", record2.getSequenceNumber(), is(greaterThan(record1.getSequenceNumber())));
		}
	}

	private static class LatchSessionListener extends SessionAdapter {

		private CountDownLatch latch = new CountDownLatch(1);

		@Override
		public void sessionEstablished(Handshaker handshaker, DTLSSession establishedSession)
				throws HandshakeException {
			latch.countDown();
		}

		public boolean waitForSessionEstablished(long timeout, TimeUnit unit) throws InterruptedException {
			return latch.await(timeout, unit);
		}
	};

	public static class SimpleRecordLayer implements RecordLayer {

		protected final UdpConnector connector;
		protected volatile DTLSFlight lastFlight;

		public SimpleRecordLayer(UdpConnector connector) {
			this.connector = connector;
		}

		@Override
		public void sendFlight(DTLSFlight flight) {
			lastFlight = flight;
			for (Record record : flight.getMessages()) {
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

		@Override
		public void cancelRetransmissions() {
		}
	};

	public static class ReverseRecordLayer extends SimpleRecordLayer {

		public ReverseRecordLayer(UdpConnector connector) {
			super(connector);
		}

		@Override
		public void sendFlight(DTLSFlight flight) {
			lastFlight = flight;
			List<Record> messages = flight.getMessages();
			for (int index = messages.size() - 1; index >= 0; index--) {
				try {
					Record record = messages.get(index);
					LOGGER.info("Reverse send {}: {}", index, record);
					connector.sendRecord(record.getPeerAddress(), record.toByteArray());
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
		}
	};
}
