/*******************************************************************************
 * Copyright (c) 2015, 2018 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - Initial creation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 464383
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix 464812
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add support for stale
 *                                                    session expiration (466554)
 *    Kai Hudalla (Bosch Software Innovations GmbH) - replace SessionStore with ConnectionStore
 *                                                    keeping all information about the connection
 *                                                    to a peer in a single place
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 472196
 *    Achim Kraus, Kai Hudalla (Bosch Software Innovations GmbH) - add test case for bug 478538
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use DtlsTestTools' accessors to explicitly retrieve
 *                                                    client & server keys and certificate chains
 *    Bosch Software Innovations GmbH - add test cases for GitHub issue #1
 *    Achim Kraus (Bosch Software Innovations GmbH) - add tests for
 *                                                    CorrelationContextMatcher
 *    Achim Kraus (Bosch Software Innovations GmbH) - add restart test with internal executor
 *    Achim Kraus (Bosch Software Innovations GmbH) - add test for retransmission of FINISHED
 *                                                    add asserts for record sequence numbers
 *                                                    of retransmitted flights
 *    Achim Kraus (Bosch Software Innovations GmbH) - add onSent() and onError().
 *                                                    use SimpleMessageCallback
 *                                                    issue #305
 *    Achim Kraus (Bosch Software Innovations GmbH) - add check for onError() in
 *                                                    testConnectorAbortsHandshakeOnUnknownPskIdentity
 *    Achim Kraus (Bosch Software Innovations GmbH) - move correlation tests to
 *                                                    DTLSCorrelationTest.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add tests for automatic resumption
 *    Vikram (University of Rostock) - add tests to check ECDHE_PSK CipherSuite
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove HELLO_VERIFY_REQUEST
 *                                                    from resumption tests
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove unused sendRecord
 *    Achim Kraus (Bosch Software Innovations GmbH) - move advanced tests to
 *                                                    DTLSConnectorAdvancedTest
 ******************************************************************************/
package org.eclipse.californium.scandium;

import static org.eclipse.californium.scandium.ConnectorHelper.LOCAL;
import static org.eclipse.californium.scandium.ConnectorHelper.SERVER_CONNECTION_STORE_CAPACITY;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.config.CertificateAuthenticationMode;
import org.eclipse.californium.elements.rule.LoggingRule;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.rule.ThreadsRule;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.SimpleMessageCallback;
import org.eclipse.californium.elements.util.StandardCharsets;
import org.eclipse.californium.elements.util.TestThreadFactory;
import org.eclipse.californium.scandium.ConnectorHelper.LatchDecrementingRawDataChannel;
import org.eclipse.californium.scandium.ConnectorHelper.LatchSessionListener;
import org.eclipse.californium.scandium.ConnectorHelper.RecordCollectorDataHandler;
import org.eclipse.californium.scandium.ConnectorHelper.TestContext;
import org.eclipse.californium.scandium.ConnectorHelper.AlertCatcher;
import org.eclipse.californium.scandium.ConnectorHelper.UdpConnector;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.ApplicationMessage;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.ClientHello;
import org.eclipse.californium.scandium.dtls.ClientKeyExchange;
import org.eclipse.californium.scandium.dtls.CompressionMethod;
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.ContentType;
import org.eclipse.californium.scandium.dtls.DTLSContext;
import org.eclipse.californium.scandium.dtls.DtlsHandshakeTimeoutException;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.eclipse.californium.scandium.dtls.ExtendedMasterSecretMode;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.HandshakeMessage;
import org.eclipse.californium.scandium.dtls.HandshakeType;
import org.eclipse.californium.scandium.dtls.Handshaker;
import org.eclipse.californium.scandium.dtls.HelloRequest;
import org.eclipse.californium.scandium.dtls.HelloVerifyRequest;
import org.eclipse.californium.scandium.dtls.InMemoryConnectionStore;
import org.eclipse.californium.scandium.dtls.InMemoryReadWriteLockConnectionStore;
import org.eclipse.californium.scandium.dtls.PSKClientKeyExchange;
import org.eclipse.californium.scandium.dtls.ProtocolVersion;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.ResumptionSupportingConnectionStore;
import org.eclipse.californium.scandium.dtls.SessionId;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedPskStore;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedSinglePskStore;
import org.eclipse.californium.scandium.dtls.x509.NewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.SingleCertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.StaticNewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.rule.DtlsNetworkRule;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Ignore;
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
public class DTLSConnectorTest {

	public static final Logger LOGGER = LoggerFactory.getLogger(DTLSConnectorTest.class);

	@ClassRule
	public static DtlsNetworkRule network = new DtlsNetworkRule(DtlsNetworkRule.Mode.DIRECT,
			DtlsNetworkRule.Mode.NATIVE);

	@ClassRule
	public static ThreadsRule cleanup = new ThreadsRule();

	@Rule
	public TestNameLoggerRule names = new TestNameLoggerRule();

	@Rule 
	public LoggingRule logging = new LoggingRule();

	private static final int CLIENT_CONNECTION_STORE_CAPACITY = 5;
	private static final PskPublicInformation CLIENT_IDENTITY = new PskPublicInformation("Client_identity");
	private static final String CLIENT_IDENTITY_SECRET = "secretPSK";
	private static final int MAX_TIME_TO_WAIT_SECS = 2;

	private static ConnectorHelper serverHelper;
	private static ExecutorService executor;

	DtlsConnectorConfig clientConfig;
	DTLSConnector client;
	TestContext clientTestContext;
	DTLSContext establishedClientContext;
	ResumptionSupportingConnectionStore clientConnectionStore;

	@BeforeClass
	public static void loadKeys() throws IOException, GeneralSecurityException {

		executor = ExecutorsUtil.newFixedThreadPool(2, new TestThreadFactory("DTLS-"));

		AdvancedSinglePskStore pskStore = new AdvancedSinglePskStore(CLIENT_IDENTITY,
				CLIENT_IDENTITY_SECRET.getBytes());

		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder()
				.setTrustedCertificates(DtlsTestTools.getTrustedCertificates()).setTrustAllRPKs().build();

		serverHelper = new ConnectorHelper(network);

		serverHelper.serverBuilder.set(DtlsConfig.DTLS_RETRANSMISSION_TIMEOUT, 500, TimeUnit.MILLISECONDS)
				.set(DtlsConfig.DTLS_ADDITIONAL_ECC_TIMEOUT, 2000, TimeUnit.MILLISECONDS)
				.set(DtlsConfig.DTLS_MAX_RETRANSMISSIONS, 2)
				.set(DtlsConfig.DTLS_SUPPORT_KEY_MATERIAL_EXPORT, true)
				.set(DtlsConfig.DTLS_EXTENDED_MASTER_SECRET_MODE, ExtendedMasterSecretMode.ENABLED)
				.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false)
				.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
						CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256)
				.setAdvancedCertificateVerifier(verifier).setAdvancedPskStore(pskStore);
		serverHelper.startServer();
	}

	@AfterClass
	public static void tearDown() {
		if (serverHelper != null) {
			serverHelper.destroyServer();
			serverHelper = null;
		}
		if (executor != null) {
			ExecutorsUtil.shutdownExecutorGracefully(100, executor);
			executor = null;
		}
	}

	@Before
	public void setUp() throws Exception {
		clientConfig = newClientConfigBuilder().setAddress(LOCAL).build();
		clientConnectionStore = ConnectorHelper.createDebugConnectionStore(clientConfig);
		client = serverHelper.createClient(clientConfig, clientConnectionStore);
		client.setExecutor(executor);
	}

	@After
	public void cleanUp() {
		if (client != null) {
			client.destroy();
		}
		serverHelper.cleanUpServer();
	}

	private static DtlsConnectorConfig.Builder newClientConfigBuilder() throws Exception {
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder()
				.setTrustedCertificates(DtlsTestTools.getTrustedCertificates()).setTrustAllRPKs().build();
		return DtlsConnectorConfig.builder(network.createClientTestConfig())
				.set(DtlsConfig.DTLS_MAX_CONNECTIONS, CLIENT_CONNECTION_STORE_CAPACITY)
				.set(DtlsConfig.DTLS_STALE_CONNECTION_THRESHOLD, 60, TimeUnit.SECONDS)
				.set(DtlsConfig.DTLS_RECEIVER_THREAD_COUNT, 1)
				.set(DtlsConfig.DTLS_CONNECTOR_THREAD_COUNT, 2)
				.setLoggingTag("client")
				.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getClientPrivateKey(),
						DtlsTestTools.getClientCertificateChain(), CertificateType.RAW_PUBLIC_KEY,
						CertificateType.X_509))
				.setAdvancedCertificateVerifier(verifier);
	}

	@Test
	public void testSendInvokesMessageCallbackOnSent() throws Exception {

		// GIVEN a message including a MessageCallback
		SimpleMessageCallback callback = new SimpleMessageCallback();
		RawData outboundMessage = RawData.outbound(new byte[] { 0x01 },
				new AddressEndpointContext(serverHelper.serverEndpoint), callback, false);

		// WHEN sending the message
		givenAnEstablishedSession(outboundMessage, true);

		// THEN assert that the callback has been invoked with a endpoint
		// context
		assertTrue(callback.isSent(TimeUnit.SECONDS.toMillis(MAX_TIME_TO_WAIT_SECS)));
		assertThat(serverHelper.serverRawDataProcessor.getLatestInboundMessage(), is(notNullValue()));
		assertThat(serverHelper.serverRawDataProcessor.getLatestInboundMessage().getEndpointContext(),
				is(notNullValue()));
	}

	@Test
	public void testSendToPortZeroFails() throws Exception {

		// GIVEN a message including a MessageCallback
		InetSocketAddress malicousDestination = new InetSocketAddress(serverHelper.serverEndpoint.getAddress(), 0);
		SimpleMessageCallback callback = new SimpleMessageCallback();
		RawData outboundMessage = RawData.outbound(new byte[] { 0x01 },
				new AddressEndpointContext(malicousDestination), callback, false);

		// WHEN sending the message
		client.start();
		client.send(outboundMessage);

		// THEN assert that the callback has been invoked with an error
		assertThat(callback.getError(TimeUnit.SECONDS.toMillis(MAX_TIME_TO_WAIT_SECS)), is(notNullValue()));
	}

	@Test
	public void testMessagesFromUnknowClientGetsDropped() throws Exception {

		// GIVEN a record;
		ApplicationMessage message = new ApplicationMessage(Bytes.EMPTY);
		Record record = new Record(ContentType.APPLICATION_DATA, ProtocolVersion.VERSION_DTLS_1_2, 10, message);
		RawData data = RawData.outbound(record.toByteArray(), new AddressEndpointContext(serverHelper.serverEndpoint),
				null, false);
		// GIVEN a unknown client;
		UDPConnector connector = new UDPConnector(null, network.createClientTestConfig());
		try {
			// WHEN sending the message
			connector.start();
			connector.send(data);

			// THEN assert that the drop handler has been invoked
			Record event = serverHelper.serverDropCatcher.waitForEvent(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertThat(event, is(notNullValue()));
			assertThat(event.getPeerAddress(), is(notNullValue()));
		} finally {
			connector.destroy();
		}
	}

	@Test
	public void testConnectorEstablishesSecureSession() throws Exception {
		givenAnEstablishedSession(true);
	}

	/**
	 * Verifies that a DTLSConnector terminates its connection with a peer when
	 * receiving a CLOSE_NOTIFY alert from the peer (bug #478538).
	 * 
	 * @throws Exception if test cannot be executed
	 */
	@Test
	public void testConnectorTerminatesConnectionOnReceivingCloseNotify() throws Exception {

		// GIVEN a CLOSE_NOTIFY alert
		AlertMessage alert = new AlertMessage(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);

		assertConnectionTerminatedOnAlert(alert);
	}

	/**
	 * Verifies that a DTLSConnector terminates its connection with a peer when
	 * receiving a FATAL alert from the peer.
	 * 
	 * @throws Exception if test cannot be executed
	 */
	@Test
	public void testConnectorTerminatesConnectionOnReceivingFatalAlert() throws Exception {

		// GIVEN a FATAL alert
		AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR);

		assertConnectionTerminatedOnAlert(alert);
	}

	private void assertConnectionTerminatedOnAlert(final AlertMessage alertToSend) throws Exception {

		givenAnEstablishedSession(false);

		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertNotNull("missing connection", connection);
		// WHEN sending a CLOSE_NOTIFY alert to the server
		client.sendAlert(connection, establishedClientContext, alertToSend);

		// THEN assert that the server has removed all connection state with
		// client
		AlertMessage alert = serverHelper.serverAlertCatcher.waitForEvent(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
		assertNotNull(alert);
		Connection serverConnection = serverHelper.serverConnectionStore.get(clientTestContext.getClientAddress());
		if (alert.getDescription() == AlertDescription.CLOSE_NOTIFY) {
			assertThat(serverConnection, is(notNullValue()));
			assertThat(serverConnection.isClosed(), is(true));
		} else {
			assertThat(serverConnection, is(nullValue()));
		}
	}

	/**
	 * Verify we send retransmission with standard timeout.
	 */
	@Test
	public void testRetransmissionNoEcc() throws Exception {
		testRetransmission(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8);
	}

	/**
	 * Verify we send retransmission with extended timeout.
	 */
	@Test
	public void testRetransmissionPskEcc() throws Exception {
		testRetransmission(CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256);
	}

	/**
	 * Verify we send retransmission with extended timeout.
	 */
	@Test
	public void testRetransmissionEcc() throws Exception {
		testRetransmission(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
	}

	private void testRetransmission(CipherSuite cipherSuite) throws Exception {
		// Configure UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler();
		collector.applyDtlsContext(null);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);

		try {
			rawClient.start();
			InetSocketAddress clientEndpoint = rawClient.getAddress();

			// Send CLIENT_HELLO
			ClientHello clientHello = createClientHello(cipherSuite);
			rawClient.sendRecord(serverHelper.serverEndpoint,
					DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, clientHello.toByteArray()));

			// Handle HELLO_VERIFY_REQUEST
			List<Record> rs = collector.waitForRecords(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs); // check there is no timeout
			Record record = rs.get(0);
			assertThat("Expected HANDSHAKE message from server", record.getType(), is(ContentType.HANDSHAKE));
			HandshakeMessage msg = (HandshakeMessage) record.getFragment();
			assertThat("Expected HELLO_VERIFY_REQUEST from server", msg.getMessageType(),
					is(HandshakeType.HELLO_VERIFY_REQUEST));
			Connection con = serverHelper.serverConnectionStore.get(clientEndpoint);
			assertNull(con);
			byte[] cookie = ((HelloVerifyRequest) msg).getCookie();
			assertNotNull(cookie);

			// Send CLIENT_HELLO with cookie
			clientHello.setCookie(cookie);
			rawClient.sendRecord(serverHelper.serverEndpoint,
					DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, clientHello.toByteArray()));

			// Handle SERVER HELLO
			// assert that we have an ongoingHandshake for this connection
			rs = collector.waitForRecords(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs); // check there is no timeout
			con = serverHelper.serverConnectionStore.get(clientEndpoint);
			assertNotNull(con);
			Handshaker ongoingHandshake = con.getOngoingHandshake();
			assertNotNull(ongoingHandshake);
			record = rs.get(0);
			assertThat("Expected HANDSHAKE message from server", record.getType(), is(ContentType.HANDSHAKE));
			msg = (HandshakeMessage) record.getFragment();
			assertThat("Expected SERVER_HELLO from server", msg.getMessageType(), is(HandshakeType.SERVER_HELLO));

			// Do not reply
			// Handle retransmission of SERVER HELLO

			int timeout = cipherSuite.isEccBased() ? 2000 : 200;
			rs = collector.waitForRecords(timeout, TimeUnit.MILLISECONDS);
			// check there is no timeout
			assertNull("retransmission too early", rs);

			// Handle retransmission of SERVER HELLO
			rs = collector.waitForRecords(1000, TimeUnit.MILLISECONDS);
			assertNotNull("timeout", rs); // check there is no timeout
			con = serverHelper.serverConnectionStore.get(clientEndpoint);
			assertNotNull(con);
			ongoingHandshake = con.getOngoingHandshake();
			assertNotNull(ongoingHandshake);
			record = rs.get(0);
			assertThat("Expected HANDSHAKE message from server", record.getType(), is(ContentType.HANDSHAKE));
			msg = (HandshakeMessage) record.getFragment();
			assertThat("Expected SERVER_HELLO from server", msg.getMessageType(), is(HandshakeType.SERVER_HELLO));

		} finally {
			rawClient.stop();
		}
	}

	/**
	 * Verify we don't send retransmission after receiving the expected message.
	 */
	@Test
	public void testNoRetransmissionIfMessageReceived() throws Exception {
		// Configure UDP connector
		RecordCollectorDataHandler clientCollector = new RecordCollectorDataHandler();
		clientCollector.applyDtlsContext(null);
		UdpConnector rawClient = new UdpConnector(LOCAL, clientCollector);

		try {
			rawClient.start();
			InetSocketAddress clientEndpoint = rawClient.getAddress();

			// Send CLIENT_HELLO
			ClientHello clientHello = createClientHello(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8);
			rawClient.sendRecord(serverHelper.serverEndpoint,
					DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, clientHello.toByteArray()));

			// Handle HELLO_VERIFY_REQUEST
			List<Record> rs = clientCollector.waitForRecords(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs); // check there is no timeout
			Record record = rs.get(0);
			assertThat("Expected HANDSHAKE message from server", record.getType(), is(ContentType.HANDSHAKE));
			HandshakeMessage msg = (HandshakeMessage) record.getFragment();
			assertThat("Expected HELLO_VERIFY_REQUEST from server", msg.getMessageType(),
					is(HandshakeType.HELLO_VERIFY_REQUEST));
			Connection con = serverHelper.serverConnectionStore.get(clientEndpoint);
			assertNull(con);
			byte[] cookie = ((HelloVerifyRequest) msg).getCookie();
			assertNotNull(cookie);

			// Send CLIENT_HELLO with cookie
			clientHello.setCookie(cookie);
			rawClient.sendRecord(serverHelper.serverEndpoint,
					DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, clientHello.toByteArray()));

			// Handle SERVER HELLO
			// assert that we have an ongoingHandshake for this connection
			rs = clientCollector.waitForRecords(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("timeout", rs); // check there is no timeout
			con = serverHelper.serverConnectionStore.get(clientEndpoint);
			assertNotNull(con);
			Handshaker ongoingHandshake = con.getOngoingHandshake();
			assertNotNull(ongoingHandshake);
			record = rs.get(0);
			assertThat("Expected HANDSHAKE message from server", record.getType(), is(ContentType.HANDSHAKE));
			msg = (HandshakeMessage) record.getFragment();
			assertThat("Expected SERVER_HELLO from server", msg.getMessageType(), is(HandshakeType.SERVER_HELLO));

			// Send CLIENT_KEY_EXCHANGE
			ClientKeyExchange keyExchange = new PSKClientKeyExchange(CLIENT_IDENTITY);
			keyExchange.setMessageSeq(clientHello.getMessageSeq() + 1);
			rawClient.sendRecord(serverHelper.serverEndpoint,
					DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 1, keyExchange.toByteArray()));

			// Ensure there is no retransmission
			assertNull(clientCollector.waitForRecords(
				(long) (serverHelper.serverConfig.getTimeAsInt(DtlsConfig.DTLS_RETRANSMISSION_TIMEOUT, TimeUnit.MILLISECONDS) * 1.1), TimeUnit.MILLISECONDS));
		} finally {
			rawClient.stop();
		}
	}

	/**
	 * Verifies behavior described in
	 * <a href="https://tools.ietf.org/html/rfc6347#section-4.2.8" target=
	 * "_blank"> section 4.2.8 of RFC 6347 (DTLS 1.2)</a>.
	 * 
	 * @throws Exception if test fails
	 */
	@Test
	public void testConnectorKeepsExistingSessionOnEpochZeroClientHello() throws Exception {

		givenAnEstablishedSession(true);
		SessionId sessionId = clientTestContext.getSessionIdentifier();

		// client has successfully established a secure session with server
		// and has been "crashed". Now we try to establish a new session with
		// a client connecting from the same IP address and port again
		RecordCollectorDataHandler handler = new RecordCollectorDataHandler();
		handler.applyDtlsContext(null);

		UdpConnector rawClient = new UdpConnector(clientTestContext.getClientAddress(), handler);
		rawClient.start();

		rawClient.sendRecord(serverHelper.serverEndpoint,
				DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, createClientHello().toByteArray()));

		try {
			List<Record> flight = handler.assertFlight(1, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			Record record = flight.get(0);
			assertThat("Expected HANDSHAKE message from server", record.getType(), is(ContentType.HANDSHAKE));
			HandshakeMessage msg = (HandshakeMessage) record.getFragment();
			assertThat("Expected HELLO_VERIFY_REQUEST from server", msg.getMessageType(),
					is(HandshakeType.HELLO_VERIFY_REQUEST));
			Connection con = serverHelper.serverConnectionStore.get(clientTestContext.getClientAddress());
			assertNotNull(con);
			assertNotNull(con.getEstablishedSession());
			assertThat("Server should not have established new session with client yet",
					con.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		} finally {
			synchronized (rawClient) {
				rawClient.stop();
				// give OS some time to release socket so that we can bind
				// original client to it again
				rawClient.wait(100);
			}
		}

		// now check if we can still use the originally established session to
		// exchange application data
		clientTestContext.setLatchCount(1);
		// restart original client binding to same IP address and port as before
		client.restart();
		// make sure client still has original session in its cache
		Connection con = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertNotNull(con);
		assertNotNull(con.getEstablishedSession());
		assertThat(con.getEstablishedSession().getSessionIdentifier(), is(sessionId));

		RawData data = RawData.outbound("Hello World".getBytes(),
				new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);

		con = serverHelper.serverConnectionStore.get(client.getAddress());
		assertNotNull(con);
		assertNotNull(con.getEstablishedSession());
		assertTrue(clientTestContext.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		assertThat("Server should have reused existing session with client instead of creating a new one",
				con.getEstablishedSession().getSessionIdentifier(), is(sessionId));
	}

	/**
	 * Verifies behavior described in
	 * <a href="https://tools.ietf.org/html/rfc6347#section-4.2.8" target=
	 * "_blank"> section 4.2.8 of RFC 6347 (DTLS 1.2)</a>.
	 */
	@Test
	public void testAcceptClientHelloAfterIncompleteHandshake() throws Exception {
		if (client != null) {
			client.destroy();
		}
		// GIVEN a handshake that has been aborted before completion
		givenAnIncompleteHandshake();

		// WHEN starting a new handshake (epoch 0) reusing the same client IP
		DtlsConnectorConfig clientConfig = newClientConfigBuilder().setAddress(LOCAL).build();
		clientConnectionStore = ConnectorHelper.createDebugConnectionStore(clientConfig);
		client = new DTLSConnector(clientConfig, clientConnectionStore);

		// THEN assert that the handshake succeeds and a session is established
		// sometime the retransmission of the previous incomplete handshake
		// fails the new handshake. Therefore a retry is used.
		givenAnEstablishedSessionWithRetry();
	}

	/**
	 * Verifies behavior described in
	 * <a href="https://tools.ietf.org/html/rfc6347#section-4.2.8" target=
	 * "_blank"> section 4.2.8 of RFC 6347 (DTLS 1.2)</a>.
	 */
	@Test
	public void testClientHelloRetransmissionDoNotRestartHandshake() throws Exception {
		// configure UDP connector
		RecordCollectorDataHandler handler = new RecordCollectorDataHandler();
		handler.applyDtlsContext(null);
		UdpConnector rawClient = new UdpConnector(LOCAL, handler);
		try {
			rawClient.start();
			InetSocketAddress clientEndpoint = rawClient.getAddress();

			// send CLIENT_HELLO
			ClientHello clientHello = createClientHello(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8);
			rawClient.sendRecord(serverHelper.serverEndpoint,
					DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, clientHello.toByteArray()));

			// handle HELLO_VERIFY_REQUEST
			List<Record> flight = handler.assertFlight(1, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			Record record = flight.get(0);

			assertThat("Expected HANDSHAKE message from server", record.getType(), is(ContentType.HANDSHAKE));
			HandshakeMessage msg = (HandshakeMessage) record.getFragment();
			assertThat("Expected HELLO_VERIFY_REQUEST from server", msg.getMessageType(),
					is(HandshakeType.HELLO_VERIFY_REQUEST));
			Connection con = serverHelper.serverConnectionStore.get(clientEndpoint);
			assertNull(con);
			byte[] cookie = ((HelloVerifyRequest) msg).getCookie();
			assertNotNull(cookie);

			// send CLIENT_HELLO with cookie
			clientHello.setCookie(cookie);
			rawClient.sendRecord(serverHelper.serverEndpoint,
					DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, clientHello.toByteArray()));

			// assert that we have an ongoingHandshake for this connection
			flight = handler.assertFlight(1, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			record = flight.get(0);

			assertThat("Expected HANDSHAKE message from server", record.getType(), is(ContentType.HANDSHAKE));
			msg = (HandshakeMessage) record.getFragment();
			assertThat("Expected SERVER_HELLO from server", msg.getMessageType(), is(HandshakeType.SERVER_HELLO));

			con = serverHelper.serverConnectionStore.get(clientEndpoint);
			assertNotNull(con);
			Handshaker ongoingHandshake = con.getOngoingHandshake();
			assertNotNull(ongoingHandshake);

			// send CLIENT_KEY_EXCHANGE
			ClientKeyExchange keyExchange = new PSKClientKeyExchange(CLIENT_IDENTITY);
			rawClient.sendRecord(serverHelper.serverEndpoint,
					DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 1, keyExchange.toByteArray()));
			handler.assertFlight(1, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			// re-send CLIENT_HELLO to simulate retransmission
			rawClient.sendRecord(serverHelper.serverEndpoint,
					DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, clientHello.toByteArray()));

			// send Alert to receive an answer even
			AlertMessage closeNotify = new AlertMessage(AlertLevel.FATAL, AlertDescription.CLOSE_NOTIFY);
			rawClient.sendRecord(serverHelper.serverEndpoint,
					DtlsTestTools.newDTLSRecord(ContentType.ALERT.getCode(), 0, 2, closeNotify.toByteArray()));

			// check that we don't get a response for this CLIENT_HELLO, it must
			// be ignore
			flight = handler.assertFlight(1, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			record = flight.get(0);
			assertThat("Expected ALERT message from server", record.getType(), is(ContentType.ALERT));

		} finally {
			rawClient.stop();
		}
	}

	/**
	 * Verifies behavior described in
	 * <a href="https://tools.ietf.org/html/rfc6347#section-4.2.8" target=
	 * "_blank"> section 4.2.8 of RFC 6347 (DTLS 1.2)</a>.
	 * 
	 * @throws Exception if test fails
	 */
	@Test
	public void testConnectorReplacesExistingSessionAfterFullHandshake() throws Exception {

		givenAnEstablishedSession(true);

		// the ID of the originally established session
		SessionId originalSessionId = clientTestContext.getSessionIdentifier();

		// client has successfully established a secure session with server
		// and has been "crashed"
		// now we try to establish a new session with a client connecting from
		// the same IP address and port again
		clientTestContext.setLatchCount(1);
		DtlsConnectorConfig clientConfig = newClientConfigBuilder().setAddress(clientTestContext.getClientAddress()).build();
		ResumptionSupportingConnectionStore clientConnectionStore = ConnectorHelper.createDebugConnectionStore(clientConfig);
		client = new DTLSConnector(clientConfig, clientConnectionStore);
		client.setRawDataReceiver(clientTestContext.getChannel());
		client.setExecutor(executor);
		client.start();

		RawData data = RawData.outbound("Hello World".getBytes(),
				new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);

		assertTrue(clientTestContext.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		Connection con = serverHelper.serverConnectionStore.get(clientTestContext.getClientAddress());
		assertNotNull(con);
		assertNotNull(con.getEstablishedSession());
		// make sure that the server has created a new session replacing the
		// original one with the client
		assertThat("Server should have replaced original session with client with a newly established one",
				con.getEstablishedSession().getSessionIdentifier(), is(not(originalSessionId)));
	}

	@Test
	public void testStartStopWithNewAddress() throws Exception {
		// Do a first handshake
		givenAnEstablishedSession(false);
		byte[] sessionId = clientTestContext.getSessionIdentifier().getBytes();

		// Stop the client
		client.stop();
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getBytes());

		// Restart it
		client.start();
		assertNotEquals(clientTestContext.getClientAddress(), client.getAddress());

		// Prepare message sending
		final String msg = "Hello Again";
		clientTestContext.setLatchCount(1);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null,
				false);
		client.send(data);
		assertTrue(clientTestContext.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getBytes());
		assertClientIdentity(RawPublicKeyIdentity.class);
	}

	@Test
	public void testStartStopWithSameAddress() throws Exception {
		// Do a first handshake
		givenAnEstablishedSession(false);
		byte[] sessionId = clientTestContext.getSessionIdentifier().getBytes();

		// Stop the client
		client.stop();
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getBytes());

		// Restart it
		client.restart();
		assertEquals(clientTestContext.getClientAddress(), client.getAddress());

		// Prepare message sending
		final String msg = "Hello Again";
		clientTestContext.setLatchCount(1);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null,
				false);
		client.send(data);
		assertTrue(clientTestContext.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getBytes());
		assertClientIdentity(RawPublicKeyIdentity.class);
	}

	@Test
	public void testStartStopWithSameAddressAndInternalExecutor() throws Exception {
		// use internal executor
		client.setExecutor(null);
		// Do a first handshake
		givenAnEstablishedSession(false);
		byte[] sessionId = clientTestContext.getSessionIdentifier().getBytes();

		// Stop the client
		client.stop();
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getBytes());

		// Restart it
		client.restart();
		assertEquals(clientTestContext.getClientAddress(), client.getAddress());

		// Prepare message sending
		final String msg = "Hello Again";
		clientTestContext.setLatchCount(1);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null,
				false);
		client.send(data);
		assertTrue(clientTestContext.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getBytes());
		assertClientIdentity(RawPublicKeyIdentity.class);
	}

	@Test
	public void testStartStopWithSameAddressPersistent() throws Exception {
		// Do a first handshake
		givenAnEstablishedSession(false);
		byte[] sessionId = clientTestContext.getSessionIdentifier().getBytes();

		// Stop the client
		client.stop();
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getBytes());
		DatagramWriter writer = new DatagramWriter(128);
		connection.writeTo(writer);
		DatagramReader reader = new DatagramReader(writer.toByteArray());
		Connection connection2 = Connection.fromReader(reader, 0);
		clientConnectionStore.remove(connection, true);
		connection2.setConnectorContext(executor, null);
		clientConnectionStore.put(connection2);

		// Restart it
		client.restart();
		assertEquals(clientTestContext.getClientAddress(), client.getAddress());

		// Prepare message sending
		final String msg = "Hello Again";
		clientTestContext.setLatchCount(1);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null,
				false);
		client.send(data);
		assertTrue(clientTestContext.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getBytes());
		assertClientIdentity(RawPublicKeyIdentity.class);
	}

	@Test
	public void testConnectorSendsHelloVerifyRequestWithoutCreatingSession() throws Exception {
		int capacity = serverHelper.serverConnectionStore.remainingCapacity();
		RecordCollectorDataHandler handler = new RecordCollectorDataHandler();
		handler.applyDtlsContext(null);
		UdpConnector rawClient = new UdpConnector(LOCAL, handler);

		try {
			rawClient.start();

			// send a CLIENT_HELLO without cookie
			ClientHello clientHello = createClientHello();

			rawClient.sendRecord(serverHelper.serverEndpoint,
					DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, clientHello.toByteArray()));

			List<Record> flight = handler.assertFlight(1, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			Record record = flight.get(0);

			assertThat("Expected HANDSHAKE message from server", record.getType(), is(ContentType.HANDSHAKE));
			HandshakeMessage handshake = (HandshakeMessage) record.getFragment();
			assertThat("Expected HELLO_VERIFY_REQUEST from server", handshake.getMessageType(),
					is(HandshakeType.HELLO_VERIFY_REQUEST));
			assertThat("Server should not have created session for CLIENT_HELLO containging no cookie", capacity,
					is(serverHelper.serverConnectionStore.remainingCapacity()));
		} finally {
			rawClient.stop();
		}
	}

	/**
	 * Using version DTLS 1.0 in CLIENT_HELLO triggers first a
	 * HELLO_VERIFY_REQUEST and then an ALERT, both with version DTLS 1.0.
	 */
	@Test
	public void testConnectorSendsHelloVerifyRequestAlsoForLowerVersion() throws Exception {

		RecordCollectorDataHandler handler = new RecordCollectorDataHandler();
		handler.applyDtlsContext(null);
		UdpConnector rawClient = new UdpConnector(LOCAL, handler);
		ProtocolVersion version = ProtocolVersion.VERSION_DTLS_1_0;
		try {
			rawClient.start();

			// send a CLIENT_HELLO without cookie
			ClientHello clientHello = createClientHello(version);

			rawClient.sendRecord(serverHelper.serverEndpoint, DtlsTestTools
					.newDTLSRecord(ContentType.HANDSHAKE.getCode(), version, 0, 0, clientHello.toByteArray()));

			List<Record> flight = handler.assertFlight(1, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			Record record = flight.get(0);

			assertThat("Expected HANDSHAKE message from server", record.getType(), is(ContentType.HANDSHAKE));
			HandshakeMessage handshake = (HandshakeMessage) record.getFragment();
			assertThat("Expected HELLO_VERIFY_REQUEST from server", handshake.getMessageType(),
					is(HandshakeType.HELLO_VERIFY_REQUEST));
			assertThat("Expected protocol version from server", record.getVersion(), is(version));

			clientHello.setCookie(((HelloVerifyRequest) handshake).getCookie());
			clientHello.setMessageSeq(clientHello.getMessageSeq() + 1);

			rawClient.sendRecord(serverHelper.serverEndpoint, DtlsTestTools
					.newDTLSRecord(ContentType.HANDSHAKE.getCode(), version, 0, 1, clientHello.toByteArray()));

			flight = handler.assertFlight(1, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			record = flight.get(0);
			assertThat("Expected ALERT message from server", record.getType(), is(ContentType.ALERT));
			assertThat("Expected protocol version from server", record.getVersion(), is(version));

		} finally {
			rawClient.stop();
		}
	}

	/**
	 * Using a invalid version DTLS 0.9 in CLIENT_HELLO triggers first a
	 * HELLO_VERIFY_REQUEST and then an SERVER_HELLO, both with version DTLS
	 * 1.0.
	 */
	@Ignore
	@Test
	public void testConnectorSendsHelloVerifyRequestAlsoForTooLowVersion() throws Exception {

		RecordCollectorDataHandler handler = new RecordCollectorDataHandler();
		handler.applyDtlsContext(null);
		UdpConnector rawClient = new UdpConnector(LOCAL, handler);
		ProtocolVersion version = ProtocolVersion.valueOf("0.9");
		try {
			rawClient.start();

			// send a CLIENT_HELLO without cookie
			ClientHello clientHello = createClientHello(version);

			rawClient.sendRecord(serverHelper.serverEndpoint, DtlsTestTools
					.newDTLSRecord(ContentType.HANDSHAKE.getCode(), version, 0, 0, clientHello.toByteArray()));

			List<Record> flight = handler.assertFlight(1, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			Record record = flight.get(0);

			assertThat("Expected HANDSHAKE message from server", record.getType(), is(ContentType.HANDSHAKE));
			HandshakeMessage handshake = (HandshakeMessage) record.getFragment();
			assertThat("Expected HELLO_VERIFY_REQUEST from server", handshake.getMessageType(),
					is(HandshakeType.HELLO_VERIFY_REQUEST));
			assertThat("Expected protocol version from server", record.getVersion(),
					is(ProtocolVersion.VERSION_DTLS_1_0));

			clientHello.setCookie(((HelloVerifyRequest) handshake).getCookie());
			clientHello.setMessageSeq(clientHello.getMessageSeq() + 1);

			rawClient.sendRecord(serverHelper.serverEndpoint, DtlsTestTools
					.newDTLSRecord(ContentType.HANDSHAKE.getCode(), version, 0, 1, clientHello.toByteArray()));

			flight = handler.assertFlight(1, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			record = flight.get(0);
			assertThat("Expected Handshake message from server", record.getType(), is(ContentType.ALERT));
			assertThat("Expected protocol version from server", record.getVersion(),
					is(ProtocolVersion.VERSION_DTLS_1_0));

		} finally {
			rawClient.stop();
		}
	}

	/**
	 * Using version DTLS 1.3 in CLIENT_HELLO triggers first a
	 * HELLO_VERIFY_REQUEST and then an SERVER_HELLO, both with version DTLS
	 * 1.2.
	 */
	@Test
	public void testConnectorSendsHelloVerifyRequestAlsoForHigherVersion() throws Exception {

		RecordCollectorDataHandler handler = new RecordCollectorDataHandler();
		handler.applyDtlsContext(null);
		UdpConnector rawClient = new UdpConnector(LOCAL, handler);
		ProtocolVersion version = ProtocolVersion.valueOf("1.3");
		try {
			rawClient.start();

			// send a CLIENT_HELLO without cookie
			ClientHello clientHello = createClientHello(version);

			rawClient.sendRecord(serverHelper.serverEndpoint, DtlsTestTools
					.newDTLSRecord(ContentType.HANDSHAKE.getCode(), version, 0, 0, clientHello.toByteArray()));

			List<Record> flight = handler.assertFlight(1, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			Record record = flight.get(0);

			assertThat("Expected HANDSHAKE message from server", record.getType(), is(ContentType.HANDSHAKE));
			HandshakeMessage handshake = (HandshakeMessage) record.getFragment();
			assertThat("Expected HELLO_VERIFY_REQUEST from server", handshake.getMessageType(),
					is(HandshakeType.HELLO_VERIFY_REQUEST));
			assertThat("Expected protocol version from server", record.getVersion(),
					is(ProtocolVersion.VERSION_DTLS_1_2));

			clientHello.setCookie(((HelloVerifyRequest) handshake).getCookie());
			clientHello.setMessageSeq(clientHello.getMessageSeq() + 1);

			rawClient.sendRecord(serverHelper.serverEndpoint, DtlsTestTools
					.newDTLSRecord(ContentType.HANDSHAKE.getCode(), version, 0, 1, clientHello.toByteArray()));

			flight = handler.assertFlight(1, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			record = flight.get(0);
			assertThat("Expected Handshake message from server", record.getType(), is(ContentType.HANDSHAKE));
			assertThat("Expected protocol version from server", record.getVersion(),
					is(ProtocolVersion.VERSION_DTLS_1_2));

		} finally {
			rawClient.stop();
		}
	}

	@Test
	public void testConnectorAcceptsClientHelloAfterLostHelloVerifyRequest() throws Exception {

		// make the server send a HELLO_VERIFY_REQUEST
		testConnectorSendsHelloVerifyRequestWithoutCreatingSession();
		// ignore the HELLO_VERIFY_REQUEST (i.e. assume the request is lost)
		// and try to establish a fresh session
		givenAnEstablishedSession(true);
		Connection connection = serverHelper.serverConnectionStore.get(clientTestContext.getClientAddress());
		assertNotNull(connection);
		assertThat(connection.hasEstablishedDtlsContext(), is(true));
	}

	@SuppressWarnings("deprecation")
	@Test
	public void testConnectorTerminatesHandshakeIfConnectionStoreIsExhausted() throws Exception {
		logging.setLoggingLevel("ERROR", InMemoryConnectionStore.class, InMemoryReadWriteLockConnectionStore.class);
		serverHelper.serverConnectionStore.clear();
		assertEquals(SERVER_CONNECTION_STORE_CAPACITY, serverHelper.serverConnectionStore.remainingCapacity());
		assertTrue(serverHelper.serverConnectionStore.put(new Connection(new InetSocketAddress("192.168.0.1", 5050))
				.setConnectorContext(executor, null)));
		assertTrue(serverHelper.serverConnectionStore.put(new Connection(new InetSocketAddress("192.168.0.2", 5050))
				.setConnectorContext(executor, null)));
		assertTrue(serverHelper.serverConnectionStore.put(new Connection(new InetSocketAddress("192.168.0.3", 5050))
				.setConnectorContext(executor, null)));

		LatchDecrementingRawDataChannel clientRawDataChannel = new LatchDecrementingRawDataChannel(1);
		client.setRawDataReceiver(clientRawDataChannel);
		client.start();
		InetSocketAddress clientEndpoint = client.getAddress();
		RawData data = RawData.outbound("Hello World".getBytes(),
				new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);

		assertFalse(clientRawDataChannel.await(500, TimeUnit.MILLISECONDS));
		assertNull("Server should not have established a session with client",
				serverHelper.serverConnectionStore.get(clientEndpoint));
	}

	/**
	 * Verifies that connector ignores CLIENT KEY EXCHANGE with unknown PSK
	 * identity.
	 */
	@Test
	public void testConnectorIgnoresUnknownPskIdentity() throws Exception {
		ensureConnectorIgnoresBadCredentials(
				new AdvancedSinglePskStore("unknownIdentity", CLIENT_IDENTITY_SECRET.getBytes()));
		AlertMessage alert = serverHelper.serverAlertCatcher.waitForEvent(2, TimeUnit.SECONDS);
		assertThat("server side internal alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.UNKNOWN_PSK_IDENTITY)));
	}

	/**
	 * Verifies that connector ignores FINISHED message with bad PSK.
	 */
	@Test
	public void testConnectorIgnoresBadPsk() throws Exception {
		ensureConnectorIgnoresBadCredentials(new AdvancedSinglePskStore(CLIENT_IDENTITY, "bad_psk".getBytes()));
	}

	private void ensureConnectorIgnoresBadCredentials(AdvancedPskStore pskStoreWithBadCredentials) throws Exception {
		if (client != null) {
			client.destroy();
		}
		clientConfig = DtlsConnectorConfig.builder(network.createClientTestConfig())
				.set(DtlsConfig.DTLS_RECEIVER_THREAD_COUNT, 1)
				.set(DtlsConfig.DTLS_CONNECTOR_THREAD_COUNT, 2)
				.setLoggingTag("client").setAddress(LOCAL)
				.set(DtlsConfig.DTLS_RETRANSMISSION_TIMEOUT, 250, TimeUnit.MILLISECONDS)
				.set(DtlsConfig.DTLS_MAX_RETRANSMISSIONS, 1)
				.setAdvancedPskStore(pskStoreWithBadCredentials).build();
		client = serverHelper.createClient(clientConfig);
		client.start();
		SimpleMessageCallback callback = new SimpleMessageCallback();
		RawData data = RawData.outbound("Hello".getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint),
				callback, false);
		client.send(data);

		Throwable error = callback.getError(TimeUnit.SECONDS.toMillis(MAX_TIME_TO_WAIT_SECS * 5));
		assertThat(error, is(notNullValue()));
		// timeout is not reported with HandshakeException!
		assertThat(error, instanceOf(DtlsHandshakeTimeoutException.class));

		LatchSessionListener listener = serverHelper.sessionListenerMap.get(client.getAddress());
		assertThat("server side session listener missing", listener, is(notNullValue()));
		Throwable cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("server side handshake failure missing", cause, is(notNullValue()));
		assertThat(cause.getMessage(), containsString("Handshake flight"));

		listener = serverHelper.sessionListenerMap.get(serverHelper.serverEndpoint);
		assertThat("client side session listener missing", listener, is(notNullValue()));
		cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("client side handshake failure missing", cause, is(notNullValue()));
		assertThat(cause.getMessage(), containsString("Handshake flight "));
	}

	@Test
	public void testProcessApplicationUsesNullPrincipalForUnauthenticatedPeer() throws Exception {
		ConnectorHelper serverHelper = new ConnectorHelper(network);
		try {
			// given an established session with a server that doesn't require
			// clients to authenticate
			serverHelper.serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE)
					.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(),
							DtlsTestTools.getServerCertificateChain(), CertificateType.RAW_PUBLIC_KEY));
			serverHelper.startServer();
			serverHelper.givenAnEstablishedSession(client, true);
			assertThat(serverHelper.serverRawDataProcessor.getClientEndpointContext().getPeerIdentity(),
					is(nullValue()));
		} finally {
			serverHelper.destroyServer();
		}
	}

	private void assertClientIdentity(final Class<?> principalType) {

		// assert that client identity is of given type
		assertThat(serverHelper.serverRawDataProcessor.getClientEndpointContext().getPeerIdentity(),
				instanceOf(principalType));
	}

	@Test
	public void testGetMaximumFragmentLengthReturnsDefaultValueForUnknownPeer() {
		// given an empty client side connection store
		clientConnectionStore.clear();

		// when querying the max fragment length for an unknown peer
		InetSocketAddress unknownPeer = serverHelper.serverEndpoint;
		int maxFragmentLength = client.getMaximumFragmentLength(unknownPeer);

		// then the value is the minimum IPv4 MTU - DTLS/UDP/IP header overhead
		assertThat(maxFragmentLength, is(DTLSConnector.DEFAULT_IPV4_MTU - Record.DTLS_HANDSHAKE_HEADER_LENGTH
				- DTLSConnector.IPV4_HEADER_LENGTH));
	}

	@Test
	public void testDestroyClearsConnectionStore() throws Exception {
		// given a non-empty connection store
		givenAnEstablishedSession(true);
		assertThat(clientConnectionStore.get(serverHelper.serverEndpoint), is(notNullValue()));

		// when the client connector is destroyed
		client.destroy();

		// assert that the client's connection store is empty
		assertThat(clientConnectionStore.remainingCapacity(), is(CLIENT_CONNECTION_STORE_CAPACITY));
		assertThat(clientConnectionStore.get(serverHelper.serverEndpoint), is(nullValue()));
	}

	@Test
	public void testNoRenegotiationAllowed() throws Exception {
		givenAnEstablishedSession(false);

		// Catch alert receive by the client
		AlertCatcher alertCatcher = new AlertCatcher();
		client.setAlertHandler(alertCatcher);

		// send a CLIENT_HELLO message to the server to renegotiation connection
		Record record = new Record(ContentType.HANDSHAKE, establishedClientContext.getWriteEpoch(), createClientHello(),
				establishedClientContext, false, 0);
		record.setAddress(serverHelper.serverEndpoint, null);
		client.sendRecord(record);

		// ensure server answer with a NO_RENOGIATION alert
		AlertMessage alert = alertCatcher.waitForEvent(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
		assertThat("client received alert", alert,
				is(new AlertMessage(AlertLevel.WARNING, AlertDescription.NO_RENEGOTIATION)));
	}

	@Test
	public void testNoRenegotiationOnHelloRequest() throws Exception {
		givenAnEstablishedSession(false);

		// send a HELLO_REQUEST message to the client
		DTLSContext context = clientTestContext.getEstablishedServerContext();
		Record record = new Record(ContentType.HANDSHAKE, context.getWriteEpoch(),
				new HelloRequest(), context, false, 0);
		record.setAddress(clientTestContext.getClientAddress(), null);
		serverHelper.server.sendRecord(record);

		// ensure client answer with a NO_RENOGIATION alert
		AlertMessage alert = serverHelper.serverAlertCatcher.waitForEvent(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
		assertThat("server received alert", alert,
				is(new AlertMessage(AlertLevel.WARNING, AlertDescription.NO_RENEGOTIATION)));
	}

	/**
	 * Test invoking of onConnect when sending without session. Test onConnect
	 * is not invoked, when sending with established session.
	 */
	@Test
	public void testSendingInvokesOnConnect() throws Exception {
		// GIVEN a EndpointContextMatcher, blocking
		SimpleMessageCallback callback = new SimpleMessageCallback(1, false);
		// GIVEN a message to send
		RawData outboundMessage = RawData.outbound(new byte[] { 0x01 },
				new AddressEndpointContext(serverHelper.serverEndpoint), callback, false);
		client.start();

		// WHEN sending the initial message
		client.send(outboundMessage);

		// THEN assert that a session is established.
		assertThat(callback.await(TimeUnit.SECONDS.toMillis(MAX_TIME_TO_WAIT_SECS)), is(true));

		// THEN assert that onConnect is invoked once
		assertThat(callback.isConnecting(), is(true));

		// WHEN sending the next message
		callback = new SimpleMessageCallback(1, false);
		// GIVEN a message to send
		outboundMessage = RawData.outbound(new byte[] { 0x01 }, new AddressEndpointContext(serverHelper.serverEndpoint),
				callback, false);
		client.send(outboundMessage);

		assertThat(callback.await(TimeUnit.SECONDS.toMillis(MAX_TIME_TO_WAIT_SECS)), is(true));
		// THEN assert that onConnect is not invoked
		assertThat(callback.isConnecting(), is(false));
	}

	/**
	 * Test exporting key material on client and server side is the same.
	 */
	@Test
	public void testKeyMaterialExport() throws Exception {
		int size = 20;
		byte[] label = "EXPERIMENTAL_TEST".getBytes(StandardCharsets.UTF_8);
		if (client != null) {
			client.destroy();
		}

		// WHEN starting a new handshake (epoch 0) reusing the same client IP
		DtlsConnectorConfig clientConfig = newClientConfigBuilder().setAddress(LOCAL)
				.set(DtlsConfig.DTLS_SUPPORT_KEY_MATERIAL_EXPORT, true).build();
		clientConnectionStore = ConnectorHelper.createDebugConnectionStore(clientConfig);
		client = new DTLSConnector(clientConfig, clientConnectionStore);

		// THEN assert that the handshake succeeds and a session is established
		givenAnEstablishedSession(false);
		DTLSContext serverDtlsContext = serverHelper.getEstablishedServerDtlsContext(client.getAddress());
		assertNotNull("missing server side dtls context", serverDtlsContext);
		byte[] clientKeyMaterial = establishedClientContext.exportKeyMaterial(label, null, size);
		byte[] serverKeyMaterial = serverDtlsContext.exportKeyMaterial(label, null, size);
		assertEquals(size, clientKeyMaterial.length);
		assertEquals(size, serverKeyMaterial.length);
		assertArrayEquals(clientKeyMaterial, serverKeyMaterial);
		serverHelper.server.stop();
		ConnectorHelper.reloadConnections("server", serverHelper.server);
		serverHelper.server.restart();
		serverDtlsContext = serverHelper.server.getDtlsContextByAddress(client.getAddress());
		byte[] server2KeyMaterial = serverDtlsContext.exportKeyMaterial(label, null, size);
		assertEquals(size, server2KeyMaterial.length);
		assertArrayEquals(serverKeyMaterial, server2KeyMaterial);
	}

	private ClientHello createClientHello(CipherSuite... cipherSuites) {
		return createClientHello(ProtocolVersion.VERSION_DTLS_1_2, cipherSuites);
	}

	private ClientHello createClientHello(ProtocolVersion version, CipherSuite... cipherSuites) {
		List<CipherSuite> list = clientConfig.getSupportedCipherSuites();
		if (cipherSuites != null && cipherSuites.length > 0) {
			list = Arrays.asList(cipherSuites);
		}
		ClientHello hello = new ClientHello(version, list, clientConfig.getSupportedSignatureAlgorithms(),
				clientConfig.getIdentityCertificateTypes(), clientConfig.getTrustCertificateTypes(),
				clientConfig.getSupportedGroups());
		hello.addCompressionMethod(CompressionMethod.NULL);
		hello.setMessageSeq(0);
		return hello;
	}

	private void givenAnEstablishedSession(boolean releaseSocket) throws Exception {
		RawData raw = RawData.outbound("Hello World".getBytes(),
				new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		givenAnEstablishedSession(raw, releaseSocket);
	}

	private void givenAnEstablishedSession(RawData msgToSend, boolean releaseSocket) throws Exception {

		clientTestContext = serverHelper.givenAnEstablishedSession(client, msgToSend, false);
		Connection con = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertNotNull(con);
		establishedClientContext = con.getEstablishedDtlsContext();
		assertNotNull(establishedClientContext);
		if (releaseSocket) {
			client.stop();
		}
	}

	private void givenAnEstablishedSessionWithRetry() throws Exception {
		SimpleMessageCallback callback = new SimpleMessageCallback();
		RawData raw = RawData.outbound("Hello World".getBytes(),
				new AddressEndpointContext(serverHelper.serverEndpoint), callback, false);
		try {
			clientTestContext = serverHelper.givenAnEstablishedSession(client, raw, false);
		} catch (AssertionError error) {
			Throwable sendError = callback.getError();
			if (sendError instanceof HandshakeException) {
				// sending failed, retry
				raw = RawData.outbound("Hello World".getBytes(),
						new AddressEndpointContext(serverHelper.serverEndpoint), callback, false);
				client.stop();
				clientTestContext = serverHelper.givenAnEstablishedSession(client, raw, false);
			} else {
				if (sendError != null) {
					sendError.printStackTrace();
				}
				throw error;
			}
		}
		Connection con = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertNotNull(con);
		establishedClientContext = con.getEstablishedDtlsContext();
		assertNotNull(establishedClientContext);
		client.stop();
	}

	private void givenAnIncompleteHandshake() throws Exception {
		// configure UDP connector
		RecordCollectorDataHandler handler = new RecordCollectorDataHandler();
		handler.applyDtlsContext(null);
		UdpConnector rawClient = new UdpConnector(LOCAL, handler);

		try {
			rawClient.start();
			InetSocketAddress clientEndpoint = rawClient.getAddress();

			// send CLIENT_HELLO
			ClientHello clientHello = createClientHello();
			rawClient.sendRecord(serverHelper.serverEndpoint,
					DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, clientHello.toByteArray()));

			// handle HELLO_VERIFY_REQUEST
			List<Record> flight = handler.assertFlight(1, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			Record record = flight.get(0);
			assertThat("Expected HANDSHAKE message from server", record.getType(), is(ContentType.HANDSHAKE));
			HandshakeMessage msg = (HandshakeMessage) record.getFragment();
			assertThat("Expected HELLO_VERIFY_REQUEST from server", msg.getMessageType(),
					is(HandshakeType.HELLO_VERIFY_REQUEST));
			Connection con = serverHelper.serverConnectionStore.get(clientEndpoint);
			assertNull(con);
			byte[] cookie = ((HelloVerifyRequest) msg).getCookie();
			assertNotNull(cookie);

			// send CLIENT_HELLO with cookie
			clientHello.setCookie(cookie);
			rawClient.sendRecord(serverHelper.serverEndpoint,
					DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, clientHello.toByteArray()));

			handler.assertFlight(1, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			// assert that we have an ongoingHandshake for this connection
			con = serverHelper.serverConnectionStore.get(clientEndpoint);
			assertNotNull(con);
			Handshaker ongoingHandshake = con.getOngoingHandshake();
			assertNotNull(ongoingHandshake);
		} finally {
			synchronized (rawClient) {
				rawClient.stop();
				// in order to prevent sporadic BindExceptions during test
				// execution
				// give OS some time before allowing test cases to re-bind to
				// same port
				rawClient.wait(200);
			}
		}
	}
}
