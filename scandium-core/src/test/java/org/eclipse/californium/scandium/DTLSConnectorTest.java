/*******************************************************************************
 * Copyright (c) 2015, 2016 Bosch Software Innovations GmbH and others.
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
 ******************************************************************************/
package org.eclipse.californium.scandium;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.californium.elements.CorrelationContext;
import org.eclipse.californium.elements.DtlsCorrelationContext;
import org.eclipse.californium.elements.MessageCallback;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.scandium.auth.PreSharedKeyIdentity;
import org.eclipse.californium.scandium.auth.RawPublicKeyIdentity;
import org.eclipse.californium.scandium.auth.X509CertPath;
import org.eclipse.californium.scandium.category.Medium;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.CertificateTypeExtension.CertificateType;
import org.eclipse.californium.scandium.dtls.ClientHello;
import org.eclipse.californium.scandium.dtls.ClientKeyExchange;
import org.eclipse.californium.scandium.dtls.CompressionMethod;
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.ContentType;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.eclipse.californium.scandium.dtls.HandshakeMessage;
import org.eclipse.californium.scandium.dtls.HandshakeType;
import org.eclipse.californium.scandium.dtls.Handshaker;
import org.eclipse.californium.scandium.dtls.HelloVerifyRequest;
import org.eclipse.californium.scandium.dtls.InMemoryConnectionStore;
import org.eclipse.californium.scandium.dtls.InMemorySessionCache;
import org.eclipse.californium.scandium.dtls.PSKClientKeyExchange;
import org.eclipse.californium.scandium.dtls.ProtocolVersion;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.SessionId;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.InMemoryPskStore;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Medium.class)
public class DTLSConnectorTest {

	private static final int CLIENT_CONNECTION_STORE_CAPACITY = 5;
	private static final int SERVER_CONNECTION_STORE_CAPACITY = 2;
	private static final int DTLS_UDP_IP_HEADER_LENGTH = 53;
	private static final int IPV6_MIN_MTU = 1280;
	private static final String CLIENT_IDENTITY_SECRET = "secretPSK";
	private static final String CLIENT_IDENTITY = "Client_identity";
	private static final int MAX_TIME_TO_WAIT_SECS = 2;
	
	private static DtlsConnectorConfig serverConfig;
	private static DTLSConnector server;
	private static InetSocketAddress serverEndpoint;
	private static InMemoryConnectionStore serverConnectionStore;
	private static InMemorySessionCache serverSessionCache;
	private static SimpleRawDataChannel serverRawDataChannel;
	private static RawDataProcessor serverRawDataProcessor;

	DtlsConnectorConfig clientConfig;
	DTLSConnector client;
	InetSocketAddress clientEndpoint;
	LatchDecrementingRawDataChannel clientRawDataChannel;
	DTLSSession establishedServerSession;
	DTLSSession establishedClientSession;
	InMemoryConnectionStore clientConnectionStore;

	@BeforeClass
	public static void loadKeys() throws IOException, GeneralSecurityException {
		// load the key store

		serverRawDataProcessor = new MessageCapturingProcessor();
		serverSessionCache = new InMemorySessionCache();
		serverConnectionStore = new InMemoryConnectionStore(SERVER_CONNECTION_STORE_CAPACITY, 5 * 60, serverSessionCache); // connection timeout 5mins
		serverRawDataChannel = new SimpleRawDataChannel(serverRawDataProcessor);

		InMemoryPskStore pskStore = new InMemoryPskStore();
		pskStore.setKey(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes());
		serverConfig = new DtlsConnectorConfig.Builder(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
			.setSupportedCipherSuites(
				new CipherSuite[]{
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
						CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
						CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256})
			.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getServerCertificateChain(), true)
			.setTrustStore(DtlsTestTools.getTrustedCertificates())
			.setPskStore(pskStore)
			.setClientAuthenticationRequired(true)
			.build();

		server = new DTLSConnector(serverConfig, serverConnectionStore);
		server.setRawDataReceiver(serverRawDataChannel);
		server.start();
		serverEndpoint = server.getAddress();
		assertTrue(server.isRunning());
	}

	@AfterClass
	public static void tearDown() {
		server.destroy();
	}

	@Before
	public void setUp() throws Exception {

		clientConnectionStore = new InMemoryConnectionStore(CLIENT_CONNECTION_STORE_CAPACITY, 60);
		clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
		clientConfig = newStandardConfig(clientEndpoint);

		client = new DTLSConnector(clientConfig, clientConnectionStore);

		clientRawDataChannel = new LatchDecrementingRawDataChannel();
	}

	@After
	public void cleanUp() {
		if (client != null) {
			client.destroy();
		}
		serverConnectionStore.clear();
		serverRawDataChannel.setProcessor(serverRawDataProcessor);
		server.setErrorHandler(null);
	}

	private static DtlsConnectorConfig newStandardConfig(InetSocketAddress bindAddress) throws Exception {
		return newStandardConfigBuilder(bindAddress).build();
	}

	private static DtlsConnectorConfig.Builder newStandardConfigBuilder(InetSocketAddress bindAddress)  throws Exception {
		return new DtlsConnectorConfig.Builder(bindAddress)
				.setIdentity(DtlsTestTools.getClientPrivateKey(), DtlsTestTools.getClientCertificateChain(), true)
				.setTrustStore(DtlsTestTools.getTrustedCertificates());
	}

	@Test
	public void testSendInvokesMessageCallback() throws Exception {

		// GIVEN a message including a MessageCallback
		final AtomicBoolean isCallbackInvoked = new AtomicBoolean();
		RawData outboundMessage = RawData.outbound(
				new byte[]{0x01},
				serverEndpoint,
				new MessageCallback() {

					@Override
					public void onContextEstablished(CorrelationContext context) {
						isCallbackInvoked.set(context != null);
					}
				},
				false);

		// WHEN sending the message
		givenAnEstablishedSession(outboundMessage, true);

		// THEN assert that the callback has been invoked with a correlation context
		assertTrue(isCallbackInvoked.get());
		assertThat(serverRawDataProcessor.getLatestInboundMessage(), is(notNullValue()));
		assertThat(serverRawDataProcessor.getLatestInboundMessage().getCorrelationContext(), is(notNullValue()));
	}

	@Test
	public void testConnectorAddsCorrelationContextToReceivedApplicationMessage() throws Exception {
		// GIVEN a message to be sent to the server
		RawData outboundMessage = RawData.outbound(new byte[]{0x01}, serverEndpoint, null, false);

		// WHEN a session has been established and the message has been sent to the server
		givenAnEstablishedSession(outboundMessage, true);

		// THEN assert that the message delivered to the server side application layer
		// contains a correlation context containing the established session's ID, epoch and cipher 
		DTLSSession session = clientConnectionStore.get(serverEndpoint).getEstablishedSession();
		assertThat(serverRawDataProcessor.getLatestInboundMessage(), is(notNullValue()));
		DtlsCorrelationContext context = (DtlsCorrelationContext) serverRawDataProcessor.getLatestInboundMessage().getCorrelationContext();
		assertThat(context, is(notNullValue()));
		assertThat(context.getSessionId(), is(session.getSessionIdentifier().toString()));
		assertThat(context.getEpoch(), is(String.valueOf(session.getReadEpoch())));
		assertThat(context.getCipher(), is(session.getReadStateCipher()));
	}

	@Test
	public void testConnectorEstablishesSecureSession() throws Exception {
		givenAnEstablishedSession();
	}

	/**
	 * Verifies that a DTLSConnector terminates its connection with a peer when receiving
	 * a CLOSE_NOTIFY alert from the peer (bug #478538).
	 * 
	 * @throws Exception if test cannot be executed
	 */
	@Test
	public void testConnectorTerminatesConnectionOnReceivingCloseNotify() throws Exception {

		// GIVEN a CLOSE_NOTIFY alert
		AlertMessage alert = new AlertMessage(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY, serverEndpoint);

		assertConnectionTerminatedOnAlert(alert);
	}

	/**
	 * Verifies that a DTLSConnector terminates its connection with a peer when receiving
	 * a FATAL alert from the peer.
	 * 
	 * @throws Exception if test cannot be executed
	 */
	@Test
	public void testConnectorTerminatesConnectionOnReceivingFatalAlert() throws Exception {

		// GIVEN a FATAL alert
		AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, serverEndpoint);

		assertConnectionTerminatedOnAlert(alert);
	}

	private void assertConnectionTerminatedOnAlert(final AlertMessage alert) throws Exception {
		final CountDownLatch alertReceived = new CountDownLatch(1);
		server.setErrorHandler(new ErrorHandler() {
			
			@Override
			public void onError(InetSocketAddress peerAddress, AlertLevel level, AlertDescription description) {
				if (alert.getDescription().equals(description) && peerAddress.equals(clientEndpoint)) {
					alertReceived.countDown();
				}
			}
		});

		givenAnEstablishedSession(false);

		// WHEN sending a CLOSE_NOTIFY alert to the server
		client.send(alert, establishedClientSession);

		// THEN assert that the server has removed all connection state with client
		assertTrue(alertReceived.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		assertThat(serverConnectionStore.get(clientEndpoint), is(nullValue()));
	}

	/**
	 * Verifies behavior described in <a href="http://tools.ietf.org/html/rfc6347#section-4.2.8">
	 * section 4.2.8 of RFC 6347 (DTLS 1.2)</a>.
	 *  
	 * @throws Exception if test fails
	 */
	@Test
	public void testConnectorKeepsExistingSessionOnEpochZeroClientHello() throws Exception {

		givenAnEstablishedSession();

		// client has successfully established a secure session with server
		// and has been "crashed"
		// now we try to establish a new session with a client connecting from the
		// same IP address and port again
		
		final CountDownLatch latch = new CountDownLatch(1);
		final List<Record> receivedRecords = new ArrayList<>();

		DataHandler handler = new DataHandler() {
			
			@Override
			public void handleData(byte[] data) {
				receivedRecords.addAll(Record.fromByteArray(data, serverEndpoint));
				latch.countDown();
			}
		};
		UdpConnector rawClient = new UdpConnector(clientEndpoint, handler, clientConfig);
		rawClient.start();

		rawClient.sendRecord(serverEndpoint,
				DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, createClientHello().toByteArray()));

		try {
			assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			Record record = receivedRecords.get(0);
			assertThat("Expected HANDSHAKE message from server",
					record.getType(), is(ContentType.HANDSHAKE));
			HandshakeMessage msg = (HandshakeMessage) record.getFragment();
			assertThat("Expected HELLO_VERIFY_REQUEST from server",
					msg.getMessageType(), is(HandshakeType.HELLO_VERIFY_REQUEST));
			Connection con = serverConnectionStore.get(clientEndpoint);
			assertNotNull(con);
			assertNotNull(con.getEstablishedSession());
			assertThat("Server should not have established new session with client yet",
					con.getEstablishedSession().getSessionIdentifier(),
					is(establishedServerSession.getSessionIdentifier()));
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
		final CountDownLatch clientLatch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(clientLatch);
		// restart original client binding to same IP address and port as before
		client.restart();
		// make sure client still has original session in its cache
		Connection con = clientConnectionStore.get(serverEndpoint);
		assertNotNull(con);
		assertNotNull(con.getEstablishedSession());
		assertThat(con.getEstablishedSession().getSessionIdentifier(), is(establishedServerSession.getSessionIdentifier()));

		client.send(new RawData("Hello World".getBytes(), serverEndpoint));

		con = serverConnectionStore.get(client.getAddress());
		assertNotNull(con);
		assertNotNull(con.getEstablishedSession());
		assertTrue(clientLatch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		assertThat("Server should have reused existing session with client instead of creating a new one",
				con.getEstablishedSession().getSessionIdentifier(),
				is(establishedServerSession.getSessionIdentifier()));
	}

	/**
	 * Verifies behavior described in <a href="http://tools.ietf.org/html/rfc6347#section-4.2.8">
	 * section 4.2.8 of RFC 6347 (DTLS 1.2)</a>.
	 */
	@Test
	public void testAcceptClientHelloAfterIncompleteHandshake() throws Exception {
		// GIVEN a handshake that has been aborted before completion
		givenAnIncompleteHandshake();

		// WHEN starting a new handshake (epoch 0) reusing the same client IP
		clientConfig = newStandardConfig(clientEndpoint);
		client = new DTLSConnector(clientConfig, clientConnectionStore);

		// THEN assert that the handshake succeeds and a session is established
		givenAnEstablishedSession();
	}

	/**
	 * Verifies behavior described in <a href="http://tools.ietf.org/html/rfc6347#section-4.2.8">
	 * section 4.2.8 of RFC 6347 (DTLS 1.2)</a>.
	 */
	@Test
	public void testClientHelloRetransmissionDoNotRestartHandshake() throws Exception {
		// configure UDP connector
		CountDownLatch latch = new CountDownLatch(1);
		final List<Record> receivedRecords = new ArrayList<>();
		LatchDecrementingDataHandler handler = new LatchDecrementingDataHandler(latch) {
			@Override
			public boolean handle(byte[] data) {
				receivedRecords.addAll(Record.fromByteArray(data, serverEndpoint));
				return true;
			}
		};

		UdpConnector rawClient = new UdpConnector(clientEndpoint, handler, clientConfig);
		try {
			rawClient.start();
			clientEndpoint = new InetSocketAddress(rawClient.socket.getLocalAddress(),rawClient.socket.getLocalPort());

			// send CLIENT_HELLO
			ClientHello clientHello = createClientHello();
			rawClient.sendRecord(
					serverEndpoint,
					DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, clientHello.toByteArray()));

			// handle HELLO_VERIFY_REQUEST
			assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			Record record = receivedRecords.get(0);
			assertThat("Expected HANDSHAKE message from server",
					record.getType(), is(ContentType.HANDSHAKE));
			HandshakeMessage msg = (HandshakeMessage) record.getFragment();
			assertThat("Expected HELLO_VERIFY_REQUEST from server",
					msg.getMessageType(), is(HandshakeType.HELLO_VERIFY_REQUEST));
			Connection con = serverConnectionStore.get(clientEndpoint);
			assertNull(con);
			byte[] cookie = ((HelloVerifyRequest) msg).getCookie();
			assertNotNull(cookie);
			receivedRecords.clear();

			// send CLIENT_HELLO with cookie
			latch = new CountDownLatch(1);
			handler.setLatch(latch);
			clientHello.setCookie(cookie);
			clientHello.setFragmentLength(clientHello.getMessageLength());
			rawClient.sendRecord(
					serverEndpoint,
					DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, clientHello.toByteArray()));

			// assert that we have an ongoingHandshake for this connection
			assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			con = serverConnectionStore.get(clientEndpoint);
			assertNotNull(con);
			Handshaker ongoingHandshake = con.getOngoingHandshake();
			assertNotNull(ongoingHandshake);
			record = receivedRecords.get(0);
			assertThat("Expected HANDSHAKE message from server",
					record.getType(), is(ContentType.HANDSHAKE));
			msg = (HandshakeMessage) record.getFragment();
			assertThat("Expected SERVER_HELLO from server",
					msg.getMessageType(), is(HandshakeType.SERVER_HELLO));
			receivedRecords.clear();

			// send CLIENT_KEY_EXCHANGE
			latch = new CountDownLatch(1);
			handler.setLatch(latch);
			ClientKeyExchange keyExchange = new PSKClientKeyExchange(CLIENT_IDENTITY, serverEndpoint);
			rawClient.sendRecord(serverEndpoint,
							DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 1, keyExchange.toByteArray()));

			// re-send CLIENT_HELLO to simulate retransmission
			latch = new CountDownLatch(1);
			handler.setLatch(latch);
			rawClient.sendRecord(
					serverEndpoint,
					DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, clientHello.toByteArray()));

			// send Alert to receive an answer even
			AlertMessage closeNotify = new AlertMessage(AlertLevel.FATAL, AlertDescription.CLOSE_NOTIFY, serverEndpoint);
			rawClient.sendRecord(serverEndpoint, DtlsTestTools.newDTLSRecord(ContentType.ALERT.getCode(), 0, 2, closeNotify.toByteArray()));

			// check that we don't get a response for this CLIENT_HELLO, it must be ignore
			assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			record = receivedRecords.get(0);
			assertThat("Expected ALERT message from server",
					record.getType(), is(ContentType.ALERT));

		} finally {
			rawClient.stop();
		}
	}

	/**
	 * Verifies behavior described in <a href="http://tools.ietf.org/html/rfc6347#section-4.2.8">
	 * section 4.2.8 of RFC 6347 (DTLS 1.2)</a>.
	 *  
	 * @throws Exception if test fails
	 */
	@Test
	public void testConnectorReplacesExistingSessionAfterFullHandshake() throws Exception {

		givenAnEstablishedSession();

		// the ID of the originally established session
		SessionId originalSessionId = establishedServerSession.getSessionIdentifier();

		// client has successfully established a secure session with server
		// and has been "crashed"
		// now we try to establish a new session with a client connecting from the
		// same IP address and port again
		final CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);
		client = new DTLSConnector(newStandardConfig(clientEndpoint));
		client.setRawDataReceiver(clientRawDataChannel);
		client.start();

		client.send(new RawData("Hello World".getBytes(), serverEndpoint));

		assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		Connection con = serverConnectionStore.get(clientEndpoint);
		assertNotNull(con);
		assertNotNull(con.getEstablishedSession());
		// make sure that the server has created a new session replacing the original one with the client
		assertThat("Server should have replaced original session with client with a newly established one",
				con.getEstablishedSession().getSessionIdentifier(), is(not(originalSessionId)));
	}

	@Test
	public void testConnectorResumesSessionFromNewConnection() throws Exception {
		// Do a first handshake
		givenAnEstablishedSession();
		client.stop();
		byte[] sessionId = establishedServerSession.getSessionIdentifier().getId();

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverEndpoint);
		Connection connection = clientConnectionStore.get(serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getId());

		// create a new client with different inetAddress but with the same session store.
		clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 10001);
		clientConfig = DTLSConnectorTest.newStandardConfig(clientEndpoint);
		client = new DTLSConnector(clientConfig, clientConnectionStore);
		clientRawDataChannel = new LatchDecrementingRawDataChannel();
		client.setRawDataReceiver(clientRawDataChannel);
		client.start();

		// Prepare message sending
		final String msg = "Hello Again";
		CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);

		// send message
		client.send(new RawData(msg.getBytes(), serverEndpoint));
		assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getId());
		assertClientIdentity(RawPublicKeyIdentity.class);
	}

	@Test
	public void testStartStopWithNewAddress() throws Exception {
		// Do a first handshake
		givenAnEstablishedSession(false);
		byte[] sessionId = establishedServerSession.getSessionIdentifier().getId();
		InetSocketAddress firstAddress = client.getAddress();

		// Stop the client
		client.stop();
		Connection connection = clientConnectionStore.get(serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getId());

		// Restart it
		client.start();
		assertNotEquals(firstAddress,client.getAddress());

		// Prepare message sending
		final String msg = "Hello Again";
		CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);

		// send message
		client.send(new RawData(msg.getBytes(), serverEndpoint));
		assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getId());
		assertClientIdentity(RawPublicKeyIdentity.class);
	}

	@Test
	public void testStartStopWithSameAddress() throws Exception {
		// Do a first handshake
		givenAnEstablishedSession(false);
		byte[] sessionId = establishedServerSession.getSessionIdentifier().getId();
		InetSocketAddress firstAddress = client.getAddress();

		// Stop the client
		client.stop();
		Connection connection = clientConnectionStore.get(serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getId());

		// Restart it
		client.restart();
		assertEquals(firstAddress,client.getAddress());

		// Prepare message sending
		final String msg = "Hello Again";
		CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);

		// send message
		client.send(new RawData(msg.getBytes(), serverEndpoint));
		assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getId());
		assertClientIdentity(RawPublicKeyIdentity.class);
	}

	@Test
	public void testConnectorResumesSessionFromSharedSessionTicket() throws Exception {
		// Do a first handshake
		givenAnEstablishedSession();
		SessionId establishedSessionId = establishedServerSession.getSessionIdentifier();

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverEndpoint);
		Connection connection = clientConnectionStore.get(serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(establishedSessionId));
		client.start();

		// remove connection from server's connection store and add ticket to session cache
		// to mimic a fail over from another node
		serverConnectionStore.remove(clientEndpoint);
		assertThat(serverSessionCache.get(establishedSessionId), is(nullValue()));
		serverSessionCache.put(establishedSessionId, establishedServerSession.getSessionTicket());

		// Prepare message sending
		final String msg = "Hello Again";
		CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);

		// send message
		client.send(new RawData(msg.getBytes(), serverEndpoint));
		assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(establishedSessionId));
		assertClientIdentity(RawPublicKeyIdentity.class);
	}

	@Test
	public void testConnectorResumesSessionFromExistingConnection() throws Exception {
		// Do a first handshake
		givenAnEstablishedSession();
		byte[] sessionId = establishedServerSession.getSessionIdentifier().getId();

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverEndpoint);
		Connection connection = clientConnectionStore.get(serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getId());
		client.start();

		// Prepare message sending
		final String msg = "Hello Again";
		CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);

		// send message
		client.send(new RawData(msg.getBytes(), serverEndpoint));
		assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getId());
		assertClientIdentity(RawPublicKeyIdentity.class);
	}

	@Test
	public void testConnectorPerformsFullHandshakeWhenResumingNonExistingSession() throws Exception {
		// Do a first handshake
		givenAnEstablishedSession();
		byte[] sessionId = establishedServerSession.getSessionIdentifier().getId();

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverEndpoint);
		Connection connection = clientConnectionStore.get(serverEndpoint);
		assertArrayEquals(sessionId, connection.getEstablishedSession().getSessionIdentifier().getId());
		client.start();

		// Prepare message sending
		final String msg = "Hello Again";
		CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);

		// remove session from server
		serverConnectionStore.remove(clientEndpoint);

		// send message
		client.send(new RawData(msg.getBytes(), serverEndpoint));
		assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check session id was not equals
		connection = clientConnectionStore.get(serverEndpoint);
		Assert.assertThat(sessionId, not(equalTo(connection.getEstablishedSession().getSessionIdentifier().getId())));
		assertClientIdentity(RawPublicKeyIdentity.class);
	}

	@Test
	public void testConnectorSendsHelloVerifyRequestWithoutCreatingSession() throws Exception {

		final CountDownLatch latch = new CountDownLatch(1);
		final List<Record> receivedRecords = new ArrayList<>();
		InetSocketAddress endpoint = new InetSocketAddress(12000);

		DataHandler handler = new DataHandler() {

			@Override
			public void handleData(byte[] data) {
				receivedRecords.addAll(Record.fromByteArray(data, serverEndpoint)); 
				latch.countDown();
			}
		};

		UdpConnector rawClient = new UdpConnector(endpoint, handler, clientConfig);

		try{
			rawClient.start();
	
			// send a CLIENT_HELLO without cookie
			ClientHello clientHello = createClientHello();
	
			rawClient.sendRecord(serverEndpoint,
					DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, clientHello.toByteArray()));

			Assert.assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			Assert.assertFalse(receivedRecords.isEmpty());
			Record record = receivedRecords.get(0);
			Assert.assertThat("Expected HANDSHAKE message from server",
					record.getType(), is(ContentType.HANDSHAKE));
			HandshakeMessage handshake = (HandshakeMessage) record.getFragment();
			Assert.assertThat("Expected HELLO_VERIFY_REQUEST from server",
					handshake.getMessageType(), is(HandshakeType.HELLO_VERIFY_REQUEST));
			Assert.assertNull("Server should not have created session for CLIENT_HELLO containging no cookie",
					serverConnectionStore.get(endpoint));
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
		givenAnEstablishedSession();
		Assert.assertThat(establishedServerSession.getPeer(), is(clientEndpoint));
	}

	@Test
	public void testConnectorTerminatesHandshakeIfConnectionStoreIsExhausted() throws Exception {
		serverConnectionStore.clear();
		assertTrue(serverConnectionStore.remainingCapacity() == SERVER_CONNECTION_STORE_CAPACITY);
		assertTrue(serverConnectionStore.put(new Connection(new InetSocketAddress("192.168.0.1", 5050))));
		assertTrue(serverConnectionStore.put(new Connection(new InetSocketAddress("192.168.0.2", 5050))));

		CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);
		client.setRawDataReceiver(clientRawDataChannel);
		client.start();
		clientEndpoint = client.getAddress();
		client.send(new RawData("Hello World".getBytes(), serverEndpoint));

		assertFalse(latch.await(500, TimeUnit.MILLISECONDS));
		assertNull("Server should not have established a session with client", serverConnectionStore.get(clientEndpoint));
	}

	@Test
	public void testConnectorAbortsHandshakeOnUnknownPskIdentity() throws Exception {

		final CountDownLatch latch = new CountDownLatch(1);
		clientConfig = new DtlsConnectorConfig.Builder(clientEndpoint)
			.setPskStore(new StaticPskStore("unknownIdentity", CLIENT_IDENTITY_SECRET.getBytes()))
			.build();
		client = new DTLSConnector(clientConfig);
		client.setErrorHandler(new ErrorHandler() {

			@Override
			public void onError(InetSocketAddress peerAddress, AlertLevel level, AlertDescription description) {
				latch.countDown();
				assertThat(level, is(AlertLevel.FATAL));
				assertThat(peerAddress, is(serverEndpoint));
			}
		});
		client.start();
		client.send(new RawData("Hello".getBytes(), serverEndpoint));

		assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
	}

	/**
	 * Verifies that the connector can successfully establish a session using a CBC based cipher suite.
	 */
	@Test
	public void testConnectorEstablishesSecureSessionUsingCbcBlockCipher() throws Exception {
		clientConfig =  new DtlsConnectorConfig.Builder(clientEndpoint)
			.setSupportedCipherSuites(new CipherSuite[]{CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256})
			.setIdentity(DtlsTestTools.getClientPrivateKey(), DtlsTestTools.getClientCertificateChain(), false)
			.setTrustStore(DtlsTestTools.getTrustedCertificates())
			.build();
		client = new DTLSConnector(clientConfig, clientConnectionStore);
		givenAnEstablishedSession();
	}

	/**
	 * Verifies that the connector includes a <code>RawPublicKeyIdentity</code> representing
	 * the authenticated client in the <code>RawData</code> object passed to the application
	 * layer.
	 */
	@Test
	public void testProcessApplicationMessageAddsRawPublicKeyIdentity() throws Exception {

		givenAnEstablishedSession();

		assertClientIdentity(RawPublicKeyIdentity.class);
	}

	/**
	 * Verifies that the connector includes a <code>PreSharedKeyIdentity</code> representing
	 * the authenticated client in the <code>RawData</code> object passed to the application
	 * layer.
	 */
	@Test
	public void testProcessApplicationMessageAddsPreSharedKeyIdentity() throws Exception {

		// given an established session with a client using PSK authentication
		clientConfig = new DtlsConnectorConfig.Builder(clientEndpoint)
			.setPskStore(new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()))
			.build();
		client = new DTLSConnector(clientConfig, clientConnectionStore);
		givenAnEstablishedSession();

		assertClientIdentity(PreSharedKeyIdentity.class);
	}

	/**
	 * Verifies that the connector includes an <code>X500Principal</code> representing
	 * the authenticated client in the <code>RawData</code> object passed to the application
	 * layer.
	 */
	@Test
	public void testProcessApplicationMessageAddsX509CertPath() throws Exception {

		// given an established session with a client using X.509 based authentication
		clientConfig = new DtlsConnectorConfig.Builder(clientEndpoint)
			.setIdentity(DtlsTestTools.getClientPrivateKey(), DtlsTestTools.getClientCertificateChain(), false)
			.setTrustStore(DtlsTestTools.getTrustedCertificates())
			.build();
		client = new DTLSConnector(clientConfig, clientConnectionStore);
		givenAnEstablishedSession();

		assertClientIdentity(X509CertPath.class);
	}

	/**
	 * This test currently cannot be executed like this because the server side DTLSConnector
	 * is initialized statically and thus cannot be re-configured "on-the-fly".
	 * 
	 * @throws Exception if the test cannot be executed
	 */
	@Ignore
	@Test
	public void testProcessApplicationUsesNullPrincipalForUnauthenticatedPeer() throws Exception {

		// given an established session with a server that doesn't require
		// clients to authenticate
		serverConfig = new DtlsConnectorConfig.Builder(serverEndpoint)
				.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getServerCertificateChain(), true)
				.setClientAuthenticationRequired(false)
				.build();
		server = new DTLSConnector(serverConfig, serverConnectionStore);
		givenAnEstablishedSession();

		assertClientIdentity(null);
	}

	@SuppressWarnings("rawtypes")
	private void assertClientIdentity(final Class principalType) {

		// assert that client identity is of given type
		if (principalType == null) {
			assertThat(serverRawDataProcessor.getClientIdentity(), is(nullValue()));
		} else {
			assertThat(serverRawDataProcessor.getClientIdentity(), instanceOf(principalType));
		}
	}

	@Test
	public void testGetMaximumTransmissionUnitReturnsDefaultValue() {
		// given a connector that has not been started yet
		DTLSConnector connector = client;

		// when retrieving the maximum transmission unit from the client
		int mtu = connector.getMaximumTransmissionUnit();

		// then the value is the IPv6 min. MTU
		assertThat(mtu, is(IPV6_MIN_MTU));
	}

	@Test
	public void testGetMaximumFragmentLengthReturnsDefaultValueForUnknownPeer() {
		// given an empty client side connection store
		clientConnectionStore.clear();

		// when querying the max fragment length for an unknown peer
		InetSocketAddress unknownPeer = serverEndpoint;
		int maxFragmentLength = client.getMaximumFragmentLength(unknownPeer);

		// then the value is the minimum IPv6 MTU - DTLS/UDP/IP header overhead
		assertThat(maxFragmentLength, is(IPV6_MIN_MTU - DTLS_UDP_IP_HEADER_LENGTH));
	}

	@Test
	public void testDestroyClearsConnectionStore() throws Exception {
		// given a non-empty connection store
		givenAnEstablishedSession();
		assertThat(clientConnectionStore.get(serverEndpoint), is(notNullValue()));

		// when the client connector is destroyed
		client.destroy();

		// assert that the client's connection store is empty
		assertThat(clientConnectionStore.remainingCapacity(), is(CLIENT_CONNECTION_STORE_CAPACITY));
		assertThat(clientConnectionStore.get(serverEndpoint), is(nullValue()));
	}

	private ClientHello createClientHello() {
		return createClientHello(null);
	}

	private ClientHello createClientHello(DTLSSession sessionToResume) {
		ClientHello hello = null;
		if (sessionToResume == null) {
			hello = new ClientHello(new ProtocolVersion(), new SecureRandom(), Collections.<CertificateType> emptyList(), Collections.<CertificateType> emptyList(),clientEndpoint);
		} else {
			hello = new ClientHello(new ProtocolVersion(), new SecureRandom(),sessionToResume, null, null);
		}
		hello.addCipherSuite(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8);
		hello.addCipherSuite(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
		hello.addCompressionMethod(CompressionMethod.NULL);
		hello.setMessageSeq(0);
		return hello;
	}

	private void givenAnEstablishedSession() throws Exception {
		givenAnEstablishedSession(true);
	}
	private void givenAnEstablishedSession(boolean releaseSocket) throws Exception {
		givenAnEstablishedSession(new RawData("Hello World".getBytes(), serverEndpoint), releaseSocket);
	}

	private void givenAnEstablishedSession(RawData msgToSend, boolean releaseSocket) throws Exception {

		CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);
		client.setRawDataReceiver(clientRawDataChannel);
		client.start();
		clientEndpoint = client.getAddress();
		client.send(msgToSend);

		assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		Connection con = serverConnectionStore.get(clientEndpoint);
		assertNotNull(con);
		establishedServerSession = con.getEstablishedSession();
		assertNotNull(establishedServerSession);
		con = clientConnectionStore.get(serverEndpoint);
		assertNotNull(con);
		establishedClientSession = con.getEstablishedSession();
		assertNotNull(establishedClientSession);
		if (releaseSocket) {
			synchronized (client) {
				client.releaseSocket();
				// in order to prevent sporadic BindExceptions during test execution
				// give OS some time before allowing test cases to re-bind to same port
				client.wait(200);
			}
		}
	}

	private abstract class LatchDecrementingDataHandler implements DataHandler {
		private CountDownLatch latch;

		public LatchDecrementingDataHandler(CountDownLatch latch){
			this.setLatch(latch);
		}

		@Override
		public void handleData(byte[] data) {
			if (handle(data))
				latch.countDown();
		}

		public abstract boolean handle(byte[] data);

		public void setLatch(CountDownLatch latch) {
			this.latch = latch;
		}
	};

	private void givenAnIncompleteHandshake() throws Exception {
		// configure UDP connector
		CountDownLatch latch = new CountDownLatch(1);
		final List<Record> receivedRecords = new ArrayList<>();
		LatchDecrementingDataHandler handler = new LatchDecrementingDataHandler(latch) {
			@Override
			public boolean handle(byte[] data) {
				receivedRecords.addAll(Record.fromByteArray(data, serverEndpoint));
				return true;
			}
		};

		UdpConnector rawClient = new UdpConnector(clientEndpoint, handler, clientConfig);

		try {
			rawClient.start();
			clientEndpoint = new InetSocketAddress(rawClient.socket.getLocalAddress(),rawClient.socket.getLocalPort());

			// send CLIENT_HELLO
			ClientHello clientHello = createClientHello();
			rawClient.sendRecord(
					serverEndpoint,
					DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, clientHello.toByteArray()));

			// handle HELLO_VERIFY_REQUEST
			assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			Record record = receivedRecords.get(0);
			assertThat("Expected HANDSHAKE message from server",
					record.getType(), is(ContentType.HANDSHAKE));
			HandshakeMessage msg = (HandshakeMessage) record.getFragment();
			assertThat("Expected HELLO_VERIFY_REQUEST from server",
					msg.getMessageType(), is(HandshakeType.HELLO_VERIFY_REQUEST));
			Connection con = serverConnectionStore.get(clientEndpoint);
			assertNull(con);
			byte[] cookie = ((HelloVerifyRequest) msg).getCookie();
			assertNotNull(cookie);
			receivedRecords.clear();

			// send CLIENT_HELLO with cookie
			latch = new CountDownLatch(1);
			handler.setLatch(latch);
			clientHello.setCookie(cookie);
			clientHello.setFragmentLength(clientHello.getMessageLength());
			rawClient.sendRecord(
					serverEndpoint,
					DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, clientHello.toByteArray()));

			// assert that we have an ongoingHandshake for this connection
			assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			con = serverConnectionStore.get(clientEndpoint);
			assertNotNull(con);
			Handshaker ongoingHandshake = con.getOngoingHandshake();
			assertNotNull(ongoingHandshake);
		} finally {
			synchronized (rawClient) {
				rawClient.stop();
				// in order to prevent sporadic BindExceptions during test execution
				// give OS some time before allowing test cases to re-bind to same port
				rawClient.wait(200);
			}
		}
	}

	private class LatchDecrementingRawDataChannel extends SimpleRawDataChannel {
		private CountDownLatch latch;

		public LatchDecrementingRawDataChannel() {
			super(null);
		}

		public synchronized void setLatch(CountDownLatch latchToDecrement) {
			this.latch = latchToDecrement;
		}

		@Override
		public synchronized void receiveData(RawData raw) {
			super.receiveData(raw);
			if (latch != null) {
				latch.countDown();
			}
		}
	}

	private static class SimpleRawDataChannel implements RawDataChannel {

		private RawDataProcessor processor;

		public SimpleRawDataChannel(RawDataProcessor processor) {
			setProcessor(processor);
		}

		public void setProcessor(RawDataProcessor processor) {
			this.processor = processor;
		}

		@Override
		public void receiveData(RawData raw) {
			if (processor != null) {
				RawData response = this.processor.process(raw);
				if (response != null) {
					server.send(response);
				}
			}
		}
	}

	private interface RawDataProcessor {

		RawData process(RawData request);

		RawData getLatestInboundMessage();

		Principal getClientIdentity();
	}

	private static class MessageCapturingProcessor implements RawDataProcessor {
		private AtomicReference<RawData> inboundMessage = new AtomicReference<RawData>();

		@Override
		public RawData process(RawData request) {
			inboundMessage.set(request);
			return new RawData("ACK".getBytes(), request.getInetSocketAddress());
		}

		@Override
		public Principal getClientIdentity() {
			if (inboundMessage != null) {
				return inboundMessage.get().getSenderIdentity();
			} else {
				return null;
			}
		}

		@Override
		public RawData getLatestInboundMessage() {
			return inboundMessage.get();
		}
	}

	private interface DataHandler {
		void handleData(byte[] data);
	}

	private class UdpConnector {

		InetSocketAddress address;
		DatagramSocket socket;
		AtomicBoolean running = new AtomicBoolean();
		DataHandler handler;
		Thread receiver;

		public UdpConnector(final InetSocketAddress bindToAddress, final DataHandler dataHandler, final DtlsConnectorConfig config) {
			this.address = bindToAddress;
			this.handler = dataHandler;
			Runnable rec = new Runnable() {

				@Override
				public void run() {
					byte[] buf = new byte[8192];
					DatagramPacket packet = new DatagramPacket(buf, buf.length);
					while (running.get()) {
						try {
							socket.receive(packet);
							if (packet.getLength() > 0) {
								// handle data
								handler.handleData(Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getLength()));
								packet.setLength(buf.length);
							}
						} catch (IOException e) {
							// do nothing
						}
					}
				}
			};
			receiver = new Thread(rec);
		}

		public void start() throws IOException {
			if (running.compareAndSet(false, true)) {
				socket = new DatagramSocket(address);
				receiver.start();
			}
		}

		public void stop() {
			if (running.compareAndSet(true, false)) {
				socket.close();
			}
		}

		public void sendRecord(InetSocketAddress peerAddress, byte[] record) throws IOException {
			DatagramPacket datagram = new DatagramPacket(record, record.length, peerAddress.getAddress(), peerAddress.getPort());

			if (!socket.isClosed()) {
				socket.send(datagram);
			}
		}
	}
}
