/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 ******************************************************************************/
package org.eclipse.californium.scandium;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.scandium.auth.PreSharedKeyIdentity;
import org.eclipse.californium.scandium.auth.RawPublicKeyIdentity;
import org.eclipse.californium.scandium.category.Medium;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateTypeExtension.CertificateType;
import org.eclipse.californium.scandium.dtls.ClientHello;
import org.eclipse.californium.scandium.dtls.CompressionMethod;
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.ConnectionStore;
import org.eclipse.californium.scandium.dtls.ContentType;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.eclipse.californium.scandium.dtls.HandshakeMessage;
import org.eclipse.californium.scandium.dtls.HandshakeType;
import org.eclipse.californium.scandium.dtls.InMemoryConnectionStore;
import org.eclipse.californium.scandium.dtls.ProtocolVersion;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.SessionId;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
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

	private static final int MAX_TIME_TO_WAIT_SECS = 2;
	private static KeyStore keyStore;
	private static PrivateKey serverPrivateKey;
	private static PrivateKey clientPrivateKey;
	
	private static DtlsConnectorConfig serverConfig;
	private static DTLSConnector server;
	private static InetSocketAddress serverEndpoint;
	private static InMemoryConnectionStore serverSessionStore;
	private static Certificate[] trustedCertificates;
	private static SimpleRawDataChannel serverRawDataChannel;
	private static RawDataProcessor defaultRawDataProcessor;
	
	DtlsConnectorConfig clientConfig;
	DTLSConnector client;
	InetSocketAddress clientEndpoint;
	LatchDecrementingRawDataChannel clientRawDataChannel;
	DTLSSession establishedSession;
	ConnectionStore clientSessionStore;

	@BeforeClass
	public static void loadKeys() throws IOException, GeneralSecurityException {
		// load the key store
		keyStore = DtlsTestTools.loadKeyStore(DtlsTestTools.KEY_STORE_LOCATION, DtlsTestTools.KEY_STORE_PASSWORD);
		serverPrivateKey = (PrivateKey) keyStore.getKey("server", DtlsTestTools.KEY_STORE_PASSWORD.toCharArray());
		clientPrivateKey = (PrivateKey) keyStore.getKey("client", DtlsTestTools.KEY_STORE_PASSWORD.toCharArray());
		// load the trust store
		trustedCertificates = DtlsTestTools.getTrustedCertificates();
		
		serverSessionStore = new InMemoryConnectionStore(2, 5 * 60); // capacity 1, connection timeout 5mins
		serverEndpoint = new InetSocketAddress(InetAddress.getLocalHost(), 10100);
		defaultRawDataProcessor = new RawDataProcessor() {
			
			@Override
			public RawData process(RawData request) {
				// echo request
				return new RawData("ACK".getBytes(), request.getInetSocketAddress());
			}
		};
		
		serverRawDataChannel = new SimpleRawDataChannel(defaultRawDataProcessor);
		
		InMemoryPskStore pskStore = new InMemoryPskStore();
		pskStore.setKey("Client_identity", "secretPSK".getBytes());
		serverConfig = new DtlsConnectorConfig.Builder(serverEndpoint)
			.setSupportedCipherSuites(
				new CipherSuite[]{
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
						CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
						CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256})
			.setIdentity(serverPrivateKey, keyStore.getCertificateChain("server"), true)
			.setTrustStore(trustedCertificates)
			.setPskStore(pskStore)
			.setClientAuthenticationRequired(true)
			.build();

		server = new DTLSConnector(serverConfig, serverSessionStore);
		server.setRawDataReceiver(serverRawDataChannel);
		server.start();
		Assert.assertTrue(server.isRunning());
	}

	@AfterClass
	public static void tearDown() {
		server.destroy();
	}
	
	@Before
	public void setUp() throws Exception {

		clientSessionStore = new InMemoryConnectionStore(5, 60);
		clientEndpoint = new InetSocketAddress(InetAddress.getLocalHost(), 10000);
		
		clientConfig = new DtlsConnectorConfig.Builder(clientEndpoint)
			.setIdentity(clientPrivateKey, keyStore.getCertificateChain("client"), true)
			.setTrustStore(trustedCertificates)
			.build();

		client = new DTLSConnector(clientConfig, clientSessionStore);
		
		clientRawDataChannel = new LatchDecrementingRawDataChannel();
	}

	@After
	public void cleanUp() {
		if (client != null) {
			client.destroy();
		}
		serverSessionStore.clear();
		serverRawDataChannel.setProcessor(defaultRawDataProcessor);
	}
	
	@Test
	public void testConnectorEstablishesSecureSession() throws Exception {
		givenAnEstablishedSession();
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
			Connection con = serverSessionStore.get(clientEndpoint);
			assertNotNull(con);
			assertNotNull(con.getEstablishedSession());
			assertThat("Server should not have established new session with client yet",
					con.getEstablishedSession().getSessionIdentifier(),
					is(establishedSession.getSessionIdentifier()));
		} finally {
			rawClient.stop();
		}
		
		// now check if we can still use the originally established session to
		// exchange application data
		final CountDownLatch clientLatch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(clientLatch);
		// reactivate original client
		client.start();
		// make sure client still has original session in its cache
		Connection con = clientSessionStore.get(serverEndpoint);
		assertNotNull(con);
		assertTrue(con.hasActiveEstablishedSession());
		assertThat(con.getEstablishedSession().getSessionIdentifier(), is(establishedSession.getSessionIdentifier()));

		client.send(new RawData("Hello World".getBytes(), serverEndpoint));

		con = serverSessionStore.get(clientEndpoint);
		assertNotNull(con);
		assertNotNull(con.getEstablishedSession());
		assertTrue(clientLatch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		assertThat("Server should have reused existing session with client instead of creating a new one",
				con.getEstablishedSession().getSessionIdentifier(),
				is(establishedSession.getSessionIdentifier()));
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
		SessionId originalSessionId = establishedSession.getSessionIdentifier();
		
		// client has successfully established a secure session with server
		// and has been "crashed"
		// now we try to establish a new session with a client connecting from the
		// same IP address and port again
		final CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);
		client = new DTLSConnector(clientConfig);
		client.setRawDataReceiver(clientRawDataChannel);
		client.start();
		
		client.send(new RawData("Hello World".getBytes(), serverEndpoint));

		Connection con = serverSessionStore.get(clientEndpoint);
		assertNotNull(con);
		assertNotNull(con.getEstablishedSession());
		assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		// make sure that the server has created a new session replacing the original one with the client
		assertThat("Server should have replaced original session with client with a newly established one",
				con.getEstablishedSession().getSessionIdentifier(), is(not(originalSessionId)));
	}
	
	@Test
	public void testConnectorResumesExistingSession() throws Exception {
	
		givenAnEstablishedSession();
		
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
		
		// send a CLIENT_HELLO containing the established session's ID
		// indicating that we want to resume the existing session
		ClientHello clientHello = createClientHello(establishedSession);
		
		rawClient.sendRecord(serverEndpoint,
				DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, clientHello.toByteArray()));
		
		try{
			Assert.assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			Assert.assertFalse(receivedRecords.isEmpty());
			Record record = receivedRecords.get(0);
			Assert.assertThat("Expected HANDSHAKE message from server",
					record.getType(), is(ContentType.HANDSHAKE));
			// TODO: check if received message is a SERVER_HELLO with the same sessionId
			// this is currently not possible because the server erroneously encrypts handshake messages
		} finally {
			rawClient.stop();
		}
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
		rawClient.start();
		
		// send a CLIENT_HELLO without cookie
		ClientHello clientHello = createClientHello();
		
		rawClient.sendRecord(serverEndpoint,
				DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, clientHello.toByteArray()));
		
		try{
			Assert.assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			Assert.assertFalse(receivedRecords.isEmpty());
			Record record = receivedRecords.get(0);
			Assert.assertThat("Expected HANDSHAKE message from server",
					record.getType(), is(ContentType.HANDSHAKE));
			HandshakeMessage handshake = (HandshakeMessage) record.getFragment();
			Assert.assertThat("Expected HELLO_VERIFY_REQUEST from server",
					handshake.getMessageType(), is(HandshakeType.HELLO_VERIFY_REQUEST));
			Assert.assertNull("Server should not have created session for CLIENT_HELLO containging no cookie",
					serverSessionStore.get(endpoint));
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
		Assert.assertThat(establishedSession.getPeer(), is(clientEndpoint));
	}

	@Test
	public void testConnectorTerminatesHandshakeIfConnectionStoreIsExhausted() throws Exception {
		serverSessionStore.clear();
		assertTrue(serverSessionStore.getCapacity() == 2);
		assertTrue(serverSessionStore.put(new Connection(new InetSocketAddress("192.168.0.1", 5050))));
		assertTrue(serverSessionStore.put(new Connection(new InetSocketAddress("192.168.0.2", 5050))));

		CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);
		client.setRawDataReceiver(clientRawDataChannel);
		client.start();
		client.send(new RawData("Hello World".getBytes(), serverEndpoint));

		assertFalse(latch.await(500, TimeUnit.MILLISECONDS));
		assertNull("Server should not have established a session with client", serverSessionStore.get(clientEndpoint));
	}

	@Test
	public void testConnectorAbortsHandshakeOnUnknownPskIdentity() throws Exception {

		final CountDownLatch latch = new CountDownLatch(1);

		clientConfig = new DtlsConnectorConfig.Builder(clientEndpoint)
			.setPskStore(new StaticPskStore("unknownIdentity", "secretPSK".getBytes()))
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
			.setIdentity((PrivateKey) keyStore.getKey("client", DtlsTestTools.KEY_STORE_PASSWORD.toCharArray()),
				keyStore.getCertificateChain("client"), false)
			.setTrustStore(trustedCertificates)
			.build();
		client = new DTLSConnector(clientConfig, clientSessionStore);
		givenAnEstablishedSession();
	}
	
	/**
	 * Verifies that the connector includes a <code>RawPublicKeyIdentity</code> representing
	 * the authenticated client in the <code>RawData</code> object passed to the application
	 * layer.
	 */
	@Test
	public void testProcessApplicationMessageAddsRawPublicKeyIdentity() throws Exception {
		
		assertClientIdentity(RawPublicKeyIdentity.class);
	}
	
	/**
	 * Verifies that the connector includes a <code>PreSharedKeyIdentity</code> representing
	 * the authenticated client in the <code>RawData</code> object passed to the application
	 * layer.
	 */
	@Test
	public void testProcessApplicationMessageAddsPreSharedKeyIdentity() throws Exception {
		// verify Pre-shared Key identity
		clientConfig = new DtlsConnectorConfig.Builder(clientEndpoint)
			.setPskStore(new StaticPskStore("Client_identity", "secretPSK".getBytes()))
			.build();
		client = new DTLSConnector(clientConfig, clientSessionStore);
		assertClientIdentity(PreSharedKeyIdentity.class);
	}
	
	/**
	 * Verifies that the connector includes an <code>X500Principal</code> representing
	 * the authenticated client in the <code>RawData</code> object passed to the application
	 * layer.
	 */
	@Test
	public void testProcessApplicationMessageAddsX500Principal() throws Exception {
		// verify X500 principal
		clientConfig = new DtlsConnectorConfig.Builder(clientEndpoint)
			.setIdentity((PrivateKey) keyStore.getKey("client", DtlsTestTools.KEY_STORE_PASSWORD.toCharArray()),
				keyStore.getCertificateChain("client"), false)
			.setTrustStore(trustedCertificates)
			.build();
		client = new DTLSConnector(clientConfig, clientSessionStore);
		assertClientIdentity(X500Principal.class);
	}

	@Ignore
	@Test
	public void testProcessApplicationUsesNullPrincipalForUnauthenticatedPeer() throws Exception {
		
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(serverEndpoint);
		builder.setIdentity((PrivateKey) keyStore.getKey("server", DtlsTestTools.KEY_STORE_PASSWORD.toCharArray()),
				keyStore.getCertificateChain("server"), true);
		builder.setClientAuthenticationRequired(false);
		serverConfig = builder.build();
		server = new DTLSConnector(serverConfig, serverSessionStore);
		
		assertClientIdentity(null);
	}
	
	@SuppressWarnings("rawtypes")
	private void assertClientIdentity(final Class principalType) throws Exception {
		
		serverRawDataChannel.setProcessor(new RawDataProcessor() {
			
			@Override
			public RawData process(RawData request) {
				if (principalType == null) {
					Assert.assertNull(request.getSenderIdentity());
				} else {
					Assert.assertThat(request.getSenderIdentity(), instanceOf(principalType));
				}
				return new RawData("ACK".getBytes(), request.getInetSocketAddress());
			}
		});
		
		CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);
		client.setRawDataReceiver(clientRawDataChannel);
		client.start();
		client.send(new RawData("Hello World".getBytes(), serverEndpoint));

		Assert.assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		Connection con = serverSessionStore.get(clientEndpoint);
		assertNotNull(con);
		assertNotNull(con.getEstablishedSession());
	}
	
	private ClientHello createClientHello() {
		return createClientHello(null);
	}
	
	private ClientHello createClientHello(DTLSSession sessionToResume) {
		ClientHello hello = null;
		if (sessionToResume == null) {
			hello = new ClientHello(new ProtocolVersion(), new SecureRandom(), Collections.<CertificateType> emptyList(), Collections.<CertificateType> emptyList(),clientEndpoint);
		} else {
			hello = new ClientHello(new ProtocolVersion(), new SecureRandom(),sessionToResume);
		}
		hello.addCipherSuite(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8);
		hello.addCipherSuite(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
		hello.addCompressionMethod(CompressionMethod.NULL);
		hello.setMessageSeq(0);
		return hello;
	}

	private void givenAnEstablishedSession() throws Exception {
		RawData msgToSend = new RawData("Hello World".getBytes(), serverEndpoint);

		CountDownLatch latch = new CountDownLatch(1);
		clientRawDataChannel.setLatch(latch);
		client.setRawDataReceiver(clientRawDataChannel);
		client.start();
		client.send(msgToSend);

		assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		Connection con = serverSessionStore.get(clientEndpoint);
		assertNotNull(con);
		establishedSession = con.getEstablishedSession();
		assertNotNull(establishedSession);
		client.releaseSocket();
	}
	
	private class LatchDecrementingRawDataChannel implements RawDataChannel {
		private CountDownLatch latch;
		
		public synchronized void setLatch(CountDownLatch latchToDecrement) {
			this.latch = latchToDecrement;
		}
		
		@Override
		public synchronized void receiveData(RawData raw) {
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
			RawData response = this.processor.process(raw); 
			if (response != null) {
				server.send(response);
			}
		}
	}
	
	private interface RawDataProcessor {
		RawData process(RawData request);
	}
	
	private interface DataHandler {
		void handleData(byte[] data);
	}
	
	private class UdpConnector {
		
		InetSocketAddress address;
		DatagramSocket socket;
		boolean running;
		DataHandler handler;
		Thread receiver;
		
		public UdpConnector(final InetSocketAddress bindToAddress, final DataHandler dataHandler, final DtlsConnectorConfig config) {
			this.address = bindToAddress;
			this.handler = dataHandler;
			Runnable rec = new Runnable() {
				
				@Override
				public void run() {
					byte[] buf = new byte[config.getMaxPayloadSize()];
					DatagramPacket packet = new DatagramPacket(buf, buf.length);
					while (running) {
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
			socket = new DatagramSocket(address);
			running = true;
			receiver.start();
		}

		public void stop() {
			running = false;
			socket.close();
		}

		public void sendRecord(InetSocketAddress peerAddress, byte[] record) throws IOException {
			DatagramPacket datagram = new DatagramPacket(record, record.length, peerAddress.getAddress(), peerAddress.getPort());

			if (!socket.isClosed()) {
				socket.send(datagram);
			}
		}
	}
}
