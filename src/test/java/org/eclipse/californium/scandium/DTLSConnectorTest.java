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
 ******************************************************************************/
package org.eclipse.californium.scandium;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.ClientHello;
import org.eclipse.californium.scandium.dtls.CompressionMethod;
import org.eclipse.californium.scandium.dtls.ContentType;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.eclipse.californium.scandium.dtls.HandshakeMessage;
import org.eclipse.californium.scandium.dtls.HandshakeType;
import org.eclipse.californium.scandium.dtls.InMemorySessionStore;
import org.eclipse.californium.scandium.dtls.ProtocolVersion;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.SessionId;
import org.eclipse.californium.scandium.dtls.SessionStore;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class DTLSConnectorTest {

	private static final int MAX_TIME_TO_WAIT_SECS = 2;
	
	DtlsConnectorConfig serverConfig;
	DTLSConnector server;
	DtlsConnectorConfig clientConfig;
	DTLSConnector client;
	InetSocketAddress serverEndpoint;
	InetSocketAddress clientEndpoint;
	LatchDecrementingRawDataChannel rawDataChannel;
	DTLSSession establishedSession;
	SessionStore serverSessionStore;
	SessionStore clientSessionStore;

	@Before
	public void setUp() throws Exception {

		serverSessionStore = new InMemorySessionStore();
		clientSessionStore = new InMemorySessionStore();
		
		clientEndpoint = new InetSocketAddress(InetAddress.getLocalHost(), 10000);
		serverEndpoint = new InetSocketAddress(InetAddress.getLocalHost(), 10100);
		// load the key store
		KeyStore keyStore = DtlsTestTools.loadKeyStore(DtlsTestTools.KEY_STORE_LOCATION, DtlsTestTools.KEY_STORE_PASSWORD);

		// load the trust store
		KeyStore trustStore = DtlsTestTools.loadKeyStore(DtlsTestTools.TRUST_STORE_LOCATION, DtlsTestTools.TRUST_STORE_PASSWORD);
		
		// You can load multiple certificates if needed
		Certificate[] trustedCertificates = new Certificate[1];
		trustedCertificates[0] = trustStore.getCertificate("root");
		
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(clientEndpoint);
		builder.setSupportedCipherSuites(new CipherSuite[]{CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
		builder.setIdentity((PrivateKey) keyStore.getKey("client", DtlsTestTools.KEY_STORE_PASSWORD.toCharArray()),
				keyStore.getCertificateChain("client"), false);
		builder.setTrustStore(trustedCertificates);
		builder.setPskStore(new StaticPskStore("Client_identity", "secretPSK".getBytes()));
		clientConfig = builder.build();
		
		builder = new DtlsConnectorConfig.Builder(serverEndpoint);
		builder.setSupportedCipherSuites(new CipherSuite[]{CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
				CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
		builder.setIdentity((PrivateKey) keyStore.getKey("server", DtlsTestTools.KEY_STORE_PASSWORD.toCharArray()),
				keyStore.getCertificateChain("server"), false);
		builder.setTrustStore(trustedCertificates);
		builder.setPskStore(new StaticPskStore("Client_identity", "secretPSK".getBytes()));
		serverConfig = builder.build();

		server = new DTLSConnector(serverConfig, serverSessionStore);
		client = new DTLSConnector(clientConfig, clientSessionStore);
		
		rawDataChannel = new LatchDecrementingRawDataChannel();
	}
	
	@After
	public void destroyConnectors() {
		if (client != null) {
			client.destroy();
		}
		if (server != null) {
			server.destroy();
		}
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
				receivedRecords.addAll(Record.fromByteArray(data));
				latch.countDown();
			}
		};
		UdpConnector rawClient = new UdpConnector(clientEndpoint, handler, clientConfig);
		rawClient.start();
		
		rawClient.sendRecord(serverEndpoint,
				DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, createClientHello().toByteArray()));
		
		try {
			Assert.assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			Record record = receivedRecords.get(0);
			Assert.assertThat("Expected HANDSHAKE message from server",
					record.getType(), is(ContentType.HANDSHAKE));
			HandshakeMessage msg = (HandshakeMessage) record.getFragment();
			Assert.assertThat("Expected HELLO_VERIFY_REQUEST from server",
					msg.getMessageType(), is(HandshakeType.HELLO_VERIFY_REQUEST));
			Assert.assertThat("Server should not have established new session with client yet",
					serverSessionStore.get(clientEndpoint).getSessionIdentifier(),
					is(establishedSession.getSessionIdentifier()));
		} finally {
			rawClient.stop();
		}
		
		// now check if we can still use the originally established session to
		// exchange application data
		final CountDownLatch clientLatch = new CountDownLatch(1);
		rawDataChannel.setLatch(clientLatch);
		// reactivate original client
		client.start();
		// make sure client still has original session in its cache
		DTLSSession clientSession = clientSessionStore.get(serverEndpoint);
		Assert.assertTrue(clientSession.isActive());
		Assert.assertThat(clientSession.getSessionIdentifier(), is(establishedSession.getSessionIdentifier()));

		client.send(new RawData("Hello World".getBytes(), serverEndpoint));

		Assert.assertTrue(clientLatch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		Assert.assertThat("Server should have reused existing session with client instead of creating a new one",
				serverSessionStore.get(clientEndpoint).getSessionIdentifier(),
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
		rawDataChannel.setLatch(latch);
		client = new DTLSConnector(clientConfig);
		client.setRawDataReceiver(rawDataChannel);
		client.start();
		
		client.send(new RawData("Hello World".getBytes(), serverEndpoint));

		Assert.assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		// make sure that the server has created a new session replacing the original one with the client
		Assert.assertThat("Server should have replaced original session with client with a newly established one",
				serverSessionStore.get(clientEndpoint).getSessionIdentifier(), is(not(originalSessionId)));
	}
	
	@Test
	public void testConnectorResumesExistingSession() throws Exception {
	
		givenAnEstablishedSession();
		
		final CountDownLatch latch = new CountDownLatch(1);
		final List<Record> receivedRecords = new ArrayList<>();
		
		DataHandler handler = new DataHandler() {
			
			@Override
			public void handleData(byte[] data) {
				receivedRecords.addAll(Record.fromByteArray(data)); 
				latch.countDown();
			}
		};
		UdpConnector rawClient = new UdpConnector(clientEndpoint, handler, clientConfig);
		rawClient.start();
		
		// send a CLIENT_HELLO containing the established session's ID
		// indicating that we want to resume the existing session
		ClientHello clientHello = createClientHello();
		clientHello.setSessionId(establishedSession.getSessionIdentifier());
		
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

		server.start();
		
		final CountDownLatch latch = new CountDownLatch(1);
		final List<Record> receivedRecords = new ArrayList<>();
		
		DataHandler handler = new DataHandler() {
			
			@Override
			public void handleData(byte[] data) {
				receivedRecords.addAll(Record.fromByteArray(data)); 
				latch.countDown();
			}
		};
		UdpConnector rawClient = new UdpConnector(clientEndpoint, handler, clientConfig);
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
					serverSessionStore.get(clientEndpoint));
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
	
	private ClientHello createClientHello() {
		ClientHello hello = new ClientHello(new ProtocolVersion(), new SecureRandom(), false);
		hello.addCipherSuite(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8);
		hello.addCipherSuite(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
		hello.addCompressionMethod(CompressionMethod.NULL);
		hello.setMessageSeq(0);
		return hello;
	}

	private void givenAnEstablishedSession() throws Exception {
		RawData msgToSend = new RawData("Hello World".getBytes(), serverEndpoint);

		server.setRawDataReceiver(new RawDataChannel() {

			@Override
			public void receiveData(RawData raw) {
				server.send(new RawData("ACK".getBytes(), raw.getAddress(), raw.getPort()));
			}
		});
		server.start();
		Assert.assertTrue(server.isRunning());

		CountDownLatch latch = new CountDownLatch(1);
		rawDataChannel.setLatch(latch);
		client.setRawDataReceiver(rawDataChannel);
		client.start();
		client.send(msgToSend);

		Assert.assertTrue(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		establishedSession = serverSessionStore.get(clientEndpoint);
		Assert.assertNotNull(establishedSession);
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
			receiver.interrupt();
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
