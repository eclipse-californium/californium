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
 ******************************************************************************/
package org.eclipse.californium.scandium;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
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
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.scandium.dtls.ClientHello;
import org.eclipse.californium.scandium.dtls.CompressionMethod;
import org.eclipse.californium.scandium.dtls.ContentType;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.eclipse.californium.scandium.dtls.HandshakeMessage;
import org.eclipse.californium.scandium.dtls.HandshakeType;
import org.eclipse.californium.scandium.dtls.ProtocolVersion;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

public class DTLSConnectorTest {

	private static final String TRUST_STORE_PASSWORD = "rootPass";
	private final static String KEY_STORE_PASSWORD = "endPass";
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";
	private static final int MAX_TIME_TO_WAIT_SECS = 2;
	
	DTLSConnector server;
	DTLSConnector client;
	InetSocketAddress serverEndpoint;
	InetSocketAddress clientEndpoint;
	PrivateKey serverPrivateKey;
	Certificate[] serverKeyChain;
	PrivateKey clientPrivateKey;
	Certificate[] clientKeyChain;
	Certificate[] trustedCertificates;

	@Before
	public void setUp() throws Exception {

		clientEndpoint = new InetSocketAddress(InetAddress.getLocalHost(), 10000);
		serverEndpoint = new InetSocketAddress(InetAddress.getLocalHost(), 10100);
		// load the key store
		KeyStore keyStore = KeyStore.getInstance("JKS");
		InputStream in = new FileInputStream(KEY_STORE_LOCATION);
		keyStore.load(in, KEY_STORE_PASSWORD.toCharArray());
		serverPrivateKey = (PrivateKey)keyStore.getKey("server", KEY_STORE_PASSWORD.toCharArray());
		serverKeyChain = keyStore.getCertificateChain("server");
		clientPrivateKey = (PrivateKey)keyStore.getKey("client", KEY_STORE_PASSWORD.toCharArray());
		clientKeyChain = keyStore.getCertificateChain("client");

		// load the trust store
		KeyStore trustStore = KeyStore.getInstance("JKS");
		InputStream inTrust = new FileInputStream(TRUST_STORE_LOCATION);
		trustStore.load(inTrust, TRUST_STORE_PASSWORD.toCharArray());

		// You can load multiple certificates if needed
		trustedCertificates = new Certificate[1];
		trustedCertificates[0] = trustStore.getCertificate("root");

		server = createConnector(serverEndpoint, serverPrivateKey, serverKeyChain);
		client = createConnector(clientEndpoint, clientPrivateKey, clientKeyChain);
	}
	
	@After
	public void stopServer() {
		if (server != null) {
			server.stop();
		}
	}
	
	@Test
	public void testConnectorEstablishesSecureSession() throws Exception {

		final CountDownLatch latch = new CountDownLatch(2);
		Assert.assertNotNull(server);
		server.setRawDataReceiver(new RawDataChannel() {

			@Override
			public void receiveData(RawData raw) {
				server.send(new RawData("ACK".getBytes(), raw.getAddress(), raw.getPort()));
				latch.countDown();
			}
		});
		server.start();
		Assert.assertTrue(server.isRunning());

		Assert.assertNotNull(client);
		client.setRawDataReceiver(new RawDataChannel() {

			@Override
			public void receiveData(RawData raw) {
				client.destroy();
				latch.countDown();
			}
		});
		client.start();
		client.send(new RawData("Hello World".getBytes(), serverEndpoint));

		try {
			latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			Assert.assertTrue("Request/response roundtrip did not finish within 2 secs",
					0 == latch.getCount());
		} finally {
			server.destroy();
		}
	}

	@Test
	public void testConnectorAcceptsFreshClientHelloFromRebootedClient() throws Exception {

		givenAnEstablishedSession();
		
		// client has successfully established a secure session with server
		// and has been "crashed"
		// now we try to establish a new session with a client connecting from the
		// same IP address and port again
		
		final CountDownLatch newLatch = new CountDownLatch(1);
		final List<Record> receivedRecords = new ArrayList<>();
		
		DataHandler handler = new DataHandler() {
			
			@Override
			public void handleData(byte[] data) {
				receivedRecords.addAll(Record.fromByteArray(data));
				newLatch.countDown();
			}
		};
		UdpConnector rawClient = new UdpConnector(clientEndpoint, handler, client.getConfig());
		rawClient.start();
		
		rawClient.sendRecord(serverEndpoint,
				DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, createClientHello().toByteArray()));
		
		try {
			newLatch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			Assert.assertTrue("Did not receive response from server within 2 secs",
					0 == newLatch.getCount());
			Assert.assertFalse(receivedRecords.isEmpty());
			Record record = receivedRecords.get(0);
			Assert.assertEquals("Expected HANDSHAKE message from server",
					ContentType.HANDSHAKE, record.getType());
			HandshakeMessage msg = (HandshakeMessage) record.getFragment();
			Assert.assertEquals("Expected HELLO_VERIFY_REQUEST from server",
					HandshakeType.HELLO_VERIFY_REQUEST, msg.getMessageType());
		} finally {
			rawClient.stop();
			server.destroy();
		}

	}
	
	@Test
	@Ignore
	public void testConnectorResumesExistingSession() throws Exception {
	
		givenAnEstablishedSession();
		final DTLSSession serverSession = server.getSessionByAddress(clientEndpoint);
		
		final CountDownLatch newLatch = new CountDownLatch(1);
		final List<Record> receivedRecords = new ArrayList<>();
		
		DataHandler handler = new DataHandler() {
			
			@Override
			public void handleData(byte[] data) {
				receivedRecords.addAll(Record.fromByteArray(data)); 
				newLatch.countDown();
			}
		};
		UdpConnector rawClient = new UdpConnector(clientEndpoint, handler, client.getConfig());
		rawClient.start();
		
		ClientHello clientHello = createClientHello();
		clientHello.setSessionId(serverSession.getSessionIdentifier());
		
		rawClient.sendRecord(serverEndpoint,
				DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), 0, 0, clientHello.toByteArray()));
		
		try{
			newLatch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			Assert.assertTrue("Did not receive response from server within 2 secs",
					0 == newLatch.getCount());
			Assert.assertFalse(receivedRecords.isEmpty());
			Record record = receivedRecords.get(0);
			Assert.assertEquals("Expected HANDSHAKE message from server",
					ContentType.HANDSHAKE, record.getType());
			// TODO: check if received message is a SERVER_HELLO with the same sessionId
//			try {
//				HandshakeMessage msg = (HandshakeMessage) record.getFragment();
//				System.err.println(msg);
//				Assert.assertEquals("Expected SERVER_HELLO from server",
//						HandshakeType.SERVER_HELLO, msg.getMessageType());
//				ServerHello serverHello = (ServerHello) msg;
//				Assert.assertArrayEquals(serverSession.getSessionIdentifier().getSessionId(), serverHello.getSessionId().getSessionId());
//			} catch (HandshakeException e) {
//				System.err.println("DTLS record from server seems to be encrypted based on previous session state");
//			}
		} finally {
			rawClient.stop();
			server.destroy();
		}
	}

	private ClientHello createClientHello() {
		ClientHello hello = new ClientHello(new ProtocolVersion(), new SecureRandom(), false);
		hello.addCipherSuite(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8);
		hello.addCipherSuite(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
		hello.addCompressionMethod(CompressionMethod.NULL);
		hello.setMessageSeq(0);
		return hello;
	}

	private void givenAnEstablishedSession() throws IOException {
		RawData msgToSend = new RawData("Hello World".getBytes(), serverEndpoint);

		final CountDownLatch latch = new CountDownLatch(1);
		server.setRawDataReceiver(new RawDataChannel() {

			@Override
			public void receiveData(RawData raw) {
				server.send(new RawData("ACK".getBytes(), raw.getAddress(), raw.getPort()));
			}
		});
		server.start();
		Assert.assertTrue(server.isRunning());

		client.setRawDataReceiver(new RawDataChannel() {

			@Override
			public void receiveData(RawData raw) {
				latch.countDown();
			}
		});
		client.start();
		client.send(msgToSend);

		try {
			latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			Assert.assertTrue("Request/response roundtrip did not finish within 2 secs",
					0 == latch.getCount());
		} catch (InterruptedException e) {
			Assert.fail();
		} finally {
			client.releaseSocket();
		}
	}
	
	private DTLSConnector createConnector(InetSocketAddress endpoint, PrivateKey privateKey,
			Certificate[] keyChain) throws IOException, GeneralSecurityException {
		DTLSConnector dtlsConnector = new DTLSConnector(endpoint, trustedCertificates);
		dtlsConnector.getConfig().setPrivateKey(privateKey, keyChain, true);
		dtlsConnector.getConfig().setPskStore(new StaticPskStore("Client_identity", "secretPSK".getBytes()));

		return dtlsConnector;
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
		
		public UdpConnector(final InetSocketAddress bindToAddress, final DataHandler dataHandler, final DTLSConnectorConfig config) {
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
