/*******************************************************************************
 * Copyright (c) 2016 Amazon Web Services.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * <p>
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.html.
 * <p>
 * Contributors:
 * Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.RawData;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;

public class TlsConnectorTest {

	private static final int NUMBER_OF_THREADS = 1;
	private static final int IDLE_TIMEOUT = 100;
	private static SSLContext serverContext;
	private static SSLContext clientContext;
	private final Random random = new Random(0);

	@Rule
	public final Timeout timeout = new Timeout(10, TimeUnit.SECONDS);
	private final List<Connector> cleanup = new ArrayList<>();

	@BeforeClass
	public static void initializeSsl() throws Exception {
		String algorithm = Security.getProperty("ssl.KeyManagerFactory.algorithm");

		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(TlsConnectorTest.class.getResourceAsStream("/cert.jks"), "secret".toCharArray());

		// Set up key manager factory to use our key store
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
		kmf.init(ks, "secret".toCharArray());

		// Initialize the SSLContext to work with our key managers.
		serverContext = SSLContext.getInstance("TLS");
		serverContext.init(kmf.getKeyManagers(), null, null);

		clientContext = SSLContext.getInstance("TLS");
		clientContext.init(null, new TrustManager[] { new TrustEveryoneTrustManager() }, null);
	}

	@After
	public void cleanup() {
		for (Connector connector : cleanup) {
			connector.stop();
		}
	}

	@Test
	public void pingPongMessage() throws Exception {
		int port = findEphemeralPort();
		TlsServerConnector server = new TlsServerConnector(serverContext, new InetSocketAddress(port),
				NUMBER_OF_THREADS, IDLE_TIMEOUT);
		TlsClientConnector client = new TlsClientConnector(clientContext, NUMBER_OF_THREADS, 100, 10);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		cleanup.add(server);
		cleanup.add(client);
		server.start();
		client.start();

		RawData msg = createMessage(new InetSocketAddress(port), 100);

		client.send(msg);
		serverCatcher.blockUntilSize(1);
		assertArrayEquals(msg.getBytes(), serverCatcher.getMessage(0).getBytes());

		// Response message must go over the same connection client already
		// opened
		msg = createMessage(serverCatcher.getMessage(0).getInetSocketAddress(), 10000);
		server.send(msg);
		clientCatcher.blockUntilSize(1);
		assertArrayEquals(msg.getBytes(), clientCatcher.getMessage(0).getBytes());
	}

	@Test
	public void singleServerManyClients() throws Exception {
		int port = findEphemeralPort();
		int clients = 100;
		TlsServerConnector server = new TlsServerConnector(serverContext, new InetSocketAddress(port),
				NUMBER_OF_THREADS, IDLE_TIMEOUT);
		cleanup.add(server);

		Catcher serverCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		server.start();

		List<RawData> messages = new ArrayList<>();
		for (int i = 0; i < clients; i++) {
			TlsClientConnector client = new TlsClientConnector(clientContext, NUMBER_OF_THREADS, 100, IDLE_TIMEOUT);
			cleanup.add(client);
			Catcher clientCatcher = new Catcher();
			client.setRawDataReceiver(clientCatcher);
			client.start();

			RawData msg = createMessage(new InetSocketAddress(port), 100);
			messages.add(msg);
			client.send(msg);
		}

		serverCatcher.blockUntilSize(clients);
		for (int i = 0; i < clients; i++) {
			RawData received = serverCatcher.getMessage(i);

			// Make sure that we intended to send that message
			boolean matched = false;
			for (RawData sent : messages) {
				if (Arrays.equals(sent.getBytes(), received.getBytes())) {
					matched = true;
					break;
				}
			}
			assertTrue("Received unexpected message: " + received, matched);
		}
	}

	@Test
	public void singleClientManyServers() throws Exception {
		int serverCount = 3;
		Map<InetSocketAddress, Catcher> servers = new IdentityHashMap<>();
		for (int i = 0; i < serverCount; i++) {
			int port = findEphemeralPort();
			TlsServerConnector server = new TlsServerConnector(serverContext, new InetSocketAddress(port),
					NUMBER_OF_THREADS, IDLE_TIMEOUT);
			cleanup.add(server);
			Catcher serverCatcher = new Catcher();
			server.setRawDataReceiver(serverCatcher);
			server.start();

			servers.put(server.getAddress(), serverCatcher);
		}

		TlsClientConnector client = new TlsClientConnector(clientContext, NUMBER_OF_THREADS, 100, IDLE_TIMEOUT);
		cleanup.add(client);
		Catcher clientCatcher = new Catcher();
		client.setRawDataReceiver(clientCatcher);
		client.start();

		List<RawData> messages = new ArrayList<>();
		for (InetSocketAddress address : servers.keySet()) {
			RawData message = createMessage(address, 100);
			messages.add(message);
			client.send(message);
		}

		for (RawData message : messages) {
			Catcher catcher = servers.get(message.getInetSocketAddress());
			catcher.blockUntilSize(1);
			assertArrayEquals(message.getBytes(), catcher.getMessage(0).getBytes());
		}
	}

	private int findEphemeralPort() {
		try (ServerSocket socket = new ServerSocket(0)) {
			return socket.getLocalPort();
		} catch (IOException e) {
			throw new IllegalStateException("Unable to bind to ephemeral port");
		}
	}

	private RawData createMessage(InetSocketAddress address, int messageSize) throws Exception {
		byte[] data = new byte[messageSize];
		random.nextBytes(data);

		try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
			if (messageSize < 13) {
				stream.write(messageSize << 4);
			} else if (messageSize < (1 << 8) + 13) {
				stream.write(13 << 4);
				stream.write(messageSize - 13);
			} else if (messageSize < (1 << 16) + 269) {
				stream.write(14 << 4);

				ByteBuffer buffer = ByteBuffer.allocate(2);
				buffer.putShort((short) (messageSize - 269));
				stream.write(buffer.array());
			} else {
				stream.write(15 << 4);

				ByteBuffer buffer = ByteBuffer.allocate(4);
				buffer.putInt(messageSize - 65805);
				stream.write(buffer.array());
			}

			stream.write(1); // GET
			stream.write(data);
			stream.flush();
			return new RawData(stream.toByteArray(), address);
		}
	}

	private static class TrustEveryoneTrustManager implements X509TrustManager {

		@Override
		public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
		}

		@Override
		public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
			for (X509Certificate cert : x509Certificates) {
				cert.checkValidity();
				if (!cert.getSubjectDN().getName().equals("CN=californium")) {
					throw new CertificateException("Unexpected domain name: " + cert.getSubjectDN());
				}
			}
		}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return new X509Certificate[0];
		}
	}
}
