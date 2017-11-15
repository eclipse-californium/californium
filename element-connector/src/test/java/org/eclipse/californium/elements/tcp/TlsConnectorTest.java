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
 * Achim Kraus (Bosch Software Innovations GmbH) - add more logging.
 * Achim Kraus (Bosch Software Innovations GmbH) - implement checkServerTrusted
 *                                                 to check the DN more relaxed.
 * Achim Kraus (Bosch Software Innovations GmbH) - use ConnectorTestUtil
 * Achim Kraus (Bosch Software Innovations GmbH) - use create server address
 *                                                 (LoopbackAddress)
 * Achim Kraus (Bosch Software Innovations GmbH) - add NUMBER_OF_CONNECTIONS
 *                                                 and reduce it to 50
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import static org.junit.Assert.*;
import static org.eclipse.californium.elements.tcp.ConnectorTestUtil.*;

import java.io.InputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
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

	private static final Logger LOGGER = Logger.getLogger(TlsConnectorTest.class.getName());

	private static final int NUMBER_OF_CONNECTIONS = 50;
	private static final int NUMBER_OF_THREADS = 1;
	private static final int IDLE_TIMEOUT = 100;
	private static KeyManager[] keyManagers;
	private static TrustManager[] trustManager;
	private static SSLContext serverContext;
	private static SSLContext clientContext;

	@Rule
	public final Timeout timeout = new Timeout(10, TimeUnit.SECONDS);
	private final List<Connector> cleanup = new ArrayList<>();

	@BeforeClass
	public static void initializeSsl() throws Exception {
		String algorithm = Security.getProperty("ssl.KeyManagerFactory.algorithm");
		InputStream stream = TlsConnectorTest.class.getResourceAsStream("/certs/keyStore.jks");
		if (null == stream) {
			throw new IllegalStateException("missing demo-certs keystore!");
		}

		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(stream, "endPass".toCharArray());
		int counter = 0;
		Enumeration<String> aliases = keyStore.aliases();
		while (aliases.hasMoreElements()) {
			++counter;
			LOGGER.log(Level.INFO, "{0}. KeyStore Alias: {1}", new Object[] { counter, aliases.nextElement() });
		}
		// Set up key manager factory to use our key store
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
		kmf.init(keyStore, "endPass".toCharArray());
		keyManagers = kmf.getKeyManagers();
		trustManager = new TrustManager[] { new TrustEveryoneTrustManager() };
		// Initialize the SSLContext to work with our key managers.
		serverContext = SSLContext.getInstance("TLS");
		serverContext.init(keyManagers, null, null);

		clientContext = SSLContext.getInstance("TLS");
		clientContext.init(null, trustManager, null);
	}

	@After
	public void cleanup() {
		for (Connector connector : cleanup) {
			connector.stop();
		}
	}

	@Test
	public void pingPongMessage() throws Exception {
		TlsServerConnector server = new TlsServerConnector(serverContext, createServerAddress(0), NUMBER_OF_THREADS,
				IDLE_TIMEOUT);
		TlsClientConnector client = new TlsClientConnector(clientContext, NUMBER_OF_THREADS, 100, 10);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		cleanup.add(server);
		cleanup.add(client);
		server.start();
		client.start();

		RawData msg = createMessage(server.getAddress(), 100, null, null);

		client.send(msg);
		serverCatcher.blockUntilSize(1);
		assertArrayEquals(msg.getBytes(), serverCatcher.getMessage(0).getBytes());

		// Response message must go over the same connection client already
		// opened
		msg = createMessage(serverCatcher.getMessage(0).getInetSocketAddress(), 10000, null, null);
		server.send(msg);
		clientCatcher.blockUntilSize(1);
		assertArrayEquals(msg.getBytes(), clientCatcher.getMessage(0).getBytes());
	}

	@Test
	public void singleServerManyClients() throws Exception {
		TlsServerConnector server = new TlsServerConnector(serverContext, createServerAddress(0), NUMBER_OF_THREADS,
				IDLE_TIMEOUT);
		cleanup.add(server);

		Catcher serverCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		server.start();

		List<RawData> messages = new ArrayList<>();
		for (int i = 0; i < NUMBER_OF_CONNECTIONS; i++) {
			TlsClientConnector client = new TlsClientConnector(clientContext, NUMBER_OF_THREADS, 100, IDLE_TIMEOUT);
			cleanup.add(client);
			Catcher clientCatcher = new Catcher();
			client.setRawDataReceiver(clientCatcher);
			client.start();

			RawData msg = createMessage(server.getAddress(), 100, null, null);
			messages.add(msg);
			client.send(msg);
		}

		serverCatcher.blockUntilSize(NUMBER_OF_CONNECTIONS);
		for (int i = 0; i < NUMBER_OF_CONNECTIONS; i++) {
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
			TlsServerConnector server = new TlsServerConnector(serverContext, createServerAddress(0), NUMBER_OF_THREADS,
					IDLE_TIMEOUT);
			cleanup.add(server);
			Catcher serverCatcher = new Catcher();
			server.setRawDataReceiver(serverCatcher);
			server.start();

			servers.put(getDestination(server.getAddress()), serverCatcher);
		}

		TlsClientConnector client = new TlsClientConnector(clientContext, NUMBER_OF_THREADS, 100, IDLE_TIMEOUT);
		cleanup.add(client);
		Catcher clientCatcher = new Catcher();
		client.setRawDataReceiver(clientCatcher);
		client.start();

		List<RawData> messages = new ArrayList<>();
		for (InetSocketAddress address : servers.keySet()) {
			RawData message = createMessage(address, 100, null, null);
			messages.add(message);
			client.send(message);
		}

		for (RawData message : messages) {
			Catcher catcher = servers.get(message.getInetSocketAddress());
			catcher.blockUntilSize(1);
			assertArrayEquals(message.getBytes(), catcher.getMessage(0).getBytes());
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
				/*
				 * only check, if the subject DN starts with the expected name
				 */
				if (cert.getSubjectDN().getName().startsWith("C=CA, L=Ottawa, O=Eclipse IoT, OU=Californium, CN=cf-")) {
					return;
				}
			}
			for (X509Certificate cert : x509Certificates) {
				LOGGER.log(Level.WARNING, "Untrusted certificate from {0}", cert.getSubjectDN().getName());
			}
			if (0 < x509Certificates.length) {
				throw new CertificateException(
						"Unexpected domain name: " + x509Certificates[0].getSubjectDN().getName());
			} else {
				throw new CertificateException("Certificates missing!");
			}
		}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return new X509Certificate[0];
		}
	}
}
