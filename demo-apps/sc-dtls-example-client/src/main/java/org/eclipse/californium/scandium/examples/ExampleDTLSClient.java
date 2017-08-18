/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add support for multiple clients
 *                                                    exchange multiple messages
 ******************************************************************************/
package org.eclipse.californium.scandium.examples;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.ScandiumLogger;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;

public class ExampleDTLSClient {

	static {
		ScandiumLogger.initialize();
		ScandiumLogger.setLevel(Level.FINE);
	}

	private static final int DEFAULT_PORT = 5684;
	private static final Logger LOG = Logger.getLogger(ExampleDTLSClient.class.getName());
	private static final String TRUST_STORE_PASSWORD = "rootPass";
	private static final String KEY_STORE_PASSWORD = "endPass";
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";
	private static final int NB_MESSAGE = 1000;

	private static CountDownLatch latch;
	private DTLSConnector dtlsConnector;
	private final AtomicLong count = new AtomicLong();

	public ExampleDTLSClient() {
		InputStream inTrust = null;
		InputStream in = null;
		try {
			// load key store
			KeyStore keyStore = KeyStore.getInstance("JKS");
			in = getClass().getClassLoader().getResourceAsStream(KEY_STORE_LOCATION);
			keyStore.load(in, KEY_STORE_PASSWORD.toCharArray());
			in.close();

			// load trust store
			KeyStore trustStore = KeyStore.getInstance("JKS");
			inTrust = getClass().getClassLoader().getResourceAsStream(TRUST_STORE_LOCATION);
			trustStore.load(inTrust, TRUST_STORE_PASSWORD.toCharArray());

			// You can load multiple certificates if needed
			Certificate[] trustedCertificates = new Certificate[1];
			trustedCertificates[0] = trustStore.getCertificate("root");

			DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
			builder.setPskStore(new StaticPskStore("Client_identity", "secretPSK".getBytes()));
			builder.setIdentity((PrivateKey) keyStore.getKey("client", KEY_STORE_PASSWORD.toCharArray()),
					keyStore.getCertificateChain("client"), true);
			builder.setTrustStore(trustedCertificates);
			builder.setEnableAddressReuse(false);
			builder.setConnectionThreadCount(2);
			dtlsConnector = new DTLSConnector(builder.build());
			dtlsConnector.setRawDataReceiver(new RawDataChannel() {

				@Override
				public void receiveData(RawData raw) {
					long c = count.incrementAndGet();
					LOG.log(Level.INFO, "Received response: {0} {1}", new Object[] { new String(raw.getBytes()), c });
					if (c < NB_MESSAGE) {
						dtlsConnector
								.send(new RawData(("HELLO WORLD " + c + ".").getBytes(), raw.getInetSocketAddress()));
					} else {
						latch.countDown();
						dtlsConnector.destroy();
					}
				}
			});

		} catch (GeneralSecurityException | IOException e) {
			LOG.log(Level.SEVERE, "Could not load the keystore", e);
		} finally {
			try {
				if (inTrust != null) {
					inTrust.close();
				}
				if (in != null) {
					in.close();
				}
			} catch (IOException e) {
				LOG.log(Level.SEVERE, "Cannot close key store file", e);
			}
		}
	}

	public long nbMessageReceived() {
		return count.get();
	}

	private void start() {
		try {
			dtlsConnector.start();
		} catch (IOException e) {
			LOG.log(Level.SEVERE, "Cannot start connector", e);
		}
	}

	private void startTest(InetSocketAddress peer) {
		dtlsConnector.send(new RawData("HELLO WORLD".getBytes(), peer));
	}

	private void stop() {
		if (dtlsConnector.isRunning())
			dtlsConnector.destroy();
	}

	public static void main(String[] args) throws InterruptedException {
		int max = 1;
		if (0 < args.length) {
			max = Integer.parseInt(args[0]);
		}
		latch = new CountDownLatch(max);
		List<ExampleDTLSClient> clients = new ArrayList<>(max);

		// Create & start clients
		for (int index = 0; index < max; ++index) {
			ExampleDTLSClient client = new ExampleDTLSClient();
			client.start();
			clients.add(client);
		}

		// Get peer address
		InetSocketAddress peer;
		if (args.length == 3) {
			peer = new InetSocketAddress(args[1], Integer.parseInt(args[2]));
		} else {
			peer = new InetSocketAddress(InetAddress.getLoopbackAddress(), DEFAULT_PORT);
		}

		// Start Test
		long nanos = System.nanoTime();
		for (ExampleDTLSClient client : clients) {
			client.startTest(peer);
		}

		// Wait for it
		latch.await(max * 50, TimeUnit.MILLISECONDS);
		nanos = System.nanoTime() - nanos;

		// Count messages
		long count = 0;
		for (ExampleDTLSClient client : clients) {
			count += client.nbMessageReceived();
		}

		System.out.println(count + " messages received, " + (max * NB_MESSAGE) + " expected");
		System.out.println(count + " messages in " + TimeUnit.NANOSECONDS.toMillis(nanos) + " ms");
		System.out.println((count * 1000) / TimeUnit.NANOSECONDS.toMillis(nanos) + " messages per s");

		for (ExampleDTLSClient client : clients) {
			client.stop();
		}
	}
}
