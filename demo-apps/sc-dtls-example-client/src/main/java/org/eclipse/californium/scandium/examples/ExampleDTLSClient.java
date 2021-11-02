/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add support for multiple clients
 *                                                    exchange multiple messages
 *    Achim Kraus (Bosch Software Innovations GmbH) - add client statistics
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - add argument for payload length
 ******************************************************************************/
package org.eclipse.californium.scandium.examples;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedSinglePskStore;
import org.eclipse.californium.scandium.dtls.x509.SingleCertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.StaticNewAdvancedCertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ExampleDTLSClient {

	private static final int DEFAULT_PORT = 5684;
	private static final long DEFAULT_TIMEOUT_NANOS = TimeUnit.MILLISECONDS.toNanos(10000);
	private static final Logger LOG = LoggerFactory.getLogger(ExampleDTLSClient.class);
	private static final char[] KEY_STORE_PASSWORD = "endPass".toCharArray();
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	private static final char[] TRUST_STORE_PASSWORD = "rootPass".toCharArray();
	private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";

	private static CountDownLatch messageCounter;

	private static String payload = "HELLO WORLD";

	static {
		DtlsConfig.register();
	}

	/**
	 * Special configuration defaults handler.
	 */
	private static final DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 0);
			config.set(DtlsConfig.DTLS_RECEIVER_THREAD_COUNT, 2);
			config.set(DtlsConfig.DTLS_CONNECTOR_THREAD_COUNT, 2);
		}

	};

	private DTLSConnector dtlsConnector;
	private AtomicInteger clientMessageCounter = new AtomicInteger();

	public ExampleDTLSClient() {
		try {
			// load key store
			SslContextUtil.Credentials clientCredentials = SslContextUtil.loadCredentials(
					SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION, "client", KEY_STORE_PASSWORD,
					KEY_STORE_PASSWORD);
			Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(
					SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION, "root", TRUST_STORE_PASSWORD);

			Configuration configuration = Configuration.createWithFile(Configuration.DEFAULT_FILE, "DTLS example client", DEFAULTS);

			DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder(configuration);
			builder.setAdvancedPskStore(new AdvancedSinglePskStore("Client_identity", "secretPSK".getBytes()));
			builder.setCertificateIdentityProvider(new SingleCertificateProvider(clientCredentials.getPrivateKey(), clientCredentials.getCertificateChain(),
					CertificateType.RAW_PUBLIC_KEY, CertificateType.X_509));
			builder.setAdvancedCertificateVerifier(StaticNewAdvancedCertificateVerifier.builder()
					.setTrustedCertificates(trustedCertificates).setTrustAllRPKs().build());
			dtlsConnector = new DTLSConnector(builder.build());
			dtlsConnector.setRawDataReceiver(new RawDataChannel() {

				@Override
				public void receiveData(RawData raw) {
					if (dtlsConnector.isRunning()) {
						receive(raw);
					}
				}
			});

		} catch (GeneralSecurityException | IOException e) {
			LOG.error("Could not load the keystore", e);
		}
	}

	private void receive(RawData raw) {

		messageCounter.countDown();
		long c = messageCounter.getCount();
		if (LOG.isInfoEnabled()) {
			LOG.info("Received response: {} {}", new Object[] { new String(raw.getBytes()), c });
		}
		if (0 < c) {
			clientMessageCounter.incrementAndGet();
			try {
				RawData data = RawData.outbound((payload + c + ".").getBytes(), raw.getEndpointContext(), null, false);
				dtlsConnector.send(data);
			} catch (IllegalStateException e) {
				LOG.debug("send failed after {} messages", (c - 1), e);
			}
		} else {
			dtlsConnector.destroy();
		}

	}

	private void start() {
		try {
			dtlsConnector.start();
		} catch (IOException e) {
			LOG.error("Cannot start connector", e);
		}
	}

	private void startTest(InetSocketAddress peer) {
		RawData data = RawData.outbound(payload.getBytes(), new AddressEndpointContext(peer), null, false);
		dtlsConnector.send(data);
	}

	private int stop() {
		if (dtlsConnector.isRunning()) {
			dtlsConnector.destroy();
		}
		return clientMessageCounter.get();
	}

	public static void main(String[] args) throws InterruptedException {
		int clients = 1;
		int messages = 100;
		int length = 64;
		if (0 < args.length) {
			clients = Integer.parseInt(args[0]);
			if (1 < args.length) {
				messages = Integer.parseInt(args[1]);
				if (2 < args.length) {
					length = Integer.parseInt(args[2]);
				}
			}
		}
		int maxMessages = (messages * clients);
		messageCounter = new CountDownLatch(maxMessages);
		while (payload.length() < length) {
			payload += payload;
		}
		payload = payload.substring(0, length);
		
		List<ExampleDTLSClient> clientList = new ArrayList<>(clients);
		ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors(),
				new DaemonThreadFactory("Aux#"));

		System.out.println("Create " + clients + " DTLS example clients, expect to send " + maxMessages +" messages overall.");

		final CountDownLatch start = new CountDownLatch(clients);

		// Create & start clients
		for (int index = 0; index < clients; ++index) {
			final ExampleDTLSClient client = new ExampleDTLSClient();
			clientList.add(client);
			executor.execute(new Runnable() {

				@Override
				public void run() {
					client.start();
					start.countDown();
				}
			});
		}
		start.await();
		System.out.println(clients + " DTLS example clients started.");

		// Get peer address
		InetSocketAddress peer;
		if (args.length == 5) {
			peer = new InetSocketAddress(args[3], Integer.parseInt(args[4]));
		} else {
			peer = new InetSocketAddress(InetAddress.getLoopbackAddress(), DEFAULT_PORT);
		}

		// Start Test
		long nanos = System.nanoTime();
		long lastMessageCountDown = messageCounter.getCount();

		for (ExampleDTLSClient client : clientList) {
			client.startTest(peer);
		}

		// Wait with timeout or all messages send.
		while (!messageCounter.await(DEFAULT_TIMEOUT_NANOS, TimeUnit.NANOSECONDS)) {
			long current = messageCounter.getCount();
			if (lastMessageCountDown == current && current < maxMessages) {
				// no new messages, clients are stale
				// adjust start time with timeout
				nanos += DEFAULT_TIMEOUT_NANOS; 
				break;
			}
			lastMessageCountDown = current;
		}
		long count = maxMessages - messageCounter.getCount();
		nanos = System.nanoTime() - nanos;

		System.out.println(clients + " DTLS example clients finished.");
		
		int statistic[] = new int[clients];
		for (int index = 0; index < clients; ++index) {
			ExampleDTLSClient client = clientList.get(index);
			statistic[index] = client.stop();
		}

		System.out.println(count + " messages received, " + (maxMessages) + " expected");
		System.out.println(count + " messages in " + TimeUnit.NANOSECONDS.toMillis(nanos) + " ms");
		System.out.println((count * 1000) / TimeUnit.NANOSECONDS.toMillis(nanos) + " messages per s");
		if (count < maxMessages) {
			System.out.println("Stale at " + lastMessageCountDown + " messages");
		}
		if (1 < clients) {
			Arrays.sort(statistic);
			int grouped = 10;
			int last = 0;
			for (int index = 1; index < clients; ++index) {
				if ((statistic[index] / grouped) > (statistic[last] / grouped)) {
					if (statistic[index-1] == statistic[last]) {
						System.out.println((index - last) + " clients with " + statistic[last] + " messages.");
					}
					else {
						System.out.println((index - last) + " clients with " + statistic[last] + " to " + statistic[index-1] + " messages.");
					}
					last = index;
				}
			}
			System.out.println((clients - last) + " clients with " + statistic[last] + " to " + statistic[clients-1] + " messages.");
		}
	}
}
