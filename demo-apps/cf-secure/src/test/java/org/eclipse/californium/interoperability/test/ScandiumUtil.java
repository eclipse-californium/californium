/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation.
 ******************************************************************************/
package org.eclipse.californium.interoperability.test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.util.SimpleMessageCallback;
import org.eclipse.californium.elements.util.SimpleRawDataChannel;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.examples.CredentialsUtil;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;

/**
 * Scandium utility.
 * 
 * Configure and starts {@link DTLSConnector}.
 */
public class ScandiumUtil {

	public static final int PORT = 5684;

	private static final char[] KEY_STORE_PASSWORD = "endPass".toCharArray();
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	private static final String CLIENT_NAME = "client";
	private static final String SERVER_NAME = "server";

	/**
	 * DTLS connector.
	 */
	private DTLSConnector connector;
	/**
	 * Raw data channel to receive data.
	 */
	private SimpleRawDataChannel channel;
	/**
	 * Last received data.
	 */
	private RawData receivedData;
	/**
	 * Credentials for ECDSA base cipher suites.
	 */
	private SslContextUtil.Credentials credentials;

	/**
	 * Create new utility instance.
	 * 
	 * @param client {@code true} to use client credentials, {@code false}, for
	 *            server credentials.
	 */
	public ScandiumUtil(boolean client) {
		try {
			credentials = SslContextUtil.loadCredentials(SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION,
					client ? CLIENT_NAME : SERVER_NAME, KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Shutdown the connector.
	 */
	public void shutdown() {
		if (connector != null) {
			connector.destroy();
			connector = null;
		}
		channel = null;
		receivedData = null;
	}

	/**
	 * Start connector.
	 * 
	 * @param bind address to bind connector to
	 * @param cipherSuites cipher suites to support.
	 * @throws IOException if an error occurred starting the connector on the
	 *             provided bind address
	 */
	public void start(InetSocketAddress bind, CipherSuite... cipherSuites) throws IOException {
		List<CipherSuite> suites = Arrays.asList(cipherSuites);
		DtlsConnectorConfig.Builder dtlsBuilder = new DtlsConnectorConfig.Builder();
		dtlsBuilder.setAddress(bind);
		dtlsBuilder.setRecommendedCipherSuitesOnly(false);
		dtlsBuilder.setConnectionThreadCount(2);
		dtlsBuilder.setReceiverThreadCount(2);
		if (CipherSuite.containsPskBasedCipherSuite(suites)) {
			dtlsBuilder.setPskStore(
					new StaticPskStore(CredentialsUtil.OPEN_PSK_IDENTITY, CredentialsUtil.OPEN_PSK_SECRET));
		}
		if (CipherSuite.containsCipherSuiteRequiringCertExchange(suites)) {
			if (credentials != null) {
				dtlsBuilder.setIdentity(credentials.getPrivateKey(), credentials.getCertificateChain(),
						CertificateType.X_509, CertificateType.RAW_PUBLIC_KEY);
				dtlsBuilder.setTrustStore(new Certificate[0]);
			}
		}
		dtlsBuilder.setSupportedCipherSuites(suites);
		connector = new DTLSConnector(dtlsBuilder.build());
		channel = new SimpleRawDataChannel(1);
		connector.setRawDataReceiver(channel);
		connector.start();
	}

	/**
	 * Send data through the connector. The connector must be started before.
	 * 
	 * @param data data to send
	 */
	public void send(RawData data) {
		connector.send(data);
	}

	/**
	 * Wait for received data.
	 * 
	 * @param timeout timeout to wait for
	 * @param unit time unit of timeout
	 * @return received data, or {@code null}, if no data is received in time.
	 * @throws InterruptedException if interrupted during wait
	 */
	public RawData poll(long timeout, TimeUnit unit) throws InterruptedException {
		return channel.poll(timeout, unit);
	}

	/**
	 * Assert, that this message is received in time.
	 * 
	 * The message must be first received one.
	 * 
	 * @param message message the receiving is to be asserted
	 * @param timeoutMillis timeout of message
	 * @throws InterruptedException if interrupted during wait
	 */
	public void assertReceivedData(String message, long timeoutMillis) throws InterruptedException {
		receivedData = channel.poll(timeoutMillis, TimeUnit.MILLISECONDS);
		assertNotNull("message missing!", receivedData);
		assertThat(new String(receivedData.getBytes()), is(message));
	}

	/**
	 * Send message as response to the last received message.
	 * 
	 * @param message message to send
	 * @param timeoutMillis timeout in millisecond.
	 * @see #receivedData
	 */
	public void response(String message, long timeoutMillis) {
		send(message, receivedData.getEndpointContext().getPeerAddress(), timeoutMillis);
	}

	/**
	 * Send message to destination.
	 * 
	 * @param message message to send
	 * @param destination destination address
	 * @param timeoutMillis timeout in milliseconds
	 */
	public void send(String message, InetSocketAddress destination, long timeoutMillis) {
		SimpleMessageCallback callback = new SimpleMessageCallback(1, false);
		RawData raw = RawData.outbound(message.getBytes(), new AddressEndpointContext(destination), callback, false);
		connector.send(raw);
		try {
			boolean sent = callback.isSent(timeoutMillis);
			EndpointContext context = callback.getEndpointContext();
			assertNotNull(context);
			assertNull(callback.getError());
			assertTrue(sent);
		} catch (InterruptedException ex) {
			fail(ex.getMessage());
		}
	}
}
