/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation.
 ******************************************************************************/
package org.eclipse.californium.interoperability.test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.util.SimpleMessageCallback;
import org.eclipse.californium.elements.util.SimpleRawDataChannel;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.DTLSContext;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

/**
 * Scandium utility.
 * 
 * Configure and starts {@link DTLSConnector}.
 */
public class ScandiumUtil extends ConnectorUtil {

	/**
	 * Raw data channel to receive data.
	 */
	private SimpleRawDataChannel channel;
	/**
	 * Last received data.
	 */
	private RawData receivedData;

	/**
	 * Create new utility instance.
	 * 
	 * @param client {@code true} to use client credentials, {@code false}, for
	 *            server credentials.
	 */
	public ScandiumUtil(boolean client) {
		super(client);
	}

	/**
	 * Shutdown the connector.
	 */
	@Override
	public void shutdown() {
		super.shutdown();
		channel = null;
		receivedData = null;
		assertNoUnexpectedAlert();
	}

	/**
	 * Start connector.
	 * 
	 * @param bind address to bind connector to
	 * @param trust alias of trusted certificate, or {@code null} to trust all
	 *            received certificates.
	 * @param cipherSuites cipher suites to support.
	 * @throws IOException if an error occurred starting the connector on the
	 *             provided bind address
	 */
	public void start(InetSocketAddress bind, String trust, CipherSuite... cipherSuites) throws IOException {
		build(bind, trust, cipherSuites);
		start();
	}

	/**
	 * Start connector.
	 * 
	 * @param bind address to bind connector to
	 * @param dtlsBuilder preconfigured dtls builder. May be {@code null}.
	 * @param trust alias of trusted certificate, or {@code null} to trust all
	 *            received certificates.
	 * @param cipherSuites cipher suites to support.
	 * @throws IOException if an error occurred starting the connector on the
	 *             provided bind address
	 */
	public void start(InetSocketAddress bind, DtlsConnectorConfig.Builder dtlsBuilder, String trust,
			CipherSuite... cipherSuites) throws IOException {
		build(bind, dtlsBuilder, trust, cipherSuites);
		start();
	}

	private void start() throws IOException {
		Connector connector = getConnector();
		channel = new SimpleRawDataChannel(1);
		connector.setRawDataReceiver(channel);
		try {
			connector.start();
		} catch (BindException e) {
			try {
				Thread.sleep(500);
				connector.start();
			} catch (InterruptedException e1) {
				Thread.currentThread().interrupt();
			}
		}
	}

	/**
	 * Send data through the connector. The connector must be started before.
	 * 
	 * @param data data to send
	 */
	public void send(RawData data) {
		getConnector().send(data);
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
		assertNotNull("scandium missing message '" + message + "'!", receivedData);
		assertThat(new String(receivedData.getBytes()), is(message));
	}

	/**
	 * Assert, that this message is received in time.
	 * 
	 * The message must be contained in the first received one.
	 * 
	 * @param message message the receiving is to be asserted
	 * @param timeoutMillis timeout of message
	 * @throws InterruptedException if interrupted during wait
	 * @since 3.3
	 */
	public void assertContainsReceivedData(String message, long timeoutMillis) throws InterruptedException {
		receivedData = channel.poll(timeoutMillis, TimeUnit.MILLISECONDS);
		assertNotNull("scandium missing message '" + message + "'!", receivedData);
		assertThat(new String(receivedData.getBytes()), containsString(message));
	}

	/**
	 * Get remote's principal.
	 * 
	 * @param timeoutMillis timeout of message, if not already received
	 * @return remote's principal, or {@code null}, if missing.
	 * @throws InterruptedException if interrupted during wait
	 * @since 3.8
	 */
	public Principal getPrincipal(long timeoutMillis) throws InterruptedException {
		if (receivedData == null) {
			receivedData = channel.poll(timeoutMillis, TimeUnit.MILLISECONDS);
		}
		return receivedData != null ? receivedData.getSenderIdentity() : null;
	}

	/**
	 * Get endpoint context.
	 * 
	 * @param timeoutMillis timeout of message, if not already received
	 * @return endpoint context, or {@code null}, if missing.
	 * @throws InterruptedException if interrupted during wait
	 * @since 3.8
	 */
	public EndpointContext getContext(long timeoutMillis) throws InterruptedException {
		if (receivedData == null) {
			receivedData = channel.poll(timeoutMillis, TimeUnit.MILLISECONDS);
		}
		return receivedData != null ? receivedData.getEndpointContext() : null;
	}

	/**
	 * Get DTLS context.
	 * 
	 * @param timeoutMillis timeout of message, if not already received
	 * @return DTLS context, or {@code null}, if missing.
	 * @throws InterruptedException if interrupted during wait
	 * @since 3.10
	 */
	public DTLSContext getDTLSContext(long timeoutMillis) throws InterruptedException {
		if (receivedData == null) {
			receivedData = channel.poll(timeoutMillis, TimeUnit.MILLISECONDS);
		}
		if (receivedData != null) {
			DTLSConnector dtls = (DTLSConnector) getConnector();
			return dtls.getDtlsContextByAddress(receivedData.getInetSocketAddress());
		}
		return null;
	}

	/**
	 * Assert, that the peer's principal is of expected type.
	 * 
	 * @param timeoutMillis timeout of message, if not already received
	 * @param expectedPrincipalType expected principal type. {@code null}, for
	 *            no principal.
	 * @throws InterruptedException if interrupted during wait
	 * @since 3.8
	 */
	public void assertPrincipalType(long timeoutMillis, final Class<?> expectedPrincipalType)
			throws InterruptedException {
		if (receivedData == null) {
			receivedData = channel.poll(timeoutMillis, TimeUnit.MILLISECONDS);
		}
		assertNotNull("scandium missing received message!", receivedData);
		Principal principal = receivedData.getSenderIdentity();
		// assert that peer identity is of given type
		if (principal != null && expectedPrincipalType != null) {
			assertThat(principal, instanceOf(expectedPrincipalType));
		} else if (expectedPrincipalType != null) {
			fail("scandium missing principal, expected " + expectedPrincipalType.getSimpleName() + "!");
		} else if (principal != null) {
			fail("scandium unexpected principal " + principal + "!");
		}
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
		send(raw);
		try {
			boolean sent = callback.isSent(timeoutMillis);
			EndpointContext context = callback.getEndpointContext();
			assertNull("error", callback.getError());
			assertNotNull("missing session", context);
			assertTrue("message not sent!", sent);
		} catch (InterruptedException ex) {
			fail(ex.getMessage());
		}
	}
}
