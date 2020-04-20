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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.util.SimpleMessageCallback;
import org.eclipse.californium.elements.util.SimpleRawDataChannel;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
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
	 * @param rsa use mixed certifcate path (includes RSA certificate). Server
	 *            only!
	 * @param dtlsBuilder preconfigured dtls builder. Maybe {@link null}.
	 * @param trust alias of trusted certificate, or {@code null} to trust all
	 *            received certificates.
	 * @param cipherSuites cipher suites to support.
	 * @throws IOException if an error occurred starting the connector on the
	 *             provided bind address
	 */
	public void start(InetSocketAddress bind, boolean rsa, DtlsConnectorConfig.Builder dtlsBuilder, String trust,
			CipherSuite... cipherSuites) throws IOException {
		build(bind, rsa, dtlsBuilder, trust, cipherSuites);
		start();
	}

	private void start() throws IOException {
		Connector connector = getConnector();
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
