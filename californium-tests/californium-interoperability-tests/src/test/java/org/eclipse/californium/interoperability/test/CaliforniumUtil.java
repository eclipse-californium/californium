/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Achim Kraus (Bosch.IO GmbH) - initial implementation.
 ******************************************************************************/
package org.eclipse.californium.interoperability.test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

/**
 * Californium utility.
 * 
 * Configure and starts coap-server or -client.
 */
public class CaliforniumUtil extends ConnectorUtil {

	/**
	 * {@code true}, if used as client, {@code false}, otherwise.
	 */
	private boolean asClient;
	/**
	 * Coap-server.
	 */
	private CoapServer server;
	/**
	 * Coap-client.
	 */
	private CoapClient client;

	/**
	 * Queue of incoming message for the coap-server.
	 */
	private final LinkedBlockingQueue<String> incoming = new LinkedBlockingQueue<>();

	/**
	 * Create new utility instance.
	 * 
	 * @param client {@code true} to use client credentials, {@code false}, for
	 *            server credentials.
	 */
	public CaliforniumUtil(boolean client) {
		super(client);
		asClient = client;
	}

	/**
	 * Shutdown the coap-server or -client.
	 */
	@Override
	public void shutdown() {
		if (server != null) {
			server.destroy();
			server = null;
		}
		if (client != null) {
			client.shutdown();
			client = null;
		}
		super.shutdown();
		incoming.clear();
	}

	/**
	 * Start coap-server or -client.
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
	 * Start coap-server or -client.
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
		NetworkConfig config = NetworkConfig.getStandard();
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setNetworkConfig(config);
		builder.setConnector(getConnector());
		CoapEndpoint endpoint = builder.build();
		if (asClient) {
			client = new CoapClient();
			client.setEndpoint(endpoint);
		} else {
			server = new CoapServer(config);
			server.addEndpoint(endpoint);
			server.add(new CoapResource("test") {

				@Override
				public void handlePOST(CoapExchange exchange) {
					addReceivedMessage(exchange.getRequestText());
					exchange.respond(ResponseCode.CHANGED, "Greetings!");
				}
			});
			server.add(new CoapResource("large") {

				@Override
				public void handlePOST(CoapExchange exchange) {
					addReceivedMessage(exchange.getRequestText());
					int size = 1024;
					String sizeParam = exchange.getQueryParameter("size");
					if (sizeParam != null && !sizeParam.isEmpty()) {
						try {
							size = Integer.parseInt(sizeParam);
						} catch (NumberFormatException ex) {
						}
					}
					byte[] message = new byte[size];
					Arrays.fill(message, (byte) '#');
					for (int index = 63; index < message.length; index += 64) {
						message[index] = (byte) '\n';
					}
					exchange.respond(ResponseCode.CHANGED, message);
				}
			});
			server.add(new CoapResource("custom") {

				@Override
				public void handlePOST(CoapExchange exchange) {
					addReceivedMessage(exchange.getRequestText());
					Response response = new Response(ResponseCode.CHANGED);
					response.setPayload("Custom Greetings!");
					response.getOptions().setContentFormat(MediaTypeRegistry.MAX_TYPE - 10);
					int OPTION_TRACE_CONTEXT = 0b1111110111111110; // 65022
					Option custom = new Option(OPTION_TRACE_CONTEXT);
					custom.setStringValue("test");
					response.getOptions().addOption(custom);
					response.getOptions().setContentFormat(MediaTypeRegistry.MAX_TYPE - 10);
					exchange.respond(response);
				}
			});
			server.add(new CoapResource("event") {

				@Override
				public void handlePOST(CoapExchange exchange) {
					addReceivedMessage(exchange.getRequestText());
					Response response = new Response(ResponseCode.CHANGED);
					response.getOptions().setLocationPath("/command/1234-abcde");
					response.getOptions().setLocationQuery("hono-command=blink");
					response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
					response.setPayload("Response!");
					exchange.respond(response);
				}
			});
			server.start();
		}
	}

	/**
	 * Send request.
	 * 
	 * Only available for clients, see {@link #CaliforniumUtil(boolean)}.
	 * 
	 * @param request request to send
	 * @return response, or {@code null}, if no response was received.
	 * @throws ConnectorException if the connector reports an error
	 * @throws IOException if the io reports an error.
	 * @throws IllegalStateException if it is not a client
	 */
	public CoapResponse send(Request request) throws ConnectorException, IOException {
		if (!asClient) {
			throw new IllegalStateException("Only available for clients!");
		}
		return client.advanced(request);
	}

	/**
	 * Add received message to incoming messages.
	 * 
	 * Only available for servers
	 * 
	 * @param message received message
	 */
	private void addReceivedMessage(String message) {
		incoming.add(message);
	}

	/**
	 * Get received message.
	 * 
	 * Only available for servers.
	 * 
	 * @return received message. Maybe {@code null}.
	 * @throws IllegalStateException if it is not a server
	 */
	public synchronized String getReceivedMessage() {
		if (asClient) {
			throw new IllegalStateException("Only available for servers!");
		}
		return incoming.poll();
	}

	/**
	 * Wait for received message.
	 * 
	 * Only available for servers.
	 * 
	 * @return received message. Maybe {@code null}.
	 * @throws InterruptedException if interrupted during wait
	 * @throws IllegalStateException if it is not a server
	 */
	public synchronized String waitForReceivedMessage(long timeoutMillis) throws InterruptedException {
		if (asClient) {
			throw new IllegalStateException("Only available for servers!");
		}
		return incoming.poll(timeoutMillis, TimeUnit.MILLISECONDS);
	}

	/**
	 * Assert, that this message is received in time.
	 * 
	 * @param message message the receiving is to be asserted
	 * @param timeoutMillis timeout of message
	 * @throws InterruptedException if interrupted during wait
	 */
	public void assertReceivedData(String message, long timeoutMillis) throws InterruptedException {
		String received = waitForReceivedMessage(timeoutMillis);
		assertNotNull("Californium server missing message '" + message + "'!", received);
		assertThat(received, is(message));
	}
}
