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

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.Arrays;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.option.MapBasedOptionRegistry;
import org.eclipse.californium.core.coap.option.OpaqueOptionDefinition;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.StandardCharsets;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

/**
 * Californium utility.
 * 
 * Configure and starts coap-server or -client.
 */
public class CaliforniumUtil extends ConnectorUtil {

	static {
		CoapConfig.register();
	}

	public static final int OPTION_TRACE_CONTEXT_NO = 0b1111110111111110; // 65022

	public static final OpaqueOptionDefinition OPTION_TRACE_CONTEXT = new OpaqueOptionDefinition(OPTION_TRACE_CONTEXT_NO, "Trace_Context", true, 1, 128);

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
	 * Last principal.
	 */
	private final AtomicReference<Principal> principal = new AtomicReference<>();
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
		assertNoUnexpectedAlert();
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
		Configuration config = Configuration.createStandardWithoutFile();
		MapBasedOptionRegistry registry = new MapBasedOptionRegistry(StandardOptionRegistry.STANDARD_OPTIONS, OPTION_TRACE_CONTEXT);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setConfiguration(config);
		builder.setConnector(getConnector());
		builder.setOptionRegistry(registry);
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
					addReceivedExchange(exchange);
					exchange.respond(ResponseCode.CHANGED, "Greetings!");
				}
			});
			server.add(new CoapResource("large") {

				@Override
				public void handlePOST(CoapExchange exchange) {
					addReceivedExchange(exchange);
					int size = 1024;
					String sizeParam = exchange.getQueryParameter("size");
					if (sizeParam != null && !sizeParam.isEmpty()) {
						try {
							size = Integer.parseInt(sizeParam);
						} catch (NumberFormatException ex) {
						}
					}
					byte[] message = createPayload(size);
					exchange.respond(ResponseCode.CHANGED, message);
				}
			});
			server.add(new CoapResource("custom") {

				@Override
				public void handlePOST(CoapExchange exchange) {
					addReceivedExchange(exchange);
					Response response = new Response(ResponseCode.CHANGED);
					response.setPayload("Custom Greetings!");
					response.getOptions().setContentFormat(MediaTypeRegistry.MAX_TYPE - 10);
					Option custom = OPTION_TRACE_CONTEXT.create(new byte[] { 0x1 });
					custom.setStringValue("test");
					response.getOptions().addOption(custom);
					response.getOptions().setContentFormat(MediaTypeRegistry.MAX_TYPE - 10);
					exchange.respond(response);
				}
			});
			server.add(new CoapResource("event") {

				@Override
				public void handlePOST(CoapExchange exchange) {
					addReceivedExchange(exchange);
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
	 * Send request using a full handshake.
	 * 
	 * Only available for clients, see {@link #CaliforniumUtil(boolean)}.
	 * 
	 * @param request request to send
	 * @return response, or {@code null}, if no response was received.
	 * @throws IllegalStateException if it is not a client
	 * @since 3.0
	 */
	public CoapResponse sendWithFullHandshake(Request request) {
		EndpointContext destinationContext = request.getDestinationContext();
		destinationContext = MapBasedEndpointContext.setEntries(destinationContext,
				DtlsEndpointContext.ATTRIBUE_HANDSHAKE_MODE_FORCE_FULL);
		request.setDestinationContext(destinationContext);
		return send(request);
	}

	/**
	 * Send request.
	 * 
	 * Only available for clients, see {@link #CaliforniumUtil(boolean)}.
	 * 
	 * @param request request to send
	 * @return response, or {@code null}, if no response was received.
	 * @throws IllegalStateException if it is not a client
	 */
	public CoapResponse send(Request request) {
		if (!asClient) {
			throw new IllegalStateException("Only available for clients!");
		}
		try {
			CoapResponse response = client.advanced(request);
			if (response != null) {
				principal.set(response.advanced().getSourceContext().getPeerIdentity());
			}
			return response;
		} catch (ConnectorException ex) {
			return null;
		} catch (IOException ex) {
			return null;
		}
	}

	/**
	 * Add received message to incoming messages.
	 * 
	 * Only available for servers
	 * 
	 * @param exchange exchange with received request
	 */
	private void addReceivedExchange(CoapExchange exchange) {
		principal.set(exchange.advanced().getRequest().getSourceContext().getPeerIdentity());
		incoming.add(exchange.getRequestText());
	}

	/**
	 * Get principal.
	 * 
	 * @return principal. Maybe {@code null}.
	 */
	public Principal getPrincipal() {
		return principal.get();
	}

	/**
	 * Get received message.
	 * 
	 * Only available for servers.
	 * 
	 * @return received message. Maybe {@code null}.
	 * @throws IllegalStateException if it is not a server
	 */
	public String getReceivedMessage() {
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
	public String waitForReceivedMessage(long timeoutMillis) throws InterruptedException {
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
	 * @throws IllegalStateException if it is not a server
	 */
	public void assertReceivedData(String message, long timeoutMillis) throws InterruptedException {
		String received = waitForReceivedMessage(timeoutMillis);
		assertThat("Californium server missing message '" + message + "'!", received, is(notNullValue()));
		assertThat(received, is(message));
	}

	/**
	 * Assert, that the peer's principal is of expected type.
	 * 
	 * @param expectedPrincipalType expected principal type
	 * @since 3.0
	 */
	public void assertPrincipalType(final Class<?> expectedPrincipalType) {
		// assert that peer identity is of given type
		assertThat(principal.get(), instanceOf(expectedPrincipalType));
	}

	/**
	 * Create payload.
	 * 
	 * @param size size of payload.
	 * @return created payload.
	 * @since 3.0
	 */
	public byte[] createPayload(int size) {
		byte[] message = new byte[size];
		Arrays.fill(message, (byte) '#');
		for (int index = 0; index < message.length; ++index) {
			int page = index / 64;
			message[index] = (byte) Character.forDigit((page / 16) % 16, 16);
			++index;
			if (index < message.length) {
				message[index] = (byte) Character.forDigit(page % 16, 16);
				index += 62;
				if (index < message.length) {
					message[index] = (byte) '\n';
				}
			}
		}
		return message;
	}

	/**
	 * Create text payload.
	 * 
	 * @param size size of text payload.
	 * @return created text payload.
	 * @since 3.0
	 */
	public String createTextPayload(int size) {
		byte[] message = createPayload(size);
		return new String(message, StandardCharsets.US_ASCII);
	}
}
