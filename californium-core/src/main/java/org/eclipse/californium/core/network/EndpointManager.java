/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - log default_secure_endpoint
 *                                                    instead of default_endpoint
 *                                                    in setDefaultSecureEndpoint
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use Logger's message formatting instead of
 *                                                    explicit String concatenation
 *    Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add reset() for junit tests
 ******************************************************************************/
package org.eclipse.californium.core.network;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.elements.tcp.TcpClientConnector;
import org.eclipse.californium.elements.tcp.TlsClientConnector;

import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A factory for {@link Endpoint}s that can be used by clients for sending
 * outbound CoAP requests.
 *
 * The EndpointManager contains the default endpoint for coap (on port 5683) and
 * coaps (CoAP over DTLS). When an application serves only as client but not
 * server it can just use the default endpoint to send requests. When the
 * application sends a request by calling {@link Request#send()} the send method
 * sends itself over the default endpoint.
 * <p>
 * To make a server listen for requests on the default endpoint, call
 * 
 * <pre>
 * {
 * 	&#64;code
 * 	CoapServer server = new CoapServer();
 * }
 * </pre>
 * 
 * or more explicit
 * 
 * <pre>
 * {
 * 	&#64;code
 * 	Endpoint endpoint = EndpointManager.getEndpointManager().getDefaultEndpoint();
 * 	CoapServer server = new CoapServer();
 * 	server.addEndpoint(endpoint);
 * }
 * </pre>
 */
public class EndpointManager {

	/** The logger */
	private final static Logger LOGGER = Logger.getLogger(EndpointManager.class.getCanonicalName());

	/** The singleton manager instance */
	private static EndpointManager manager = new EndpointManager();

	/**
	 * Gets the singleton manager.
	 *
	 * @return the endpoint manager
	 */
	public static EndpointManager getEndpointManager() {
		return manager;
	}

	/** The default endpoint for CoAP */
	private Endpoint default_endpoint;

	/** The default endpoint for secure CoAP */
	private Endpoint default_secure_endpoint;

	/** Endpoint for CoAP over TCP. */
	private Endpoint default_tcp_endpoint;

	/** Endponit for CoAP over TLS. */
	private Endpoint default_secure_tpc_endpoint;

	/**
	 * Gets the default endpoint for implicit use by clients. By default, the
	 * endpoint has a single-threaded executor and is started. It is possible to
	 * send requests over the endpoint and receive responses. It is not possible
	 * to receive requests by default. If a request arrives at the endpoint, the
	 * {@link ClientMessageDeliverer} rejects it. To receive requests, the
	 * endpoint must be added to an instance of {@link CoapServer}. Be careful
	 * with stopping or destroying the default endpoint as it affects all
	 * messages that are supposed to be sent over it.
	 *
	 * @return the default endpoint
	 */
	public synchronized Endpoint getDefaultEndpoint() {
		if (default_endpoint == null) {
			createDefaultEndpoint();
		}
		return default_endpoint;
	}

	/**
	 * Gets the default tcp endpoint for implicit use by client. By default, the
	 * tcp endpoint has single worker thread, and uses default TCP settings. Be
	 * careful to stop default tcp endpoint, as it stops all messages sent over
	 * it.
	 */
	public Endpoint getDefaultTcpEndpoint() {
		if (default_tcp_endpoint == null) {
			createTcpEndpoint();
		}
		return default_tcp_endpoint;
	}

	/**
	 * Gets the default tcp endpoint for implicit use by client. By default, the
	 * tcp endpoint has single worker thread, and uses default TCP settings. Be
	 * careful to stop default tcp endpoint, as it stops all messages sent over
	 * it.
	 */
	public Endpoint getDefaultSecureTcpEndpoint() {
		if (default_secure_tpc_endpoint == null) {
			createSecureTcpEndpoint();
		}
		return default_secure_tpc_endpoint;
	}

	/*
	 * Creates an endpoint with the wildcard address (::0) and an ephemeral port.
	 * The new endpoint gets a client message deliverer and is started. To
	 * listen on specific interfaces or ports, set the default endpoint
	 * manually. To distinguish different interfaces, one endpoint per interface
	 * must be added.
	 */
	private synchronized void createDefaultEndpoint() {
		if (default_endpoint != null)
			return;

		default_endpoint = new CoapEndpoint();

		try {
			default_endpoint.start();
			LOGGER.log(Level.INFO, "Created implicit default endpoint {0}", default_endpoint.getAddress());
		} catch (IOException e) {
			LOGGER.log(Level.SEVERE, "Could not create default endpoint", e);
		}
	}

	private synchronized void createTcpEndpoint() {
		if (default_tcp_endpoint != null)
			return;

		NetworkConfig config = NetworkConfig.getStandard();
		TcpClientConnector connector = new TcpClientConnector(config.getInt(NetworkConfig.Keys.TCP_WORKER_THREADS),
				config.getInt(NetworkConfig.Keys.TCP_CONNECT_TIMEOUT),
				config.getInt(NetworkConfig.Keys.TCP_CONNECTION_IDLE_TIMEOUT));

		default_tcp_endpoint = new CoapEndpoint(connector, config);
		try {
			default_tcp_endpoint.start();
			LOGGER.log(Level.INFO, "Created implicit tcp endpoint {0}", default_tcp_endpoint.getAddress());
		} catch (IOException e) {
			LOGGER.log(Level.SEVERE, "Could not create tcp endpoint", e);
		}
	}

	private synchronized void createSecureTcpEndpoint() {
		if (default_secure_tpc_endpoint != null)
			return;

		NetworkConfig config = NetworkConfig.getStandard();
		TlsClientConnector connector = new TlsClientConnector(config.getInt(NetworkConfig.Keys.TCP_WORKER_THREADS),
				config.getInt(NetworkConfig.Keys.TCP_CONNECT_TIMEOUT),
				config.getInt(NetworkConfig.Keys.TCP_CONNECTION_IDLE_TIMEOUT));

		default_secure_tpc_endpoint = new CoapEndpoint(connector, config);
		try {
			default_secure_tpc_endpoint.start();
			LOGGER.log(Level.INFO, "Created implicit secure tcp endpoint {0}",
					default_secure_tpc_endpoint.getAddress());
		} catch (IOException e) {
			LOGGER.log(Level.SEVERE, "Could not create secure tcp endpoint", e);
		}
	}

	/**
	 * Configures a new secure tcp endpoint to use by default. Any old tcp
	 * endpoint is destroyed.
	 *
	 * @param endpoint
	 *            the new default secure tcp endpoint.
	 */
	public synchronized void setTcpEndpoint(Endpoint endpoint) {
		if (this.default_tcp_endpoint != null) {
			this.default_tcp_endpoint.destroy();
		}

		LOGGER.log(Level.CONFIG, "{0} becomes tcp endpoint", endpoint.getAddress());

		this.default_tcp_endpoint = endpoint;

		if (!this.default_tcp_endpoint.isStarted()) {
			try {
				default_tcp_endpoint.start();
			} catch (IOException e) {
				LOGGER.log(Level.SEVERE, "Could not start new tcp endpoint", e);
			}
		}
	}

	/**
	 * Configures a new secure tcp endpoint to use by default. Any old tcp
	 * endpoint is destroyed.
	 *
	 * @param endpoint
	 *            the new default secure tcp endpoint.
	 */
	public synchronized void setSecureTcpEndpoint(Endpoint endpoint) {
		if (this.default_secure_tpc_endpoint != null) {
			this.default_secure_tpc_endpoint.destroy();
		}

		LOGGER.log(Level.CONFIG, "{0} becomes secure tcp endpoint", endpoint.getAddress());

		this.default_secure_tpc_endpoint = endpoint;

		if (!this.default_secure_tpc_endpoint.isStarted()) {
			try {
				default_secure_tpc_endpoint.start();
			} catch (IOException e) {
				LOGGER.log(Level.SEVERE, "Could not start new secure tcp endpoint", e);
			}
		}
	}

	/**
	 * Configures a new default endpoint. Any old default endpoint is destroyed.
	 * 
	 * @param endpoint
	 *            the new default endpoint
	 */
	public synchronized void setDefaultEndpoint(Endpoint endpoint) {

		if (this.default_endpoint != null) {
			this.default_endpoint.destroy();
		}

		LOGGER.log(Level.CONFIG, "{0} becomes default endpoint", endpoint.getAddress());

		this.default_endpoint = endpoint;

		if (!this.default_endpoint.isStarted()) {
			try {
				default_endpoint.start();
			} catch (IOException e) {
				LOGGER.log(Level.SEVERE, "Could not start new default endpoint", e);
			}
		}
	}

	/**
	 * Gets the default endpoint for coaps for implicit use by clients. By
	 * default, the endpoint has a single-threaded executor and is started. It
	 * is possible to send requests over the endpoint and receive responses. It
	 * is not possible to receive requests by default. If a request arrives at
	 * the endpoint, the {@link ClientMessageDeliverer} rejects it. To receive
	 * requests, the endpoint must be added to an instance of
	 * {@link CoapServer}. Be careful with stopping or destroying the default
	 * endpoint as it affects all messages that are supposed to be sent over it.
	 *
	 * @return the default endpoint
	 */
	public synchronized Endpoint getDefaultSecureEndpoint() {
		try {
			if (default_secure_endpoint == null) {
				createDefaultSecureEndpoint();
			}
		} catch (Exception e) {
			LOGGER.log(Level.SEVERE, "Exception while getting the default secure endpoint", e);
		}
		return default_secure_endpoint;
	}

	private synchronized void createDefaultSecureEndpoint() {
		if (default_secure_endpoint != null)
			return;

		LOGGER.config("Secure endpoint must be injected via setDefaultSecureEndpoint()");
	}

	/**
	 * Configures a new default secure endpoint. Any old default endpoint is
	 * destroyed.
	 * 
	 * @param endpoint
	 *            the new default endpoint
	 */
	public synchronized void setDefaultSecureEndpoint(Endpoint endpoint) {

		if (this.default_secure_endpoint != null) {
			this.default_secure_endpoint.destroy();
		}

		this.default_secure_endpoint = endpoint;

		if (!this.default_secure_endpoint.isStarted()) {
			try {
				default_secure_endpoint.start();
				LOGGER.log(Level.INFO, "Started new default secure endpoint {0}", default_secure_endpoint.getAddress());
			} catch (IOException e) {
				LOGGER.log(Level.SEVERE, "Could not start new default secure endpoint", e);
			}
		}
	}

	public Collection<InetAddress> getNetworkInterfaces() {
		Collection<InetAddress> interfaces = new LinkedList<InetAddress>();
		try {
			Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
			while (nets.hasMoreElements()) {
				Enumeration<InetAddress> inetAddresses = nets.nextElement().getInetAddresses();
				while (inetAddresses.hasMoreElements()) {
					interfaces.add(inetAddresses.nextElement());
				}
			}
		} catch (SocketException e) {
			LOGGER.log(Level.SEVERE, "Could not fetch all interface addresses", e);
		}
		return interfaces;
	}

	// Needed for JUnit Tests to remove state for deduplication
	/**
	 * Clear the state for deduplication in both default endpoints.
	 */
	public static void clear() {
		EndpointManager it = getEndpointManager();
		if (it.default_endpoint != null)
			it.default_endpoint.clear();
		if (it.default_secure_endpoint != null)
			it.default_secure_endpoint.clear();
		if (it.default_tcp_endpoint != null)
			it.default_tcp_endpoint.clear();
		if (it.default_secure_tpc_endpoint != null)
			it.default_secure_tpc_endpoint.clear();
	}

	// Needed for JUnit Tests to ensure, that the defaults endpoints are reseted
	// to their initial values.
	/**
	 * Reset default endpoints. Destroy all default endpoints and clear their
	 * set.
	 */
	public static void reset() {
		EndpointManager it = getEndpointManager();
		if (it.default_endpoint != null) {
			it.default_endpoint.destroy();
			it.default_endpoint = null;
		}
		if (it.default_secure_endpoint != null) {
			it.default_secure_endpoint.destroy();
			it.default_secure_endpoint = null;
		}
		if (it.default_tcp_endpoint != null) {
			it.default_tcp_endpoint.destroy();
			it.default_tcp_endpoint = null;
		}
		if (it.default_secure_tpc_endpoint != null) {
			it.default_secure_tpc_endpoint.destroy();
			it.default_secure_tpc_endpoint = null;
		}
	}

	/**
	 * ClientMessageDeliverer is a simple implementation of the interface
	 * {@link MessageDeliverer}. When a response arrives it adds it to the
	 * corresponding request. If requests arrive, however, the
	 * ClientMessageDeliverer rejects them.
	 */
	public static class ClientMessageDeliverer implements MessageDeliverer {

		@Override
		public void deliverRequest(Exchange exchange) {
			LOGGER.severe("Default endpoint without CoapServer has received a request.");
			exchange.sendReject();
		}

		@Override
		public void deliverResponse(Exchange exchange, Response response) {
			if (exchange == null)
				throw new NullPointerException();
			if (exchange.getRequest() == null)
				throw new NullPointerException();
			if (response == null)
				throw new NullPointerException();
			exchange.getRequest().setResponse(response);
		}
	}
}
