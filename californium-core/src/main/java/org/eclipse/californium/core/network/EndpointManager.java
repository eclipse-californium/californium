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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add getDefaultEndpoint(String scheme)
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.elements.tcp.TcpClientConnector;

/**
 * A factory for {@link Endpoint}s that can be used by clients for sending
 * outbound CoAP requests.
 *
 * The EndpointManager contains the default endpoint for coap (on port 5683) and
 * endpoint for other schemes (coaps, CoAP over DTLS, coap+tcp, COAP over TCP,
 * coaps+tcp, COAPS over TCP,). When an application serves only as client but
 * not server it can just use the default endpoint to send requests. When the
 * application sends a request by calling {@link Request#send()} the send method
 * sends itself over the default endpoint.
 * <p>
 * To make a server listen for requests on the default endpoint, call
 * 
 * <pre>
 * 
 * {
 * 	CoapServer server = new CoapServer();
 * }
 * </pre>
 * 
 * or more explicit
 * 
 * <pre>
 * 
 * {
 * 	Endpoint endpoint = EndpointManager.getEndpointManager().getDefaultEndpoint();
 * 	CoapServer server = new CoapServer();
 * 	server.addEndpoint(endpoint);
 * }
 * </pre>
 */
public class EndpointManager {

	/** The logger */
	private static final Logger LOGGER = Logger.getLogger(EndpointManager.class.getCanonicalName());

	/** The singleton manager instance */
	private static final EndpointManager manager = new EndpointManager();

	/**
	 * Gets the singleton manager.
	 *
	 * @return the endpoint manager
	 */
	public static EndpointManager getEndpointManager() {
		return manager;
	}

	/** Map of schemes to their default endpoints */
	private final Map<String, Endpoint> endpoints = new ConcurrentHashMap<String, Endpoint>();

	/**
	 * Get default endpoint for provided scheme. If not available, try to create
	 * one.
	 * 
	 * @param uriScheme scheme to select endpoint
	 * @return the default endpoint for the provided scheme, or null, if not
	 *         available
	 * @throws IllegalArgumentException if uriScheme is not supported
	 * 
	 * @see #getDefaultEndpoint()
	 * @see #setDefaultEndpoint(Endpoint)
	 * @see CoAP#isSupportedScheme
	 */
	public synchronized Endpoint getDefaultEndpoint(String uriScheme) {
		// default endpoints
		if (null == uriScheme) {
			uriScheme = CoAP.COAP_URI_SCHEME;
		}
		if (!CoAP.isSupportedScheme(uriScheme)) {
			throw new IllegalArgumentException("URI scheme " + uriScheme + " not supported!");
		}
		uriScheme = uriScheme.toLowerCase();
		Endpoint endpoint = endpoints.get(uriScheme);
		if (null == endpoint) {
			endpoint = createDefaultEndpoint(uriScheme);
		}
		return endpoint;
	}

	/**
	 * Set the provided endpoint as new default endpoint for its scheme. Destroy
	 * the old default endpoint for that scheme, if available, and start the new
	 * endpoint, if not already started.
	 *
	 * @param newEndpoint new default endpoint.
	 * @throws IllegalArgumentException, if the uri scheme of the provided new
	 *             endpoint is not supported.
	 * @throws NullPointerException, if the provided new endpoint is null.
	 * @see #getDefaultEndpoint()
	 * @see #setDefaultEndpoint(Endpoint)
	 * @see CoAP#isSupportedScheme
	 */
	public synchronized void setDefaultEndpoint(Endpoint newEndpoint) {
		if (null == newEndpoint) {
			throw new NullPointerException("endpoint required!");
		}
		String uriScheme = newEndpoint.getUri().getScheme();
		if (!CoAP.isSupportedScheme(uriScheme)) {
			throw new IllegalArgumentException("URI scheme " + uriScheme + " not supported!");
		}
		Endpoint oldEndpoint = endpoints.put(uriScheme, newEndpoint);
		if (null != oldEndpoint) {
			oldEndpoint.destroy();
		}
		if (!newEndpoint.isStarted()) {
			try {
				newEndpoint.start();
			} catch (IOException e) {
				LOGGER.log(Level.SEVERE, "Could not start new " + uriScheme + " endpoint", e);
			}
		}
	}

	/**
	 * Create the default endpoint for the provided uri scheme.
	 * 
	 * @param uriScheme uri scheme
	 * @return create endpoint, or null, if endpoint would require more
	 *         information (e.g. security context)
	 */
	private Endpoint createDefaultEndpoint(String uriScheme) {
		Endpoint endpoint;
		NetworkConfig config = NetworkConfig.getStandard();

		if (CoAP.COAP_SECURE_URI_SCHEME.equalsIgnoreCase(uriScheme)) {
			LOGGER.config("Secure endpoint must be injected via setDefaultEndpoint(Scheme, Endpoint) to use the proper credentials");
			return null;
		} else if (CoAP.COAP_TCP_URI_SCHEME.equalsIgnoreCase(uriScheme)) {
			TcpClientConnector connector = new TcpClientConnector(config.getInt(NetworkConfig.Keys.TCP_WORKER_THREADS),
					config.getInt(NetworkConfig.Keys.TCP_CONNECT_TIMEOUT),
					config.getInt(NetworkConfig.Keys.TCP_CONNECTION_IDLE_TIMEOUT));
			endpoint = new CoapEndpoint(connector, config);
		} else if (CoAP.COAP_SECURE_TCP_URI_SCHEME.equalsIgnoreCase(uriScheme)) {
			LOGGER.config("Secure tcp endpoint must be injected via setDefaultEndpoint(Scheme, Endpoint) to use the proper credentials");
			return null;
		} else {
			endpoint = new CoapEndpoint();
		}
		try {
			endpoint.start();
			LOGGER.log(Level.INFO, "Created implicit endpoint {0} for {1}",
					new Object[] { endpoint.getUri(), uriScheme });
		} catch (IOException e) {
			LOGGER.log(Level.SEVERE, "Could not create " + uriScheme + " endpoint", e);
		}
		endpoints.put(uriScheme, endpoint);

		return endpoint;
	}

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
	 * 
	 * @see #getDefaultEndpoint(String)
	 * @see #setDefaultEndpoint(Endpoint)
	 */
	public Endpoint getDefaultEndpoint() {
		return getDefaultEndpoint(CoAP.COAP_URI_SCHEME);
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
	 * Clear the state for deduplication in all default endpoints.
	 */
	public static void clear() {
		EndpointManager it = getEndpointManager();
		for (Endpoint endpoint : it.endpoints.values()) {
			endpoint.clear();
		}
	}

	// Needed for JUnit Tests to ensure, that the defaults endpoints are reseted
	// to their initial values.
	/**
	 * Reset default endpoints. Destroy all default endpoints and clear their set.
	 */
	public static void reset() {
		EndpointManager it = getEndpointManager();
		for (Endpoint endpoint : it.endpoints.values()) {
			endpoint.destroy();
		}
		it.endpoints.clear();
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
			if (exchange == null) {
				throw new NullPointerException("no CoAP exchange!");
			}
			if (exchange.getRequest() == null) {
				throw new NullPointerException("no CoAP request!");
			}
			if (response == null) {
				throw new NullPointerException("no CoAP response!");
			}
			exchange.getRequest().setResponse(response);
		}
	}
}
