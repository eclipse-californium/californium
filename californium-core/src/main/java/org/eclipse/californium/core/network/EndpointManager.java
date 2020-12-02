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
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - getDefaultEndpoint throws 
 *                                                    IllegalStateException
 *                                                    instead of returning null
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.io.IOException;
import java.net.URI;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.MessageDeliverer;

/**
 * A manager and coap-factory for {@link Endpoint}s that can be used by clients for sending
 * outbound CoAP requests.
 *
 * The EndpointManager contains the default endpoint for coap (on port 5683) and
 * endpoint for other schemes (coaps, CoAP over DTLS, coap+tcp, COAP over TCP,
 * coaps+tcp, COAPS over TCP,), if these additional endpoints are previously set. 
 * When an application serves only as client but not as server it can just use the
 * default endpoint to send requests. When the application sends a request by calling
 * {@link Request#send()} the send method sends itself over the default endpoint.
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
	private static final Logger LOGGER = LoggerFactory.getLogger(EndpointManager.class);

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
	 * Get default endpoint for provided scheme. 
	 * 
	 * If not available, try to create one, if the provide uriScheme is simple "coap".
	 * 
	 * @param uriScheme scheme to select endpoint
	 * @return the default endpoint for the provided scheme
	 * @throws IllegalArgumentException if uriScheme is not generally not supported
	 * @throws IllegalStateException if uriScheme requires a preset connector but no 
	 *                               connector was set previously
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
			if (CoAP.COAP_SECURE_URI_SCHEME.equalsIgnoreCase(uriScheme)) {
				throw new IllegalStateException("URI scheme " + uriScheme + " requires a previous set connector!");
			} else if (CoAP.COAP_TCP_URI_SCHEME.equalsIgnoreCase(uriScheme)) {
				throw new IllegalStateException("URI scheme " + uriScheme + " requires a previous set connector!");
			} else if (CoAP.COAP_SECURE_TCP_URI_SCHEME.equalsIgnoreCase(uriScheme)) {
				throw new IllegalStateException("URI scheme " + uriScheme + " requires a previous set connector!");
			} else {
				endpoint = new CoapEndpoint.Builder().build();
			}
			try {
				endpoint.start();
				LOGGER.info("created implicit endpoint {} for {}", endpoint.getUri(), uriScheme);
			} catch (IOException e) {
				LOGGER.error("could not create {} endpoint", uriScheme, e);
			}
			endpoints.put(uriScheme, endpoint);
		}
		return endpoint;
	}

	/**
	 * Set the provided endpoint as new default endpoint for its scheme. Destroy
	 * the old default endpoint for that scheme, if available, and start the new
	 * endpoint, if not already started.
	 *
	 * @param newEndpoint new default endpoint.
	 * @throws IllegalArgumentException if the uri scheme of the provided new
	 *             endpoint is not supported.
	 * @throws NullPointerException if the provided new endpoint is null.
	 * @see #getDefaultEndpoint()
	 * @see #setDefaultEndpoint(Endpoint)
	 * @see CoAP#isSupportedScheme
	 */
	public synchronized void setDefaultEndpoint(Endpoint newEndpoint) {
		if (null == newEndpoint) {
			throw new NullPointerException("endpoint required!");
		}
		URI uri = newEndpoint.getUri();
		if (null == uri) {
			throw new IllegalArgumentException("Endpoint protocol not supported!");
		}
		String uriScheme = uri.getScheme();
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
				LOGGER.error("could not start new {} endpoint", uriScheme, e);
			}
		}
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
	 * Reset default endpoints. Destroy all default endpoints and clear their
	 * set.
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
			LOGGER.error("Default endpoint without CoapServer has received a request.");
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
