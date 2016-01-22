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
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - log default_secure_endpoint
 *                                                    instead of default_endpoint 
 *                                                    in setDefaultSecureEndpoint
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.MessageDeliverer;

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
 * <pre>{@code
 *  CoapServer server = new CoapServer();
 * }</pre>
 * or more explicit
 * <pre>{@code
 *  Endpoint endpoint = EndpointManager.getEndpointManager().getDefaultEndpoint();
 *  CoapServer server = new CoapServer();
 *  server.addEndpoint(endpoint);
 * }</pre>
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
	
	/**
	 * Gets the default endpoint for implicit use by clients. By default, the
	 * endpoint has a single-threaded executor and is started. It is possible to
	 * send requests over the endpoint and receive responses. It is not possible
	 * to receive requests by default. If a request arrives at the endpoint, the
	 * {@link ClientMessageDeliverer} rejects it. To receive requests, the
	 * endpoint must be added to an instance of {@link CoapServer}. Be careful with
	 * stopping or destroying the default endpoint as it affects all messages
	 * that are supposed to be sent over it.
	 * 
	 * @return the default endpoint
	 */
	public Endpoint getDefaultEndpoint() {
		if (default_endpoint == null) {
			createDefaultEndpoint();
		}
		return default_endpoint;
	}

	/*
	 * Creates an endpoint with the wildcard adress (::0) and an ephemeral port.
	 * The new endpoint gets a client message deliverer and is started.
	 * To listen on specific interfaces or ports, set the default endpoint manually.
	 * To distinguish different interfaces, one endpoint per interface must be added.
	 */
	private synchronized void createDefaultEndpoint() {
		if (default_endpoint != null) return;
		
		default_endpoint = new CoapEndpoint();
		
		try {
			default_endpoint.start();
			LOGGER.log(Level.INFO, "Created implicit default endpoint " + default_endpoint.getAddress());
		} catch (IOException e) {
			LOGGER.log(Level.SEVERE, "Could not create default endpoint", e);
		}
	}
	
	/**
	 * Configures a new default endpoint. Any old default endpoint is destroyed.
	 * @param endpoint the new default endpoint
	 */
	public void setDefaultEndpoint(Endpoint endpoint) {
		
		if (this.default_endpoint!=null) {
			this.default_endpoint.destroy();
		}

		LOGGER.config(endpoint.getAddress()+" becomes default endpoint");
		
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
	 * Gets the default endpoint for coaps for implicit use by clients.
	 * By default, the endpoint has a single-threaded executor and is started.
	 * It is possible to send requests over the endpoint and receive responses.
	 * It is not possible to receive requests by default. If a request arrives
	 * at the endpoint, the {@link ClientMessageDeliverer} rejects it. To
	 * receive requests, the endpoint must be added to an instance of
	 * {@link CoapServer}. Be careful with stopping or destroying the default
	 * endpoint as it affects all messages that are supposed to be sent over it.
	 * 
	 * @return the default endpoint
	 */
	public Endpoint getDefaultSecureEndpoint() {
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
		if (default_secure_endpoint != null) return;
		
		LOGGER.config("Secure endpoint must be injected via setDefaultSecureEndpoint()");	
	}

	/**
	 * Configures a new default secure endpoint. Any old default endpoint is destroyed.
	 * @param endpoint the new default endpoint
	 */
	public void setDefaultSecureEndpoint(Endpoint endpoint) {

		if (this.default_secure_endpoint!=null) {
			this.default_secure_endpoint.destroy();
		}
		
		this.default_secure_endpoint = endpoint;

		if (!this.default_secure_endpoint.isStarted()) {
			try {
				default_secure_endpoint.start();
				LOGGER.log(Level.INFO, "Started new default secure endpoint " + default_secure_endpoint.getAddress());
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
	}
	
	/**
	 * ClientMessageDeliverer is a simple implementation of the interface
	 * {@link MessageDeliverer}. When a response arrives it adds it to the
	 * corresponding request. If requests arrive, however, the
	 * ClientMessageDeliverer rejects them.
	 */
	public static class ClientMessageDeliverer implements MessageDeliverer {
		
		/* (non-Javadoc)
		 * @see ch.inf.vs.californium.MessageDeliverer#deliverRequest(ch.inf.vs.californium.network.Exchange)
		 */
		@Override
		public void deliverRequest(Exchange exchange) {
			LOGGER.severe("Default endpoint without CoapServer has received a request.");
			exchange.sendReject();
		}
		
		/* (non-Javadoc)
		 * @see ch.inf.vs.californium.MessageDeliverer#deliverResponse(ch.inf.vs.californium.network.Exchange, ch.inf.vs.californium.coap.Response)
		 */
		@Override
		public void deliverResponse(Exchange exchange, Response response) {
			if (exchange == null) throw new NullPointerException();
			if (exchange.getRequest() == null) throw new NullPointerException();
			if (response == null) throw new NullPointerException();
			exchange.getRequest().setResponse(response);
		}
	}
}
