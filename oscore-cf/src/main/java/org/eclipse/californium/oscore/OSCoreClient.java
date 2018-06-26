/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
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
 *    Joakim Brorsson
 *    Tobias Andersson (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.Endpoint;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * The Class OSCoreClient which extends the CoapClient, creates and sets the
 * OSCoreEndpoint.
 * 
 * Disclaimer: can use the EndpointManger, see CoapClient.
 *
 */
public class OSCoreClient extends CoapClient {

	/** The logger */
	private static final Logger LOGGER = LoggerFactory.getLogger(OSCoreClient.class.getName());

	private static final byte[] EMPTY = new byte[0];

	private static OSCoreEndpoint newEndpoint() {
		OSCoreEndpoint ep = new OSCoreEndpoint();
		try {
			ep.start();
		} catch (IOException e) {
			LOGGER.error("Could not create endpoint: " + e.getMessage());
		}
		return ep;
	}

	/**
	 * Constructs a new CoapClient that has no destination URI yet.
	 * 
	 * @param db the OSCore context database
	 */
	public OSCoreClient(OSCoreCtx ctx) {
		super();
		setEndpoint(newEndpoint());
	}

	/**
	 * Constructs a new CoapClient that sends requests to the specified URI.
	 *
	 * @param uri the uri
	 * @param db the OSCore context database
	 */
	public OSCoreClient(String uri) {
		super(uri);
		setEndpoint(newEndpoint());
	}

	/**
	 * Constructs a new CoapClient that sends request to the specified URI.
	 *
	 * @param uri the uri
	 * @param db the OSCore context database
	 */
	public OSCoreClient(URI uri) {
		super(uri);
		setEndpoint(newEndpoint());
	}

	/**
	 * Constructs a new CoapClient with the specified scheme, host, port and
	 * path as URI.
	 * 
	 * @param db the OSCore context database
	 * @param scheme the scheme
	 * @param host the host
	 * @param port the port
	 * @param path the path
	 */
	public OSCoreClient(String scheme, String host, int port, String... path) {
		super(scheme, host, port, path);
		setEndpoint(newEndpoint());
	}

	/**
	 * Sends the specified request over the specified endpoint.
	 *
	 * @param request the request
	 * @param outEndpoint the endpoint
	 * @return the request
	 */
	@Override
	protected Request send(Request request, Endpoint outEndpoint) {
		OSCoreEndpoint ep = (OSCoreEndpoint) outEndpoint;
		request.getOptions().setOscore(EMPTY);
		ep.sendRequest(request);
		return request;
	}

	@Override
	public CoapClient setEndpoint(Endpoint endpoint) {
		if (endpoint instanceof OSCoreEndpoint) {
			LOGGER.info("establishing an OSCoreEndpoint");
		} else {
			LOGGER.info("establishing an non-OSCoreEndpoint");
		}
		synchronized (this) {
			this.endpoint = endpoint;
		}
		if (!endpoint.isStarted()) {
			try {
				endpoint.start();
				LOGGER.info("started set client endpoint {}", endpoint.getAddress());
			} catch (IOException e) {
				LOGGER.error("could not set and start client endpoint", e);
			}

		}

		return this;
	}
}
