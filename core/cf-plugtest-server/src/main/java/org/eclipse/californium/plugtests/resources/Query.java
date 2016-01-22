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
 ******************************************************************************/
package org.eclipse.californium.plugtests.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.*;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.*;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.server.resources.CoapExchange;

/**
 * This resource implements a test of specification for the
 * ETSI IoT CoAP Plugtests, London, UK, 7--9 Mar 2014.
 */
public class Query extends CoapResource {

	public Query() {
		super("query");
		getAttributes().setTitle("Resource accepting query parameters");
	}

	@Override
	public void handleGET(CoapExchange exchange) {

		// get request to read out details
		Request request = exchange.advanced().getRequest();
		
		StringBuilder payload = new StringBuilder();
		payload.append(String.format("Type: %d (%s)\nCode: %d (%s)\nMID: %d\n",
									 request.getType().value,
									 request.getType(),
									 request.getCode().value,
									 request.getCode(),
									 request.getMID()
									));
		payload.append("?").append(request.getOptions().getUriQueryString());
		if (payload.length()>64) {
			payload.delete(63, payload.length());
			payload.append('»');
		}
		
		// complete the request
		exchange.respond(CONTENT, payload.toString(), TEXT_PLAIN);
	}
}
