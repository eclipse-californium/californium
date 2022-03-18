/*******************************************************************************
 * Copyright (c) 2022 RISE and others.
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
 *    Rikard Höglund (RISE)
 *    
 ******************************************************************************/
package org.eclipse.californium.plugtests.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.*;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.oscore.OSCoreResource;

/**
 * Defines a resource only reachable by using OSCORE. Its content is similar to
 * the DefaultTest resource.
 *
 */
public class Oscore extends OSCoreResource {

	public Oscore() {
		super("oscore", true);
		getAttributes().setTitle("Resource only accesible when using OSCORE");
	}

	@Override
	public void handleGET(CoapExchange exchange) {

		// Check: Type, Code

		StringBuilder payload = new StringBuilder();
		payload.append("OSCORE Resource");

		Request request = exchange.advanced().getRequest();
		payload.append(String.format("\nCode: %d (%s)\nMID: %d", request.getCode().value, request.getCode(),
				request.getMID()));

		if (request.getToken() != null) {
			payload.append("\nToken: ");
			payload.append(request.getTokenString());
		}

		if (payload.length() > 64) {
			payload.delete(62, payload.length());
			payload.append('»');
		}

		// complete the request
		exchange.setMaxAge(30);
		exchange.respond(CONTENT, payload.toString(), TEXT_PLAIN);
	}

	@Override
	public void handlePOST(CoapExchange exchange) {

		// Check: Type, Code, has Content-Type

		exchange.setLocationPath("/location1/location2/location3");
		exchange.respond(CREATED);
	}

	@Override
	public void handlePUT(CoapExchange exchange) {

		// Check: Type, Code, has Content-Type

		if (exchange.getRequestOptions().hasIfNoneMatch()) {
			exchange.respond(PRECONDITION_FAILED);
		} else {
			exchange.respond(CHANGED);
		}
	}

	@Override
	public void handleDELETE(CoapExchange exchange) {
		// complete the request
		exchange.respond(DELETED);
	}
}
