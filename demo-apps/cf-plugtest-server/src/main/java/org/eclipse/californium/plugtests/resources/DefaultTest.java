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
 * This resource implements a test of specification for the ETSI IoT CoAP Plugtests, London, UK, 7--9 Mar 2014.
 */
public class DefaultTest extends CoapResource {

	public DefaultTest() {
		super("test");
		getAttributes().setTitle("Default test resource");
	}

	@Override
	public void handleGET(CoapExchange exchange) {

		// Check: Type, Code

		StringBuilder payload = new StringBuilder();

		Request request = exchange.advanced().getRequest();
		payload.append(String.format("Type: %d (%s)\nCode: %d (%s)\nMID: %d", 
				request.getType().value, 
				request.getType(), 
				request.getCode().value, 
				request.getCode(), 
				request.getMID()));

		if (request.getToken().length > 0) {
			payload.append("\nToken: ");
			StringBuilder tok = new StringBuilder(request.getToken()==null?"null":"");
			if (request.getToken()!=null) for(byte b:request.getToken()) tok.append(String.format("%02x", b&0xff));
			payload.append(tok);
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
