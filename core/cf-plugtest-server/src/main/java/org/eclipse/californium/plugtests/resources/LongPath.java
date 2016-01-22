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
import org.eclipse.californium.core.server.resources.Resource;

/**
 * This resource implements a test of specification for the
 * ETSI IoT CoAP Plugtests, London, UK, 7--9 Mar 2014.
 */
public class LongPath extends CoapResource {

	public LongPath() {
		this("seg1");

		Resource seg2 = new LongPath("seg2");
		Resource seg3 = new LongPath("seg3");

		add(seg2);
		seg2.add(seg3);
	}
	
	public LongPath(String name) {
		super(name);
		getAttributes().setTitle("Long path resource");
	}

	@Override
	public void handleGET(CoapExchange exchange) {
		Request request = exchange.advanced().getRequest();
		
		String payload = String.format("Long path resource\n" +
									   "Type: %d (%s)\nCode: %d (%s)\nMID: %d",
									   request.getType().value,
									   request.getType(),
									   request.getCode().value,
									   request.getCode(),
									   request.getMID()
									  );
		
		// complete the request
		exchange.respond(CONTENT, payload, TEXT_PLAIN);
	}
}
