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
public class Separate extends CoapResource {

	public Separate() {
		super("separate");
		getAttributes().setTitle("Resource which cannot be served immediately and which cannot be acknowledged in a piggy-backed way");
	}

	@Override
	public void handleGET(CoapExchange exchange) {

		// promise the client that this request will be acted upon by sending an Acknowledgement
		exchange.accept();

		// do the time-consuming computation
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
		}

		// get request to read out details
		Request request = exchange.advanced().getRequest();

		String payload = String.format("Type: %d (%s)\nCode: %d (%s)\nMID: %d\n",
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
