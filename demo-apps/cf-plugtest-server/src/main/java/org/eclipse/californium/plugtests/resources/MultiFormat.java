/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.plugtests.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.*;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.*;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;

import com.upokecenter.cbor.CBORObject;

/**
 * This resource implements a test of specification for the ETSI IoT CoAP Plugtests, London, UK, 7--9 Mar 2014.
 */
public class MultiFormat extends CoapResource {

	public MultiFormat() {
		super("multi-format");
		getAttributes().setTitle("Resource that exists in different content formats (text/plain utf8 and application/xml)");
		getAttributes().addContentType(TEXT_PLAIN);
		getAttributes().addContentType(APPLICATION_XML);
		getAttributes().addContentType(APPLICATION_JSON);
		getAttributes().addContentType(APPLICATION_CBOR);
	}

	@Override
	public void handleGET(CoapExchange exchange) {

		// get request to read out details
		Request request = exchange.advanced().getRequest();

		// successively create response
		Response response = new Response(CONTENT);

		String format = null;
		switch (exchange.getRequestOptions().getAccept()) {
			case UNDEFINED:
			case TEXT_PLAIN:
				response.getOptions().setContentFormat(TEXT_PLAIN);
				format = "Status type: \"%s\"\nCode: \"%s\"\nMID: %d\nAccept: %d";
				break;

			case APPLICATION_XML:
				response.getOptions().setContentFormat(APPLICATION_XML);
				format = "<msg type=\"%s\" code=\"%s\" mid=\"%d\" accept=\"%d\" />"; // should fit 64 bytes
				break;

			case APPLICATION_JSON:
				response.getOptions().setContentFormat(APPLICATION_JSON);
				format = "{ \"type\":\"%s\", \"code\":\"%s\", \"mid\":%d, \"accept\":%d }"; // should fit 64 bytes
				break;

			case APPLICATION_CBOR:
				response.getOptions().setContentFormat(APPLICATION_CBOR);
				CBORObject map = CBORObject.NewMap();
				map.set(CBORObject.FromObject("type"), CBORObject.FromObject(request.getType().name()));
				map.set(CBORObject.FromObject("code"), CBORObject.FromObject(request.getCode().name()));
				map.set(CBORObject.FromObject("mid"), CBORObject.FromObject(request.getMID()));
				map.set(CBORObject.FromObject("accept"), CBORObject.FromObject(request.getOptions().getAccept()));
				response.setPayload(map.EncodeToBytes());
				// should fit 64 bytes
				break;

			default:
				response = new Response(NOT_ACCEPTABLE);
				format = "text/plain, application/xml, application/json, or application/cbor only";
				break;
		}

		if (format != null) {
			response.setPayload( 
					String.format(format, 
						request.getType(), 
						request.getCode(), 
						request.getMID(),
						request.getOptions().getAccept()) 
				);
		}
		exchange.respond(response);
	}
}
