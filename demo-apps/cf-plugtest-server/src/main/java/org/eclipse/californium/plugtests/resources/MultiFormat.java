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
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;

/**
 * This resource implements a test of specification for the ETSI IoT CoAP Plugtests, London, UK, 7--9 Mar 2014.
 */
public class MultiFormat extends CoapResource {

	public MultiFormat() {
		super("multi-format");
		getAttributes().setTitle("Resource that exists in different content formats (text/plain utf8 and application/xml)");
		getAttributes().addContentType(0);
		getAttributes().addContentType(41);
	}

	@Override
	public void handleGET(CoapExchange exchange) {
		
		// get request to read out details
		Request request = exchange.advanced().getRequest();
		
		// successively create response
		Response response = new Response(CONTENT);

		String format = "";
		switch (exchange.getRequestOptions().getAccept()) {
			case UNDEFINED:
			case TEXT_PLAIN:
				response.getOptions().setContentFormat(TEXT_PLAIN);
				format = "Status type: \"%s\"\nCode: \"%s\"\nMID: \"%s\"\nAccept: \"%s\"";
				break;
	
			case APPLICATION_XML:
				response.getOptions().setContentFormat(APPLICATION_XML);
				format = "<msg type=\"%s\" code=\"%s\" mid=%s accept=\"%s\"/>"; // should fit 64 bytes
				break;
	
			default:
				response = new Response(NOT_ACCEPTABLE);
				format = "text/plain or application/xml only";
				break;
		}
		
		response.setPayload( 
				String.format(format, 
						request.getType(), 
						request.getCode(), 
						request.getMID(),
						MediaTypeRegistry.toString(request.getOptions().getAccept())) 
				);

		exchange.respond(response);
	}

}
