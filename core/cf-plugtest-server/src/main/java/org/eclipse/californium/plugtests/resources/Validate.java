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

import java.nio.ByteBuffer;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.*;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.*;

/**
 * This resource implements a test of specification for the ETSI IoT CoAP Plugtests, London, UK, 7--9 Mar 2014.
 */
public class Validate extends CoapResource {

	private byte[] data = null;
	private int dataCf = TEXT_PLAIN;
	private byte[] etag = {0,0,0,0};

	public Validate() {
		super("validate");
		getAttributes().setTitle("Resource which varies");
	}

	@Override
	public void handleGET(CoapExchange exchange) {
		
		// get request to read out details
		Request request = exchange.advanced().getRequest();

		// successively create response
		Response response;
		
		if (exchange.getRequestOptions().containsETag(etag)) {
			
			response = new Response(VALID);
			response.getOptions().addETag(etag.clone());
			
			// automatically change now
			storeData(null, UNDEFINED);
		} else {
			response = new Response(CONTENT);

			if (data==null) {
				etag = ByteBuffer.allocate(2).putShort( (short) (Math.random()*0x10000) ).array();
				
				StringBuilder payload = new StringBuilder();
				payload.append(
						String.format(
								"Type: %d (%s)\nCode: %d (%s)\nMID: %d", 
								request.getType().value, 
								request.getType(), 
								request.getCode().value, 
								request.getCode(),
								request.getMID()));
		
				if (request.getToken().length > 0) {
					payload.append("\nToken: ");
					payload.append(request.getTokenString());
				}
				
				if (payload.length() > 64) {
					payload.delete(63, payload.length());
					payload.append('»');
				}
				response.setPayload(payload.toString());
				response.getOptions().setContentFormat(TEXT_PLAIN);
			} else {
				response.setPayload(data);
				response.getOptions().setContentFormat(dataCf);
			}
			response.getOptions().addETag(etag.clone());
		}
		exchange.respond(response);
	}

	@Override
	public void handlePUT(CoapExchange exchange) {
		
		if (exchange.getRequestOptions().isIfMatch(etag)) {
			if (exchange.getRequestOptions().hasContentFormat()) {
				storeData(exchange.getRequestPayload(), exchange.getRequestOptions().getContentFormat());
				exchange.setETag(etag.clone());
				exchange.respond(CHANGED);
			} else {
				exchange.respond(BAD_REQUEST, "Content-Format not set");
			}
		} else if (exchange.getRequestOptions().hasIfNoneMatch() && data==null) {
			storeData(exchange.getRequestPayload(), exchange.getRequestOptions().getContentFormat());
			exchange.respond(CREATED);
		} else {
			exchange.respond(PRECONDITION_FAILED);
			// automatically change now
			storeData(null, UNDEFINED);
		}
	}

	@Override
	public void handleDELETE(CoapExchange exchange) {
		storeData(null, UNDEFINED);
		exchange.respond(DELETED);
	}

	// Internal ////////////////////////////////////////////////////////////////
	
	/*
	 * Convenience function to store data contained in a 
	 * PUT/POST-Request. Notifies observing endpoints about
	 * the change of its contents.
	 */
	private synchronized void storeData(byte[] payload, int cf) {
		
		if (payload!=null) {
			data = payload;
			dataCf = cf;
			
			etag = ByteBuffer.allocate(4).putInt( data.hashCode() ).array();
	
			// set payload and content type
			getAttributes().clearContentType();
			getAttributes().addContentType(dataCf);
			getAttributes().setMaximumSizeEstimate(data.length);
		} else {
			data = null;
			etag = ByteBuffer.allocate(2).putShort( (short) (Math.random()*0x10000) ).array();
		}
		
		// signal that resource state changed
		changed();
	}
}
