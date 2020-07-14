/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.extplugtests.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.BAD_OPTION;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CHANGED;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_ACCEPTABLE;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_IMPLEMENTED;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.UNDEFINED;

import java.util.Arrays;
import java.util.List;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;

/**
 * Benchmark resource.
 * 
 * NOT intended to be used at californium-sandbox!
 */
public class Benchmark extends CoapResource {

	private static final String RESOURCE_NAME = "benchmark";
	/**
	 * URI query parameter to specify response length.
	 */
	private static final String URI_QUERY_OPTION_RESPONSE_LENGTH = "rlen";
	/**
	 * URI query parameter to specify ack and separate response.
	 */
	private static final String URI_QUERY_OPTION_ACK = "ack";

	/**
	 * Default response.
	 */
	private final byte[] payload = "hello benchmark".getBytes();
	/**
	 * Disabled. Response with NOT_IMPLEMENTED (5.01).
	 */
	private final boolean disable;
	/**
	 * Maximum message size.
	 */
	private final int maxResourceSize;

	public Benchmark(boolean disable, int maxResourceSize) {
		super(RESOURCE_NAME);
		this.disable = disable;
		this.maxResourceSize = maxResourceSize;
		if (disable) {
			getAttributes().setTitle("Benchmark (disabled)");
		} else {
			getAttributes().setTitle("Benchmark");
		}
		getAttributes().addContentType(TEXT_PLAIN);
	}

	@Override
	public void handlePOST(CoapExchange exchange) {

		if (disable) {
			// disabled => response with NOT_IMPLEMENTED
			exchange.respond(NOT_IMPLEMENTED, RESOURCE_NAME + " is not supported on this host!");
			return;
		}

		// get request to read out details
		Request request = exchange.advanced().getRequest();

		int accept = request.getOptions().getAccept();
		if (accept != UNDEFINED && accept != TEXT_PLAIN) {
			exchange.respond(NOT_ACCEPTABLE);
			return;
		}

		List<String> uriQuery = request.getOptions().getUriQuery();
		boolean ack = false;
		int length = 0;
		for (String query : uriQuery) {
			String message = null;
			if (query.startsWith(URI_QUERY_OPTION_RESPONSE_LENGTH + "=")) {
				String rlen = query.substring(URI_QUERY_OPTION_RESPONSE_LENGTH.length() + 1);
				try {
					length = Integer.parseInt(rlen);
					if (length < 0) {
						message = "URI-query-option " + query + " is negative number!";
					} else if (length > maxResourceSize && maxResourceSize > 0) {
						message = "URI-query-option " + query + " is too large (max. " + maxResourceSize + ")!";
					}
				} catch (NumberFormatException ex) {
					message = "URI-query-option " + query + " is no number!";
				}
			} else if (query.startsWith(URI_QUERY_OPTION_ACK)) {
				ack = true;
			} else {
				message = "URI-query-option " + query + " is not supported!";
			}
			if (message != null) {
				Response response = Response.createResponse(request, BAD_OPTION);
				response.setPayload(message);
				exchange.respond(response);
				return;
			}
		}
		
		if (ack) {
			exchange.accept();
		}

		byte[] responsePayload = payload;
		if (length > 0) {
			responsePayload = Arrays.copyOf(payload, length);
			if (length > payload.length) {
				Arrays.fill(responsePayload, payload.length, length, (byte) '*');
			}
		}

		exchange.respond(CHANGED, responsePayload, TEXT_PLAIN);
	}
}
