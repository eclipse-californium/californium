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
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_ACCEPTABLE;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_IMPLEMENTED;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.UNDEFINED;

import java.util.Arrays;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.UriQueryParameter;
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
	 * Supported query parameter.
	 * 
	 * @since 3.2
	 */
	private static final List<String> SUPPORTED = Arrays.asList(URI_QUERY_OPTION_ACK, URI_QUERY_OPTION_RESPONSE_LENGTH);

	/**
	 * Default response.
	 */
	private final byte[] responsePayload = "hello benchmark".getBytes();
	/**
	 * Default notification.
	 */
	private final byte[] notificationPayload = "hello observe 000".getBytes();
	/**
	 * Disabled. Response with NOT_IMPLEMENTED (5.01).
	 */
	private final boolean disable;
	/**
	 * Maximum message size.
	 */
	private final int maxResourceSize;

	/*
	 * Defines a new timer task to return the current time
	 */
	private class TimeTask extends TimerTask {

		@Override
		public void run() {
			long millis = System.currentTimeMillis();
			String time = String.format("%03d", millis % 1000);
			int length = time.length();
			int offset = notificationPayload.length - length;
			for (int index = 0; index < length; ++index) {
				notificationPayload[offset + index] = (byte) time.charAt(index);
			}
			// Call changed to notify subscribers
			changed();
		}
	}

	public Benchmark(boolean disable, int maxResourceSize, long notifyIntervalMillis) {
		super(RESOURCE_NAME);
		this.disable = disable;
		this.maxResourceSize = maxResourceSize;
		if (disable) {
			getAttributes().setTitle("Benchmark (disabled)");
		} else {
			getAttributes().setTitle("Benchmark");
			setObservable(true);
			Timer timer = new Timer("OBSERVE", true);
			timer.schedule(new TimeTask(), 0, notifyIntervalMillis);
		}
		getAttributes().addContentType(TEXT_PLAIN);
	}

	@Override
	public void handleGET(CoapExchange exchange) {
		handleRequest(exchange, notificationPayload, CONTENT);
	}

	@Override
	public void handlePOST(CoapExchange exchange) {
		handleRequest(exchange, responsePayload, CHANGED);
	}

	public void handleRequest(CoapExchange exchange, byte[] payload, ResponseCode success) {

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

		boolean ack = false;
		int length = 0;
		try {
			UriQueryParameter helper = request.getOptions().getUriQueryParameter(SUPPORTED);
			ack = helper.hasParameter(URI_QUERY_OPTION_ACK);
			length = helper.getArgumentAsInteger(URI_QUERY_OPTION_RESPONSE_LENGTH, 0, 0, maxResourceSize);
		} catch (IllegalArgumentException ex) {
			exchange.respond(BAD_OPTION, ex.getMessage());
			return;
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

		exchange.respond(success, responsePayload, TEXT_PLAIN);
	}
}
