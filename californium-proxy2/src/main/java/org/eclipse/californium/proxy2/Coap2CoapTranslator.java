/*******************************************************************************
 * Copyright (c) 2020 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - derived from org.eclipse.californium.proxy
 ******************************************************************************/

package org.eclipse.californium.proxy2;

import java.net.URI;

import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides the translations between the messages from the internal CoAP nodes
 * and external ones.
 */
public class Coap2CoapTranslator extends CoapUriTranslator {

	/** The Constant LOG. */
	private static final Logger LOGGER = LoggerFactory.getLogger(Coap2CoapTranslator.class);

	/**
	 * Starting from an external CoAP request, the method fills a new request
	 * for the internal CoAP nodes. Prepares the new request using the provided
	 * destination URI and simply copies the options and the payload from the
	 * original request to the new one.
	 * 
	 * @param destination destination for outgoing request
	 * @param incomingRequest the original incoming request
	 * @return Request the created outgoing request
	 * @throws TranslationException the translation exception
	 */
	public Request getRequest(URI destination, Request incomingRequest) throws TranslationException {
		// check parameters
		if (destination == null) {
			throw new NullPointerException("destination == null");
		}
		if (incomingRequest == null) {
			throw new NullPointerException("incomingRequest == null");
		}

		// get the code
		Code code = incomingRequest.getCode();

		// get message type
		Type type = incomingRequest.getType();

		// create the request
		Request outgoingRequest = new Request(code);
		outgoingRequest.setConfirmable(type == Type.CON);

		// copy payload
		byte[] payload = incomingRequest.getPayload();
		outgoingRequest.setPayload(payload);

		// copy every option from the original message
		// do not copy the proxy-uri option because it is not necessary in the new message
		// do not copy the token option because it is a local option and have to be assigned by the proper layer
		// do not copy the block* option because it is a local option and have to be assigned by the proper layer
		// do not copy the uri-* options because they are already filled in the new message
		OptionSet options = new OptionSet(incomingRequest.getOptions());
		options.removeProxyScheme();
		options.removeProxyUri();
		options.removeBlock1();
		options.removeBlock2();
		options.removeUriHost();
		options.removeUriPort();
		options.clearUriPath();
		options.clearUriQuery();
		outgoingRequest.setOptions(options);

		// set the proxy-uri as the outgoing uri
		outgoingRequest.setURI(destination);

		LOGGER.debug("Incoming request translated correctly");
		return outgoingRequest;
	}

	/**
	 * Fills the new response with the response received from the internal CoAP
	 * node. Simply copies the options and the payload from the forwarded
	 * response to the new one.
	 * 
	 * @param incomingResponse the incoming response
	 * @return the response to outgoing response
	 */
	public Response getResponse(Response incomingResponse) {
		if (incomingResponse == null) {
			throw new IllegalArgumentException("incomingResponse == null");
		}

		// get the status
		ResponseCode status = incomingResponse.getCode();

		// create the response
		Response outgoingResponse = new Response(status);

		// copy payload
		byte[] payload = incomingResponse.getPayload();
		outgoingResponse.setPayload(payload);

		// copy the timestamp
		long timestamp = incomingResponse.getNanoTimestamp();
		outgoingResponse.setNanoTimestamp(timestamp);

		// copy every option
		outgoingResponse.setOptions(incomingResponse.getOptions());

		LOGGER.debug("Incoming response translated correctly");
		return outgoingResponse;
	}
}
