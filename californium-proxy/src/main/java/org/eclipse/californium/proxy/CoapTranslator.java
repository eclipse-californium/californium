/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Martin Lanter - architect and re-implementation
 *    Francesco Corazza - HTTP cross-proxy
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.proxy;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;


/**
 * Static class that provides the translations between the messages from the
 * internal CoAP nodes and external ones.
 */
public final class CoapTranslator {

	/** The Constant LOG. */
	private static final Logger LOGGER = LoggerFactory.getLogger(CoapTranslator.class.getName());

	/**
	 * Property file containing the mappings between coap messages and http
	 * messages.
	 */
//	public static final Properties COAP_TRANSLATION_PROPERTIES = new Properties("Proxy.properties");

	// Error constants
	public static final ResponseCode STATUS_FIELD_MALFORMED = ResponseCode.BAD_OPTION;
	public static final ResponseCode STATUS_TIMEOUT = ResponseCode.GATEWAY_TIMEOUT;
	public static final ResponseCode STATUS_TRANSLATION_ERROR = ResponseCode.BAD_GATEWAY;

	/**
	 * Starting from an external CoAP request, the method fills a new request
	 * for the internal CaAP nodes. Translates the proxy-uri option in the uri
	 * of the new request and simply copies the options and the payload from the
	 * original request to the new one.
	 * 
	 * @param incomingRequest
	 *            the original request
	 * 
	 * 
	 * 
	 * @return Request
	 * @throws TranslationException
	 *             the translation exception
	 */
	public static Request getRequest(final Request incomingRequest) throws TranslationException {
		// check parameters
		if (incomingRequest == null) {
			throw new IllegalArgumentException("incomingRequest == null");
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

		// get the uri address from the proxy-uri option
		URI serverUri;
		try {
			/*
			 * The new draft (14) only allows one proxy-uri option. Thus, this
			 * code segment has changed.
			 */
			String proxyUriString = URLDecoder.decode(
					incomingRequest.getOptions().getProxyUri(), "UTF-8");
			serverUri = new URI(proxyUriString);
		} catch (UnsupportedEncodingException e) {
			LOGGER.warn("UTF-8 do not support this encoding", e);
			throw new TranslationException("UTF-8 do not support this encoding", e);
		} catch (URISyntaxException e) {
			LOGGER.warn("Cannot translate the server uri", e);
			throw new TranslationException("Cannot translate the server uri", e);
		}

		// copy every option from the original message
		// do not copy the proxy-uri option because it is not necessary in
		// the new message
		// do not copy the token option because it is a local option and
		// have to be assigned by the proper layer
		// do not copy the block* option because it is a local option and
		// have to be assigned by the proper layer
		// do not copy the uri-* options because they are already filled in
		// the new message
		OptionSet options = new OptionSet(incomingRequest.getOptions());
		options.removeProxyUri();
		options.removeBlock1();
		options.removeBlock2();
		options.clearUriPath();
		options.clearUriQuery();
		outgoingRequest.setOptions(options);
		
		// set the proxy-uri as the outgoing uri
		if (serverUri != null) {
			outgoingRequest.setURI(serverUri);
		}

		LOGGER.debug("Incoming request translated correctly");
		return outgoingRequest;
	}
	
	/**
	 * Fills the new response with the response received from the internal CoAP
	 * node. Simply copies the options and the payload from the forwarded
	 * response to the new one.
	 * 
	 * @param incomingResponse
	 *            the forwarded request
	 * 
	 * 
	 * @return the response
	 */
	public static Response getResponse(final Response incomingResponse) {
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
		long timestamp = incomingResponse.getTimestamp();
		outgoingResponse.setTimestamp(timestamp);

		// copy every option
		outgoingResponse.setOptions(new OptionSet(
				incomingResponse.getOptions()));
		
		LOGGER.debug("Incoming response translated correctly");
		return outgoingResponse;
	}

	/**
	 * The Constructor is private because the class is an helper class and
	 * cannot be instantiated.
	 */
	private CoapTranslator() {
	}
}
