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
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 ******************************************************************************/
package org.eclipse.californium.core;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;


/**
 * CoapResponse provides a simple API for CoAP responses. Use a
 * {@link CoapClient} to send requests to a CoAP server and receive such a
 * response.
 * <p>
 * CoapResponse wraps an instance of type {@link Response} that is used
 * internally in Californium. To access this object directly for more detailed
 * information, call {@link #advanced()}.
 */
public class CoapResponse {

	/** The insternal response. */
	private Response response;
	
	/**
	 * Instantiates a new coap response.
	 *
	 * @param response the response
	 */
	protected CoapResponse(Response response) {
		this.response = response;
	}

	/**
	 * Gets the response code code.
	 *
	 * @return the response code
	 */
	public ResponseCode getCode() {
		return response.getCode();
	}
	
	/**
	 * Checks if the response code is a successful code.
	 *
	 * @return true, if is success
	 */
	public boolean isSuccess() {
		return CoAP.ResponseCode.isSuccess(response.getCode());
	}
	
	/**
	 * Gets the payload of this response as string.
	 *
	 * @return the response text
	 */
	public String getResponseText() {
		return response.getPayloadString();
	}
	
	/**
	 * Gets the payload of this response as byte array.
	 *
	 * @return the payload
	 */
	public byte[] getPayload() {
		return response.getPayload();
	}
	
	/**
	 * Gets the set of options of this response.
	 *
	 * @return the options
	 */
	public OptionSet getOptions() {
		return response.getOptions();
	}

	/**
	 * Gets the internal representation of the response for advanced API calls.
	 * 
	 * @return the internal response object
	 */
	public Response advanced() {
		return response;
	}
}
