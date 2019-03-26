/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
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
 *    Tobias Andersson (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;

/**
 * 
 * Extends the OSException by adding a ResponseCode.
 *
 */
public class CoapOSException extends OSException {

	/**
	 * Serial version UID
	 */
	private static final long serialVersionUID = -8059837275857542506L;

	private final ResponseCode responseCode;

	/**
	 * Constructor, sets the error message and sets the coapReponseCode
	 * 
	 * @param message the message
	 */
	public CoapOSException(String message, ResponseCode coapResponseCode) {
		super(message);
		this.responseCode = coapResponseCode;
	}

	public ResponseCode getResponseCode() {
		return responseCode;
	}

}
