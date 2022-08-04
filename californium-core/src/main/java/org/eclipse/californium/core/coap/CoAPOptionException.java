/*******************************************************************************
 * Copyright (c) 2022 Contributors to the Eclipse Foundation.
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
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;

/**
 * Indicates a problem while parsing the binary representation of a CoAP option.
 * <p>
 * The <em>message</em> property contains a description of the problem
 * encountered.
 * </p>
 */
public class CoAPOptionException extends MessageFormatException {

	private static final long serialVersionUID = 1L;
	private final ResponseCode errorCode;

	/**
	 * Creates an exception for a description, and error response code.
	 * 
	 * @param description a description of the error cause.
	 * @param errorCode error response code. {@code null} to reject the incoming
	 *            message, if possible.
	 */
	public CoAPOptionException(String description, ResponseCode errorCode) {
		super(description);
		this.errorCode = errorCode;
	}

	/**
	 * Get the error code for a response.
	 * 
	 * Note: only malformed CON-requests are responded with an error message.
	 * Malformed CON-responses are always rejected and malformed NON-messages
	 * 
	 * @return the error code, or {@code null}, if the incoming message should
	 *         be rejected, if possible.
	 */
	public final ResponseCode getErrorCode() {
		return errorCode;
	}

}
