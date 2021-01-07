/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH.
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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;

/**
 * Indicates a problem while parsing the binary representation of a CoAP
 * message.
 * <p>
 * The <em>message</em> property contains a description of the problem
 * encountered. The other properties are parsed from the binary representation.
 * </p>
 */
public class CoAPMessageFormatException extends MessageFormatException {

	private static final long serialVersionUID = 1L;
	private static final int NO_MID = -1;
	private final int mid;
	private final int code;
	private final Token token;
	private final ResponseCode errorCode;
	private final boolean confirmable;

	/**
	 * Creates an exception for a description and message properties.
	 * 
	 * Use {@link ResponseCode#BAD_OPTION} as response error code.
	 * 
	 * @param description a description of the error cause.
	 * @param token the Token of the message. Maybe {@code null}, if the message
	 *            has no token (ACK or RST).
	 * @param mid the message ID.
	 * @param code the message code.
	 * @param confirmable whether the message has been transferred reliably.
	 * @since 2.3
	 */
	public CoAPMessageFormatException(String description, Token token, int mid, int code, boolean confirmable) {
		this(description, token, mid, code, confirmable, ResponseCode.BAD_OPTION);
	}

	/**
	 * Creates an exception for a description, message properties, and error
	 * response code.
	 * 
	 * @param description a description of the error cause.
	 * @param token the Token of the message. Maybe {@code null}, if the message
	 *            has no token (ACK or RST).
	 * @param mid the message ID.
	 * @param code the message code.
	 * @param confirmable whether the message has been transferred reliably.
	 * @param errorCode error response code.
	 * @since 3.0
	 */
	public CoAPMessageFormatException(String description, Token token, int mid, int code, boolean confirmable,
			ResponseCode errorCode) {
		super(description);
		this.token = token;
		this.mid = mid;
		this.code = code;
		this.confirmable = confirmable;
		this.errorCode = errorCode;
	}

	/**
	 * Get token of message.
	 * 
	 * @return the token. Maybe {@code null}.
	 * @since 2.3
	 */
	public Token getToken() {
		return token;
	}

	/**
	 * Checks if the message's ID could be parsed successfully.
	 * 
	 * @return {@code true} if the value returned by <em>getMid</em> is the real
	 *         message ID.
	 */
	public final boolean hasMid() {
		return mid > NO_MID;
	}

	/**
	 * Get the MID of the message.
	 * 
	 * @return the mid. {@code NO_MID}, if not available.
	 */
	public final int getMid() {
		return mid;
	}

	/**
	 * Get the code of the message.
	 * 
	 * @return the code
	 */
	public final int getCode() {
		return code;
	}

	/**
	 * Get the error code for a response.
	 * 
	 * @return the error code
	 * @since 3.0
	 */
	public final ResponseCode getErrorCode() {
		return errorCode;
	}

	/**
	 * Checks if the message has been transferred reliably.
	 * 
	 * @return {@code true} if the message type is CON.
	 */
	public final boolean isConfirmable() {
		return confirmable;
	}
}
