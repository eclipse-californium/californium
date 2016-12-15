/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH.
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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.coap;

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
	private final boolean confirmable;

	/**
	 * Creates an exception for a description and message properties.
	 * 
	 * @param description a description of the error cause.
	 * @param mid the message ID.
	 * @param code the message code.
	 * @param confirmable whether the message has been transferred reliably.
	 */
	public CoAPMessageFormatException(String description, int mid, int code, boolean confirmable) {
		super(description);
		this.mid = mid;
		this.code = code;
		this.confirmable = confirmable;
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
	 * @return the mid
	 */
	public final int getMid() {
		return mid;
	}

	/**
	 * @return the code
	 */
	public final int getCode() {
		return code;
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
