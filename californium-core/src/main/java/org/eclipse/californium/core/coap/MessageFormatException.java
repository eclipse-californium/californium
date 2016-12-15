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
 *    Achim Kraus (Bosch Software Innovations GmbH) - move CoAP specific information 
 *                                                    to CoAPMessageFormatException
 ******************************************************************************/
package org.eclipse.californium.core.coap;

/**
 * Indicates a problem while parsing the binary representation of a message.
 * <p>
 * The <em>message</em> property contains a description of the problem
 * encountered.
 * </p>
 */
public class MessageFormatException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	/**
	 * Creates an exception for a description.
	 * 
	 * @param description a description of the error cause.
	 */
	public MessageFormatException(final String description) {
		super(description);
	}

}
