/*******************************************************************************
 * Copyright (c) 2016 Amazon Web Services.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * <p>
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.html.
 * <p>
 * Contributors:
 * Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 * Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 ******************************************************************************/
package org.eclipse.californium.core.network.serialization;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Token;

/**
 * Message header common to all messages.
 */
public class MessageHeader {

	private final int version;
	private final CoAP.Type type;
	private final Token token;
	private final int code;
	private final int mid;
	private final int bodyLength;

	public MessageHeader(int version, CoAP.Type type, Token token, int code, int mid, int bodyLength) {
		this.version = version;
		this.type = type;
		this.token = token;
		this.code = code;
		this.mid = mid;
		this.bodyLength = bodyLength;
	}

	/**
	 * Get length of the body.
	 * 
	 * Options + payload marker + payload length.
	 * 
	 * @return the body length
	 * @throws IllegalStateException if length is not available (value is less than 0).
	 */
	public int getBodyLength() {
		if (bodyLength < 0) {
			throw new IllegalStateException("body length not available!");
		}
		return bodyLength;
	}

	public int getVersion() {
		return version;
	}

	public CoAP.Type getType() {
		return type;
	}

	public Token getToken() {
		return token;
	}

	public int getCode() {
		return code;
	}

	public int getMID() {
		return mid;
	}
}
