/*******************************************************************************
 * Copyright (c) 2016 Amazon Web Services.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * <p>
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.html.
 * <p>
 * Contributors:
 * Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 ******************************************************************************/
package org.eclipse.californium.core.network.serialization;

import org.eclipse.californium.core.coap.CoAP;

/**
 * Message header common to all messages.
 */
public class MessageHeader {

	private final int version;
	private final CoAP.Type type;
	private final byte[] token;
	private final int code;
	private final int mid;
	private final int bodyLength;

	MessageHeader(int version, CoAP.Type type, byte[] token, int code, int mid, int bodyLength) {
		this.version = version;
		this.type = type;
		this.token = token;
		this.code = code;
		this.mid = mid;
		this.bodyLength = bodyLength;
	}

	/** Options + payload marker + payload length. */
	public int getBodyLength() {
		return bodyLength;
	}

	public int getVersion() {
		return version;
	}

	public CoAP.Type getType() {
		return type;
	}

	public byte[] getToken() {
		return token;
	}

	public int getCode() {
		return code;
	}

	public int getMID() {
		return mid;
	}
}
