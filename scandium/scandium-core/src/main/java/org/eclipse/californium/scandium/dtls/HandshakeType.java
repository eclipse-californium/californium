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
 *    Stefan Jucker - DTLS implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

/**
 * Represents the possible types of a handshake message. See <a
 * href="http://tools.ietf.org/html/rfc5246#section-7.4">RFC 5246</a> for
 * details.
 */
public enum HandshakeType {
	HELLO_REQUEST(0), CLIENT_HELLO(1), SERVER_HELLO(2), HELLO_VERIFY_REQUEST(3),
	CERTIFICATE(11), SERVER_KEY_EXCHANGE(12), CERTIFICATE_REQUEST(13), SERVER_HELLO_DONE(14),
	CERTIFICATE_VERIFY(15), CLIENT_KEY_EXCHANGE(16), FINISHED(20);

	private int code;

	private HandshakeType(int code) {
		this.code = code;
	}

	public int getCode() {
		return code;
	}

	public static HandshakeType getTypeByCode(int code) {
		for (HandshakeType type : values()) {
			if (type.code == code) {
				return type;
			}
		}
		return null;
	}

	@Override
	public String toString() {
		return new StringBuilder(name()).append(" (").append(getCode()).append(")").toString();
	}
}
