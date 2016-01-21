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
 * The content type represents a higher-level protocol to process the enclosed
 * fragment. It is one of the four types: ChangeCipherSpec, Alert, Handshake,
 * ApplicationData. For further details see <a
 * href="http://tools.ietf.org/html/rfc5246#appendix-A.1">RFC 5246</a>.
 */
public enum ContentType {

	CHANGE_CIPHER_SPEC(20), ALERT(21), HANDSHAKE(22), APPLICATION_DATA(23);

	private int code;

	public int getCode() {
		return code;
	}

	ContentType(int code) {
		this.code = code;
	}

	/**
	 * Returns the content type according to the given code. Needed when
	 * reconstructing a received byte array.
	 * 
	 * @param code
	 *            the code representation of the content type (i.e. 20, 21, 22,
	 *            23).
	 * @return the corresponding content type.
	 */
	public static ContentType getTypeByValue(int code) {
		switch (code) {
		case 20:
			return ContentType.CHANGE_CIPHER_SPEC;
		case 21:
			return ContentType.ALERT;
		case 22:
			return ContentType.HANDSHAKE;
		case 23:
			return ContentType.APPLICATION_DATA;

		default:
			return null;
		}
	}

	@Override
	public String toString() {
		switch (code) {
		case 20:
			return "Change Cipher Spec (20)";
		case 21:
			return "Alert (21)";
		case 22:
			return "Handshake (22)";
		case 23:
			return "Application Data (23)";

		default:
			return "Unknown Content Type";
		}
	}
}
