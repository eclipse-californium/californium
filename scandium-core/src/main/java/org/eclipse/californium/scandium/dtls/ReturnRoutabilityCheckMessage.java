/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.util.Arrays;

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.cipher.RandomManager;

/**
 * Return routability check message.
 * <p>
 * See <a href= "https://tlswg.org/dtls-rrc/draft-ietf-tls-dtls-rrc.html" target
 * ="_blank">dtls-rrc/draft-ietf-tls-dtls-rrc, Return Routability Check for DTLS
 * 1.2 and DTLS 1.3</a>.
 * 
 * @since 3.12
 */
public final class ReturnRoutabilityCheckMessage implements DTLSMessage {

	public static final ReturnRoutabilityCheckMessage INVALID = new ReturnRoutabilityCheckMessage();

	private static final int TYPE_BITS = 8;
	private static final int COOKIE_BYTES = 8;

	private final ReturnRoutabilityCheckType type;

	private final byte[] cookie;

	/**
	 * Creates a new <em>RRC</em> message containing specific data.
	 * <p>
	 * The given cookie will not be cloned/copied, i.e. any changes made to the
	 * cookie after this method has been invoked will be exposed in the
	 * message's payload.
	 * 
	 * @param type type of this return routability check message.
	 * @param cookie the cookie of this return routability check message. If
	 *            {@code null} a random cookie is generated.
	 * @throws NullPointerException if type is {@code null}
	 * @throws IllegalArgumentException if cookie length is not 8
	 */
	public ReturnRoutabilityCheckMessage(ReturnRoutabilityCheckType type, byte[] cookie) {
		if (type == null) {
			throw new NullPointerException("type must not be null!");
		}
		if (cookie == null) {
			cookie = Bytes.createBytes(RandomManager.currentSecureRandom(), COOKIE_BYTES);
		} else if (cookie.length != COOKIE_BYTES) {
			throw new IllegalArgumentException("cookie must have 8 bytes!");
		}
		this.type = type;
		this.cookie = cookie;
	}

	private ReturnRoutabilityCheckMessage() {
		this.type = null;
		this.cookie = Bytes.EMPTY;
	}

	public ReturnRoutabilityCheckType getReturnRoutabilityCheckType() {
		return type;
	}

	public byte[] getCookie() {
		return cookie;
	}

	public boolean equalsCookie(ReturnRoutabilityCheckMessage reply) {
		return Arrays.equals(cookie, reply.cookie);
	}

	@Override
	public ContentType getContentType() {
		return ContentType.RRC;
	}

	@Override
	public String toString(int indent) {
		StringBuilder sb = new StringBuilder();
		if (indent > 0) {
			sb.append(StringUtil.indentation(indent));
		}
		sb.append("Return Routability Check: ").append(type).append(" ").append(StringUtil.byteArray2HexString(cookie));
		if (indent > 0) {
			sb.append(StringUtil.lineSeparator());
		}
		return sb.toString();
	}

	@Override
	public String toString() {
		return toString(0);
	}

	@Override
	public int size() {
		return TYPE_BITS / Byte.SIZE + cookie.length;
	}

	@Override
	public byte[] toByteArray() {
		DatagramWriter writer = new DatagramWriter(2);

		writer.write(type.getCode(), TYPE_BITS);
		writer.writeBytes(cookie);

		return writer.toByteArray();
	}

	/**
	 * Create message from byte array.
	 * <p>
	 * 
	 * @param byteArray byte array with the return routability check data.
	 * @return created message, or {@code INVALID}, if message is invalid
	 * @see #ReturnRoutabilityCheckMessage(ReturnRoutabilityCheckType, byte[])
	 */
	public static DTLSMessage fromByteArray(byte[] byteArray) {
		DatagramReader reader = new DatagramReader(byteArray);
		int code = reader.read(TYPE_BITS);
		ReturnRoutabilityCheckType type = ReturnRoutabilityCheckType.getTypeByValue(code);
		if (type == null) {
			return INVALID;
		}
		byte[] cookie = reader.readBytes(COOKIE_BYTES);
		if (cookie.length != COOKIE_BYTES) {
			return INVALID;
		}
		if (reader.bitsLeft() != 0) {
			return INVALID;
		}
		return new ReturnRoutabilityCheckMessage(type, cookie);
	}
}
