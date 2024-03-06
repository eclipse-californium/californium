/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for message type
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for peer address
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;

/**
 * The change cipher spec protocol exists to signal transitions in ciphering
 * strategies. The protocol consists of a single message, which is encrypted and
 * compressed under the current (not the pending) connection state. The
 * ChangeCipherSpec message is sent by both the client and the server to notify
 * the receiving party that subsequent records will be protected under the newly
 * negotiated CipherSpec and keys. For further details see <a
 * href="https://tools.ietf.org/html/rfc5246#section-7.1" target="_blank">RFC 5246</a>.
 */
public final class ChangeCipherSpecMessage implements DTLSMessage {

	private static final int CCS_BITS = 8;

	private final CCSType CCSProtocolType;

	public ChangeCipherSpecMessage() {
		CCSProtocolType = CCSType.CHANGE_CIPHER_SPEC;
	}

	/**
	 * See <a href="https://tools.ietf.org/html/rfc5246#section-7.1" target="_blank">RFC 5246</a>
	 * for specification.
	 */
	public enum CCSType {

		CHANGE_CIPHER_SPEC(1);

		private int code;

		private CCSType(int code) {
			this.code = code;
		}

		public int getCode() {
			return code;
		}
	}

	@Override
	public ContentType getContentType() {
		return ContentType.CHANGE_CIPHER_SPEC;
	}

	public CCSType getCCSProtocolType() {
		return CCSProtocolType;
	}

	@Override
	public String toString(int indent) {
		return StringUtil.indentation(indent) + "Change Cipher Spec Message" + StringUtil.lineSeparator();
	}

	@Override
	public String toString() {
		return toString(0);
	}

	@Override
	public int size() {
		return CCS_BITS / Byte.SIZE;
	}

	@Override
	public byte[] toByteArray() {
		DatagramWriter writer = new DatagramWriter(1);
		writer.write(CCSProtocolType.getCode(), CCS_BITS);

		return writer.toByteArray();
	}

	public static DTLSMessage fromByteArray(byte[] byteArray) throws HandshakeException {
		DatagramReader reader = new DatagramReader(byteArray);
		int code = reader.read(CCS_BITS);
		if (code == CCSType.CHANGE_CIPHER_SPEC.getCode()) {
			if (reader.bytesAvailable()) {
				throw new HandshakeException("Change Cipher Spec must be empty!",
						new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR));
			}
			return new ChangeCipherSpecMessage();
		} else {
			String message = "Unknown Change Cipher Spec code received: " + code;
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER);
			throw new HandshakeException(message, alert);
		}
	}

}
