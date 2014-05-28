/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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

import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.util.DatagramReader;
import org.eclipse.californium.scandium.util.DatagramWriter;

/**
 * The change cipher spec protocol exists to signal transitions in ciphering
 * strategies. The protocol consists of a single message, which is encrypted and
 * compressed under the current (not the pending) connection state. The
 * ChangeCipherSpec message is sent by both the client and the server to notify
 * the receiving party that subsequent records will be protected under the newly
 * negotiated CipherSpec and keys. For further details see <a
 * href="http://tools.ietf.org/html/rfc5246#section-7.1">RFC 5246</a>.
 */
public class ChangeCipherSpecMessage implements DTLSMessage {

	// DTLS-specific constants ////////////////////////////////////////

	private static final int CCS_BITS = 8;

	// Members ////////////////////////////////////////////////////////

	private CCSType CCSProtocolType;

	// Constructor ////////////////////////////////////////////////////

	public ChangeCipherSpecMessage() {
		CCSProtocolType = CCSType.CHANGE_CIPHER_SPEC;
	}

	// Change Cipher Spec Enum ////////////////////////////////////////

	/**
	 * See <a href="http://tools.ietf.org/html/rfc5246#section-7.1">RFC 5246</a>
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
	
	// Methods ////////////////////////////////////////////////////////

	public CCSType getCCSProtocolType() {
		return CCSProtocolType;
	}
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("\tChange Cipher Spec Message\n");
		return sb.toString();
	}
	
	// Serialization //////////////////////////////////////////////////

	// @Override
	public byte[] toByteArray() {
		DatagramWriter writer = new DatagramWriter();
		writer.write(CCSProtocolType.getCode(), CCS_BITS);

		return writer.toByteArray();
	}

	public static DTLSMessage fromByteArray(byte[] byteArray) throws HandshakeException {
		DatagramReader reader = new DatagramReader(byteArray);
		int code = reader.read(CCS_BITS);
		if (code == CCSType.CHANGE_CIPHER_SPEC.getCode()) {
			return new ChangeCipherSpecMessage();
		} else {
			String message = "Unknown Change Cipher Spec code received: " + code;
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE);
			throw new HandshakeException(message, alert);
		}
	}

}
