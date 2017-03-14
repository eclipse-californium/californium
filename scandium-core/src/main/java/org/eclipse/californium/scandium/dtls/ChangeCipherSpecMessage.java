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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for message type
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for peer address
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;

/**
 * The change cipher spec protocol exists to signal transitions in ciphering
 * strategies. The protocol consists of a single message, which is encrypted and
 * compressed under the current (not the pending) connection state. The
 * ChangeCipherSpec message is sent by both the client and the server to notify
 * the receiving party that subsequent records will be protected under the newly
 * negotiated CipherSpec and keys. For further details see <a
 * href="http://tools.ietf.org/html/rfc5246#section-7.1">RFC 5246</a>.
 */
public final class ChangeCipherSpecMessage extends AbstractMessage {

	// DTLS-specific constants ////////////////////////////////////////

	private static final int CCS_BITS = 8;

	// Members ////////////////////////////////////////////////////////

	private final CCSType CCSProtocolType;

	// Constructor ////////////////////////////////////////////////////

	public ChangeCipherSpecMessage(InetSocketAddress peerAddress) {
		super(peerAddress);
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

	@Override
	public ContentType getContentType() {
		return ContentType.CHANGE_CIPHER_SPEC;
	}
	
	public CCSType getCCSProtocolType() {
		return CCSProtocolType;
	}
	
	@Override
	public String toString() {
		return "\tChange Cipher Spec Message\n";
	}
	
	// Serialization //////////////////////////////////////////////////

	@Override
	public byte[] toByteArray() {
		DatagramWriter writer = new DatagramWriter();
		writer.write(CCSProtocolType.getCode(), CCS_BITS);

		return writer.toByteArray();
	}

	public static DTLSMessage fromByteArray(byte[] byteArray, InetSocketAddress peerAddress) throws HandshakeException {
		DatagramReader reader = new DatagramReader(byteArray);
		int code = reader.read(CCS_BITS);
		if (code == CCSType.CHANGE_CIPHER_SPEC.getCode()) {
			return new ChangeCipherSpecMessage(peerAddress);
		} else {
			String message = "Unknown Change Cipher Spec code received: " + code;
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, peerAddress);
			throw new HandshakeException(message, alert);
		}
	}

}
