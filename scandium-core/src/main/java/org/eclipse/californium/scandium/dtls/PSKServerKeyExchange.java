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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for peer address
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * The key exchange message sent when using the preshared key key exchange
 * algorithm. To help the client in selecting which identity to use, the server
 * can provide a "PSK identity hint" in the ServerKeyExchange message. If no
 * hint is provided, the ServerKeyExchange message is omitted. See <a
 * href="http://tools.ietf.org/html/rfc4279#section-2">ServerKeyExchange</a> for
 * the message format.
 */
public final class PSKServerKeyExchange extends ServerKeyExchange {

	// DTLS-specific constants ////////////////////////////////////////

	private static final int IDENTITY_HINT_LENGTH_BITS = 16;

	// Members ////////////////////////////////////////////////////////

	/** The hint in cleartext. */
	private final PskPublicInformation hint;

	// Constructors ///////////////////////////////////////////////////
	
	public PSKServerKeyExchange(PskPublicInformation hint) {
		this.hint = hint;
	}

	private PSKServerKeyExchange(byte[] hintEncoded) {
		this.hint = PskPublicInformation.fromByteArray(hintEncoded);
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public int getMessageLength() {
		// fixed: 2 bytes for the length field
		// http://tools.ietf.org/html/rfc4279#section-2: opaque psk_identity_hint<0..2^16-1>
		return 2 + hint.length();
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder(super.toString());
		sb.append("\t\tPSK Identity Hint: ").append(hint).append(StringUtil.lineSeparator());

		return sb.toString();
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	public byte[] fragmentToByteArray() {
		DatagramWriter writer = new DatagramWriter(hint.length() + 2);

		writer.writeVarBytes(hint, IDENTITY_HINT_LENGTH_BITS);

		return writer.toByteArray();
	}
	
	public static HandshakeMessage fromReader(DatagramReader reader) {

		byte[] hintEncoded = reader.readVarBytes(IDENTITY_HINT_LENGTH_BITS);

		return new PSKServerKeyExchange(hintEncoded);
	}
	
	// Getters and Setters ////////////////////////////////////////////

	public PskPublicInformation getHint() {
		return hint;
	}
}
