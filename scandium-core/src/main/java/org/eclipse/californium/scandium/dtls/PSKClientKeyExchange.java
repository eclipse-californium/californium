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
 * When using preshared keys for key agreement, the client indicates which key
 * to use by including a "PSK identity" in this message. The server can
 * potentially provide a "PSK identity hint" to help the client in selecting
 * which identity to use. See <a
 * href="https://tools.ietf.org/html/rfc4279#section-2" target="_blank">RFC 4279</a> for details.
 */
public final class PSKClientKeyExchange extends ClientKeyExchange {

	private static final int IDENTITY_LENGTH_BITS = 16;

	/** The identity in cleartext. */
	private final PskPublicInformation identity;

	public PSKClientKeyExchange(PskPublicInformation identity) {
		this.identity = identity;
	}

	private PSKClientKeyExchange(byte[] identityEncoded) {
		this.identity = PskPublicInformation.fromByteArray(identityEncoded);
	}

	@Override
	public int getMessageLength() {
		// fixed: 2 bytes for the length field
		// http://tools.ietf.org/html/rfc4279#section-2: opaque psk_identity<0..2^16-1>
		return 2 + identity.length();
	}

	@Override
	public String toString(int indent) {
		StringBuilder sb = new StringBuilder(super.toString(indent));
		String indentation = StringUtil.indentation(indent + 1);
		sb.append(indentation).append("PSK Identity: ").append(identity).append(StringUtil.lineSeparator());

		return sb.toString();
	}

	@Override
	public byte[] fragmentToByteArray() {
		DatagramWriter writer = new DatagramWriter(identity.length() + 2);

		writer.writeVarBytes(identity, IDENTITY_LENGTH_BITS);

		return writer.toByteArray();
	}

	public static HandshakeMessage fromReader(DatagramReader reader) {

		byte[] identityEncoded = reader.readVarBytes(IDENTITY_LENGTH_BITS);

		return new PSKClientKeyExchange(identityEncoded);
	}

	public PskPublicInformation getIdentity() {
		return identity;
	}
}
