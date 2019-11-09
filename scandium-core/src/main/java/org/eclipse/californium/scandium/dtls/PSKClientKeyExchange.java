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

import java.net.InetSocketAddress;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StringUtil;


/**
 * When using preshared keys for key agreement, the client indicates which key
 * to use by including a "PSK identity" in this message. The server can
 * potentially provide a "PSK identity hint" to help the client in selecting
 * which identity to use. See <a
 * href="http://tools.ietf.org/html/rfc4279#section-2">RFC 4279</a> for details.
 */
public final class PSKClientKeyExchange extends ClientKeyExchange {

	// DTLS-specific constants ////////////////////////////////////////

	private static final int IDENTITY_LENGTH_BITS = 16;

	// Members ////////////////////////////////////////////////////////

	/** The identity in cleartext. */
	private final PskPublicInformation identity;

	// Constructors ///////////////////////////////////////////////////

	public PSKClientKeyExchange(PskPublicInformation identity, InetSocketAddress peerAddress) {
		super(peerAddress);
		this.identity = identity;
	}

	private PSKClientKeyExchange(byte[] identityEncoded, InetSocketAddress peerAddress) {
		super(peerAddress);
		this.identity = PskPublicInformation.fromByteArray(identityEncoded);
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public int getMessageLength() {
		// fixed: 2 bytes for the length field
		// http://tools.ietf.org/html/rfc4279#section-2: opaque psk_identity<0..2^16-1>
		return 2 + identity.length();
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder(super.toString());
		sb.append("\t\tPSK Identity: ").append(identity).append(StringUtil.lineSeparator());

		return sb.toString();
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	public byte[] fragmentToByteArray() {
		DatagramWriter writer = new DatagramWriter();
		
		writer.write(identity.length(), IDENTITY_LENGTH_BITS);
		writer.writeBytes(identity.getBytes());
		
		return writer.toByteArray();
	}

	public static HandshakeMessage fromReader(DatagramReader reader, InetSocketAddress peerAddress) {
		
		int length = reader.read(IDENTITY_LENGTH_BITS);
		byte[] identityEncoded = reader.readBytes(length);
		
		return new PSKClientKeyExchange(identityEncoded, peerAddress);
	}

	// Getters and Setters ////////////////////////////////////////////

	public PskPublicInformation getIdentity() {
		return identity;
	}
}
