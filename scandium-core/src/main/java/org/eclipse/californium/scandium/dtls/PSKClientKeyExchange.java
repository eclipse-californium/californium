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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for peer address
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.nio.charset.Charset;
import java.util.Arrays;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;


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

	private static final Charset CHAR_SET_UTF8 = Charset.forName("UTF8");

	// Members ////////////////////////////////////////////////////////

	/**
	 * The PSK identity MUST be first converted to a character string, and then
	 * encoded to octets using UTF-8. See <a
	 * href="http://tools.ietf.org/html/rfc4279#section-5.1">RFC 4279</a>.
	 */
	private final byte[] identityEncoded;

	/** The identity in cleartext. */
	private final String identity;

	// Constructors ///////////////////////////////////////////////////

	public PSKClientKeyExchange(String identity, InetSocketAddress peerAddress) {
		super(peerAddress);
		this.identityEncoded = identity.getBytes(CHAR_SET_UTF8);
		this.identity = identity;
	}
	
	private PSKClientKeyExchange(byte[] identityEncoded, InetSocketAddress peerAddress) {
		super(peerAddress);
		this.identityEncoded = Arrays.copyOf(identityEncoded, identityEncoded.length);
		this.identity = new String(this.identityEncoded, CHAR_SET_UTF8);
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public int getMessageLength() {
		// fixed: 2 bytes for the length field
		// http://tools.ietf.org/html/rfc4279#section-2: opaque psk_identity<0..2^16-1>
		return 2 + identityEncoded.length;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder(super.toString());
		sb.append("\t\tPSK Identity: ").append(identity).append(System.lineSeparator());

		return sb.toString();
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	public byte[] fragmentToByteArray() {
		DatagramWriter writer = new DatagramWriter();
		
		writer.write(identityEncoded.length, IDENTITY_LENGTH_BITS);
		writer.writeBytes(identityEncoded);
		
		return writer.toByteArray();
	}

	public static HandshakeMessage fromByteArray(byte[] byteArray, InetSocketAddress peerAddress) {
		DatagramReader reader = new DatagramReader(byteArray);
		
		int length = reader.read(IDENTITY_LENGTH_BITS);
		byte[] identityEncoded = reader.readBytes(length);
		
		return new PSKClientKeyExchange(identityEncoded, peerAddress);
	}

	// Getters and Setters ////////////////////////////////////////////

	public String getIdentity() {
		return identity;
	}
}
