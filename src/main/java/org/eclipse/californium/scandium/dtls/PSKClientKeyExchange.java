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

import java.io.UnsupportedEncodingException;

import org.eclipse.californium.scandium.util.DatagramReader;
import org.eclipse.californium.scandium.util.DatagramWriter;


/**
 * When using preshared keys for key agreement, the client indicates which key
 * to use by including a "PSK identity" in this message. The server can
 * potentially provide a "PSK identity hint" to help the client in selecting
 * which identity to use. See <a
 * href="http://tools.ietf.org/html/rfc4279#section-2">RFC 4279</a> for details.
 */
public class PSKClientKeyExchange extends ClientKeyExchange {

	// DTLS-specific constants ////////////////////////////////////////

	private static final int IDENTITY_LENGTH_BITS = 16;
	
	private static final String CHAR_SET = "UTF8";

	// Members ////////////////////////////////////////////////////////

	/**
	 * The PSK identity MUST be first converted to a character string, and then
	 * encoded to octets using UTF-8. See <a
	 * href="http://tools.ietf.org/html/rfc4279#section-5.1">RFC 4279</a>.
	 */
	private byte[] identityEncoded;

	/** The identity in cleartext. */
	private String identity;

	// Constructors ///////////////////////////////////////////////////
	
	public PSKClientKeyExchange(String identity) {
		this.identity = identity;
		try {
			this.identityEncoded = identity.getBytes(CHAR_SET);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}
	
	public PSKClientKeyExchange(byte[] identityEncoded) {
		this.identityEncoded = identityEncoded;
		try {
			this.identity = new String(identityEncoded, CHAR_SET);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public int getMessageLength() {
		// fixed: 2 bytes for the length field
		// http://tools.ietf.org/html/rfc4279#section-2: opaque psk_identity<0..2^16-1>;
		return 2 + identityEncoded.length;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder(super.toString());
		sb.append(super.toString());
		sb.append("\t\tPSK Identity: " + identity + "\n");

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
	
	public static HandshakeMessage fromByteArray(byte[] byteArray) {
		DatagramReader reader = new DatagramReader(byteArray);
		
		int length = reader.read(IDENTITY_LENGTH_BITS);
		byte[] identityEncoded = reader.readBytes(length);
		
		return new PSKClientKeyExchange(identityEncoded);
	}
	
	// Getters and Setters ////////////////////////////////////////////

	public String getIdentity() {
		return identity;
	}

	public void setIdentity(String identity) {
		this.identity = identity;
	}

}
