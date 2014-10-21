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

import java.nio.charset.Charset;

import org.eclipse.californium.scandium.util.DatagramReader;
import org.eclipse.californium.scandium.util.DatagramWriter;


/**
 * The key exchange message sent when using the preshared key key exchange
 * algorithm. To help the client in selecting which identity to use, the server
 * can provide a "PSK identity hint" in the ServerKeyExchange message. If no
 * hint is provided, the ServerKeyExchange message is omitted. See <a
 * href="http://tools.ietf.org/html/rfc4279#section-2">ServerKeyExchange</a> for
 * the message format.
 */
public class PSKServerKeyExchange extends ServerKeyExchange {

	// DTLS-specific constants ////////////////////////////////////////

	private static final int IDENTITY_HINT_LENGTH_BITS = 16;
	
	private static final Charset CHAR_SET = Charset.forName("UTF8");

	// Members ////////////////////////////////////////////////////////

	/**
	 * The PSK identity MUST be first converted to a character string, and then
	 * encoded to octets using UTF-8. See <a
	 * href="http://tools.ietf.org/html/rfc4279#section-5.1">RFC 4279</a>.
	 */
	private byte[] hintEncoded;

	/** The hint in cleartext. */
	private String hint;

	// Constructors ///////////////////////////////////////////////////
	
	public PSKServerKeyExchange(String hint) {
		this.hint = hint;
		this.hintEncoded = hint.getBytes(CHAR_SET);
	}
	
	public PSKServerKeyExchange(byte[] hintEncoded) {
		this.hintEncoded = hintEncoded;
		this.hint = new String(hintEncoded, CHAR_SET);
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public int getMessageLength() {
		// fixed: 2 bytes for the length field
		// http://tools.ietf.org/html/rfc4279#section-2: opaque psk_identity_hint<0..2^16-1>;
		return 2 + hintEncoded.length;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder(super.toString());
		sb.append("\t\tPSK Identity Hint: " + hint + "\n");

		return sb.toString();
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	public byte[] fragmentToByteArray() {
		DatagramWriter writer = new DatagramWriter();
		
		writer.write(hintEncoded.length, IDENTITY_HINT_LENGTH_BITS);
		writer.writeBytes(hintEncoded);
		
		return writer.toByteArray();
	}
	
	public static HandshakeMessage fromByteArray(byte[] byteArray) {
		DatagramReader reader = new DatagramReader(byteArray);
		
		int length = reader.read(IDENTITY_HINT_LENGTH_BITS);
		byte[] hintEncoded = reader.readBytes(length);
		
		return new PSKServerKeyExchange(hintEncoded);
	}
	
	// Getters and Setters ////////////////////////////////////////////

	public String getHint() {
		return hint;
	}

	public void setHint(String hint) {
		this.hint = hint;
	}

}
