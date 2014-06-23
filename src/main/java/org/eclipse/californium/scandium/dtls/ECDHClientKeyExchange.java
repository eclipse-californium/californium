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

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography;
import org.eclipse.californium.scandium.util.ByteArrayUtils;
import org.eclipse.californium.scandium.util.DatagramReader;
import org.eclipse.californium.scandium.util.DatagramWriter;


/**
 * {@link ClientKeyExchange} message for all ECDH based key exchange methods.
 * Contains the client's ephemeral public value. See <a
 * href="http://tools.ietf.org/html/rfc4492#section-5.7">RFC 4492</a> for further details. It is assumed, that the client's
 * ECDH public key is not in the client's certificate, so it must be provided
 * here.
 */
public class ECDHClientKeyExchange extends ClientKeyExchange {

	// DTLS-specific constants ////////////////////////////////////////
	
	protected static final int LENGTH_BITS = 8; // opaque point <1..2^8-1>;

	// Members ////////////////////////////////////////////////////////

	private byte[] pointEncoded;

	// Constructors ///////////////////////////////////////////////////

	/**
	 * Called by the client. Generates the client's ephemeral ECDH public key
	 * (encoded) which represents an elliptic curve point.
	 * 
	 * @param clientPublicKey
	 *            the client's public key.
	 */
	public ECDHClientKeyExchange(PublicKey clientPublicKey) {
		ECPublicKey publicKey = (ECPublicKey) clientPublicKey;
		ECPoint point = publicKey.getW();
		ECParameterSpec params = publicKey.getParams();
		
		pointEncoded = ECDHECryptography.encodePoint(point, params.getCurve());
	}

	/**
	 * Called by the server when receiving a {@link ClientKeyExchange} message.
	 * Stores the encoded point which will be later used, to generate the
	 * premaster secret.
	 * 
	 * @param pointEncoded
	 *            the client's ephemeral public key (encoded point).
	 */
	public ECDHClientKeyExchange(byte[] pointEncoded) {
		this.pointEncoded = pointEncoded;
	}
	
	// Serialization //////////////////////////////////////////////////

	@Override
	public byte[] fragmentToByteArray() {
		DatagramWriter writer = new DatagramWriter();

		// TODO only true, if the public value encoding is explicit (not in the
		// client's certificate), see
		// http://tools.ietf.org/html/rfc4492#section-5.7
		int length = pointEncoded.length;
		writer.write(length, LENGTH_BITS);
		writer.writeBytes(pointEncoded);

		return writer.toByteArray();
	}

	public static HandshakeMessage fromByteArray(byte[] byteArray) {
		DatagramReader reader = new DatagramReader(byteArray);
		int length = reader.read(LENGTH_BITS);
		byte[] pointEncoded = reader.readBytes(length);

		return new ECDHClientKeyExchange(pointEncoded);
	}
	
	// Methods ////////////////////////////////////////////////////////

	@Override
	public int getMessageLength() {
		// TODO only true, if the public value encoding is explicit
		return 1 + pointEncoded.length;
	}

	public byte[] getEncodedPoint() {
		return pointEncoded;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(super.toString());
		sb.append("\t\t" + ByteArrayUtils.toHexString(pointEncoded) + "\n");

		return sb.toString();
	}

}
