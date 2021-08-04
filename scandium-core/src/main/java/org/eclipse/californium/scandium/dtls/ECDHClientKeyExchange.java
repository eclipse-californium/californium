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

import java.util.Arrays;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.NoPublicAPI;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * {@link ClientKeyExchange} message for all ECDH based key exchange methods.
 * Contains the client's ephemeral public key as encoded point. See
 * <a href="https://tools.ietf.org/html/rfc4492#section-5.7" target="_blank">RFC 4492</a> for
 * further details. It is assumed, that the client's ECDH public key is not in
 * the client's certificate, so it must be provided here.
 * 
 * According <a href="https://tools.ietf.org/html/rfc8422#section-5.1.1" target="_blank">RFC
 * 8422, 5.1.1. Supported Elliptic Curves Extension</a> only "named curves" are
 * valid, the "prime" and "char2" curve descriptions are deprecated. Also only
 * "UNCOMPRESSED" as point format is valid, the other formats have been
 * deprecated.
 */
@NoPublicAPI
public class ECDHClientKeyExchange extends ClientKeyExchange {

	private static final int LENGTH_BITS = 8; // opaque point <1..2^8-1>

	/**
	 * Ephemeral public key of client as encoded point.
	 */
	private final byte[] encodedPoint;

	/**
	 * Create a {@link ClientKeyExchange} message.
	 * 
	 * @param encodedPoint
	 *            the client's ephemeral public key (as encoded point).
	 */
	public ECDHClientKeyExchange(byte[] encodedPoint) {
		super();
		if (encodedPoint == null) {
			throw new NullPointerException("encoded point cannot be null");
		}
		this.encodedPoint = encodedPoint;
	}

	@Override
	public byte[] fragmentToByteArray() {
		DatagramWriter writer = new DatagramWriter();
		writeFragment(writer);
		return writer.toByteArray();
	}

	/**
	 * Write fragment to writer.
	 * 
	 * Write the encoded point.
	 * 
	 * @param writer writer
	 */
	protected void writeFragment(DatagramWriter writer) {
		writer.writeVarBytes(encodedPoint, LENGTH_BITS);
	}

	/**
	 * Read encoded point from reader.
	 * 
	 * @param reader reader
	 * @return encoded point
	 */
	protected static byte[] readEncodedPoint(DatagramReader reader) {
		return reader.readVarBytes(LENGTH_BITS);
	}

	public static HandshakeMessage fromReader(DatagramReader reader) {
		byte[] pointEncoded = readEncodedPoint(reader);
		return new ECDHClientKeyExchange(pointEncoded);
	}

	@Override
	public int getMessageLength() {
		return 1 + encodedPoint.length;
	}

	/**
	 * Get encoded point.
	 * 
	 * @return public key as encoded point
	 */
	public byte[] getEncodedPoint() {
		return Arrays.copyOf(encodedPoint, encodedPoint.length);
	}

	@Override
	public String toString(int indent) {
		StringBuilder sb = new StringBuilder();
		sb.append(super.toString(indent));
		String indentation = StringUtil.indentation(indent + 1);
		sb.append(indentation).append("Diffie-Hellman public value: ");
		sb.append(StringUtil.byteArray2HexString(encodedPoint, StringUtil.NO_SEPARATOR, 16));
		sb.append(StringUtil.lineSeparator());

		return sb.toString();
	}

}
