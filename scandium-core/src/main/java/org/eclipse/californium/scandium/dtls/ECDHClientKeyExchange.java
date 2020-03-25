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
import java.util.Arrays;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.NoPublicAPI;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * {@link ClientKeyExchange} message for all ECDH based key exchange methods.
 * Contains the client's ephemeral public key as encoded point. See
 * <a href="http://tools.ietf.org/html/rfc4492#section-5.7">RFC 4492</a> for
 * further details. It is assumed, that the client's ECDH public key is not in
 * the client's certificate, so it must be provided here.
 * 
 * According <a href= "https://tools.ietf.org/html/rfc8422#section-5.1.1">RFC
 * 8422, 5.1.1. Supported Elliptic Curves Extension</a> only "named curves" are
 * valid, the "prime" and "char2" curve descriptions are deprecated. Also only
 * "UNCOMPRESSED" as point format is valid, the other formats have been
 * deprecated.
 */
@NoPublicAPI
public class ECDHClientKeyExchange extends ClientKeyExchange {

	// DTLS-specific constants ////////////////////////////////////////

	private static final int LENGTH_BITS = 8; // opaque point <1..2^8-1>

	// Members ////////////////////////////////////////////////////////

	/**
	 * Ephemeral public key of client as encoded point.
	 */
	private final byte[] encodedPoint;

	// Constructors ///////////////////////////////////////////////////

	/**
	 * Create a {@link ClientKeyExchange} message.
	 * 
	 * @param encodedPoint
	 *            the client's ephemeral public key (as encoded point).
	 * @param peerAddress the IP address and port of the peer this
	 *            message has been received from or should be sent to
	 */
	public ECDHClientKeyExchange(byte[] encodedPoint, InetSocketAddress peerAddress) {
		super(peerAddress);
		if (encodedPoint == null) {
			throw new NullPointerException("encoded point cannot be null");
		}
		this.encodedPoint = encodedPoint;
	}

	// Serialization //////////////////////////////////////////////////

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
		writer.write(encodedPoint.length, LENGTH_BITS);
		writer.writeBytes(encodedPoint);
	}

	/**
	 * Read encoded point from reader.
	 * 
	 * @param reader reader
	 * @return encoded point
	 */
	protected static byte[] readEncodedPoint(DatagramReader reader) {
		int length = reader.read(LENGTH_BITS);
		return reader.readBytes(length);
	}

	public static HandshakeMessage fromReader(DatagramReader reader, InetSocketAddress peerAddress) {
		byte[] pointEncoded = readEncodedPoint(reader);
		return new ECDHClientKeyExchange(pointEncoded, peerAddress);
	}

	// Methods ////////////////////////////////////////////////////////

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
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(super.toString());
		sb.append("\t\tDiffie-Hellman public value: ");
		sb.append(StringUtil.byteArray2HexString(encodedPoint));
		sb.append(StringUtil.lineSeparator());

		return sb.toString();
	}

}
