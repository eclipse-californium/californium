/*******************************************************************************
 * Copyright 2018 University of Rostock, Institute of Applied Microelectronics and Computer Engineering
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
 *    Vikram (University of Rostock)- Initial creation, adapted from ECDHClientKeyExchange
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.NoPublicAPI;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * {@link ClientKeyExchange} message for PSK-ECDH based key exchange methods.
 * Contains the client's ephemeral public key as encoded point and the PSK
 * idenity. See <a href="https://tools.ietf.org/html/rfc5489#section-2">RFC
 * 5489</a> for details. It is assumed, that the client's ECDH public key is not
 * in the client's certificate, so it must be provided here.
 * 
 * According <a href= "https://tools.ietf.org/html/rfc8422#section-5.1.1">RFC
 * 8422, 5.1.1. Supported Elliptic Curves Extension</a> only "named curves" are
 * valid, the "prime" and "char2" curve descriptions are deprecated. Also only
 * "UNCOMPRESSED" as point format is valid, the other formats have been
 * deprecated.
 */
@NoPublicAPI
public final class EcdhPskClientKeyExchange extends ECDHClientKeyExchange {

	private static final int IDENTITY_LENGTH_BITS = 16; // opaque <0..2^16-1>;

	/**
	 *See <a href="https://tools.ietf.org/html/rfc5489#section-2">RFC 5489</a>.
	 */
	private final PskPublicInformation identity;

	/**
	 * Creates a new key exchange message for an identity hint and a public key.
	 * 
	 * @param identity PSK identity as public information
	 * @param encodedPoint ephemeral public key as encoded point
	 * @param peerAddress peer's address
	 * @throws NullPointerException if either identity or clietPublicKey are {@code null}
	 */
	public EcdhPskClientKeyExchange(PskPublicInformation identity, byte[] encodedPoint, InetSocketAddress peerAddress) {
		super(encodedPoint, peerAddress);
		if (identity == null) {
			throw new NullPointerException("identity cannot be null");
		}
		this.identity = identity;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Write the identity and encoded point.
	 */
	@Override
	protected void writeFragment(DatagramWriter writer) {
		writer.write(identity.length(), IDENTITY_LENGTH_BITS);
		writer.writeBytes(identity.getBytes());
		super.writeFragment(writer);
	}

	/**
	 * Creates a new client key exchange instance from its byte representation.
	 * 
	 * @param reader reader for the binary encoding of the message.
	 * @param peerAddress peer address
	 * @return created client key exchange message
	 * @throws NullPointerException if peerAddress is {@code null}
	 */
	public static HandshakeMessage fromReader(DatagramReader reader, InetSocketAddress peerAddress) {
		if (peerAddress == null) {
			throw new NullPointerException("peer address cannot be null");
		}
		int identityLength = reader.read(IDENTITY_LENGTH_BITS);
		byte[] identityEncoded = reader.readBytes(identityLength);
		PskPublicInformation identity = PskPublicInformation.fromByteArray(identityEncoded);
		byte[] pointEncoded = readEncodedPoint(reader);
		return new EcdhPskClientKeyExchange(identity, pointEncoded, peerAddress);
	}

	@Override
	public int getMessageLength() {
		return 2 + identity.length() + super.getMessageLength();
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("\t\t Encoded identity value: ");
		sb.append(identity).append(StringUtil.lineSeparator());;
		sb.append(super.toString());
		sb.append(StringUtil.lineSeparator());
		return sb.toString();
	}

	/**
	 * This method returns the PSK identity as public information.
	 * 
	 * @return psk identity
	 */
	public PskPublicInformation getIdentity() {
		return identity;
	}
}
