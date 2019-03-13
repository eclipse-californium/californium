/*******************************************************************************
 * Copyright 2018 University of Rostock, Institute of Applied Microelectronics and Computer Engineering
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
 *    Vikram (University of Rostock)- Initial creation, adapted from ECDHClientKeyExchange
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography;

/**
 * Generates client ephemeral ECDH keys for Dtls ECDH_PSK mode.
 * 
 * See <a href="https://tools.ietf.org/html/rfc5489#section-2">RFC 5489</a> for details.
 */
public final class EcdhPskClientKeyExchange extends ClientKeyExchange {


	protected static final int LENGTH_BITS = 8; // opaque point <1..2^8-1>
	private static final int IDENTITY_LENGTH_BITS = 16; // opaque <0..2^16-1>;

	/**
	 *See <a href="https://tools.ietf.org/html/rfc5489#section-2">RFC 5489</a>.
	 */
	private final PskPublicInformation identity;
	private final byte[] pointEncoded;
	
	/**
	 * Creates a new key exchange message for an identity hint and a public key.
	 * 
	 * @param identity PSK identity as public information
	 * @param clientPublicKey ephemeral public key of client
	 * @param peerAddress peer's address
	 * @throws NullPointerException if either hint or clietPublicKey are {@code null}
	 */
	public EcdhPskClientKeyExchange(PskPublicInformation identity, PublicKey clientPublicKey, InetSocketAddress peerAddress) {
		super(peerAddress);
		if (identity == null) {
			throw new NullPointerException("identity cannot be null");
		}
		if (clientPublicKey == null) {
			throw new NullPointerException("ephemeral public key cannot be null");
		}
		this.identity = identity;
		ECPublicKey publicKey = (ECPublicKey) clientPublicKey;
		ECPoint point = publicKey.getW();
		ECParameterSpec params = publicKey.getParams();
			
		this.pointEncoded = ECDHECryptography.encodePoint(point, params.getCurve());
	}
	
	/**
	 * Creates a new key exchange message for an identity hint and a public key.
	 * 
	 * @param identityEncoded opaque encoded PSK identity hint for server
	 * @param pointEncoded ephemeral public key of client (encoded point)
	 * @param peerAddress peer's address
	 * @throws NullPointerException if either hintEncoded or pointEncoded are {@code null}
	 */
	public EcdhPskClientKeyExchange(byte[] identityEncoded, byte[] pointEncoded, InetSocketAddress peerAddress) {
		super(peerAddress);
		if (identityEncoded ==null) {
			throw new NullPointerException("identity cannot be null");
		}
		if (pointEncoded == null) {
			throw new NullPointerException("epehemeral public key cannot be null");
		}
		this.identity = PskPublicInformation.fromByteArray(identityEncoded);
		this.pointEncoded = Arrays.copyOf(pointEncoded, pointEncoded.length);
	}

	@Override
	public byte[] fragmentToByteArray() {
		DatagramWriter writer = new DatagramWriter();
		writer.write(identity.length(), IDENTITY_LENGTH_BITS);
		writer.writeBytes(identity.getBytes());
		writer.write(pointEncoded.length, LENGTH_BITS);
		writer.writeBytes(pointEncoded);
		return writer.toByteArray();
	}
	
	/**
	 * Deserialize byte array to key exchange message.
	 * 
	 * @param byteArray byte array of key exchange message
	 * @param peerAddress peer address
	 * @return created client key exchange message
	 * @throws NullPointerException if either byteArray or peerAddress is {@code null}
	 */
	public static HandshakeMessage fromByteArray(byte[] byteArray, InetSocketAddress peerAddress) {
		if (byteArray == null) {
			throw new NullPointerException("byte array cannot be null");
		}
		if (peerAddress == null) {
			throw new NullPointerException("peer address cannot be null");
		}
		DatagramReader reader = new DatagramReader(byteArray);
		int identityLength = reader.read(IDENTITY_LENGTH_BITS);
		byte[] identityEncoded = reader.readBytes(identityLength);	
		int length = reader.read(LENGTH_BITS);
		byte[] pointEncoded = reader.readBytes(length);
		return new EcdhPskClientKeyExchange(identityEncoded, pointEncoded, peerAddress);
	}
		

	@Override
	public int getMessageLength() {
		return 3 + identity.length() + pointEncoded.length;
	}

	/**
	 * This method returns the ephemeral public key (encoded point) from {@link ClientKeyExchange}.
	 * 
	 * @return encoded point in byte array
	 */
	public byte[] getEncodedPoint() {
		return Arrays.copyOf(pointEncoded, pointEncoded.length);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(super.toString());
		sb.append("\t\t Encoded identity value: ");
		sb.append(identity).append(StringUtil.lineSeparator());;
		sb.append("\t\tEC Diffie-Hellman public value: ");		
		sb.append(StringUtil.byteArray2Hex(pointEncoded));
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
