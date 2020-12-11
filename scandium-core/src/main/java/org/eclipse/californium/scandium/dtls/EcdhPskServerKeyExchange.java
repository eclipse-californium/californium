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
 *    Vikram (University of Rostock)- Initial creation, adapted from ECDHServerKeyExchange
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.NoPublicAPI;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;

/**
 * {@link ServerKeyExchange} message for PSK-ECDH based key exchange methods.
 * Contains the server's ephemeral public key as encoded point and the PSK
 * hint. See <a href="https://tools.ietf.org/html/rfc5489#section-2">RFC
 * 5489</a> for details. It is assumed, that the server's ECDH public key is not
 * in the servers's certificate, so it must be provided here.
 * 
 * According <a href= "https://tools.ietf.org/html/rfc8422#section-5.1.1">RFC
 * 8422, 5.1.1. Supported Elliptic Curves Extension</a> only "named curves" are
 * valid, the "prime" and "char2" curve descriptions are deprecated. Also only
 * "UNCOMPRESSED" as point format is valid, the other formats have been
 * deprecated.
 */
@NoPublicAPI
public final class EcdhPskServerKeyExchange extends ECDHServerKeyExchange {

	private static final int IDENTITY_HINT_LENGTH_BITS = 16;

	/** The hint in cleartext. */
	private final PskPublicInformation hint;

	/**
	 * Creates a new key exchange message with psk hint as clear text and ServerDHParams.
	 * 
	 * @see <a href="http://tools.ietf.org/html/rfc4279#section-3">RFC 4279</a>
	 * @param pskHint preshared key hint in clear text
	 * @param ecdhe {@code XECDHECryptography} including the supported group and the peer's public key
	 * @throws NullPointerException if the arguments pskHint or ecdhe are {@code null}
	 */
	public EcdhPskServerKeyExchange(PskPublicInformation pskHint, XECDHECryptography ecdhe) {
		super(ecdhe.getSupportedGroup(), ecdhe.getEncodedPoint());
		if (pskHint == null) {
			throw new NullPointerException("PSK hint must not be null");
		}
		this.hint = pskHint;
	}

	private EcdhPskServerKeyExchange(byte[] hintEncoded, SupportedGroup supportedGroup, byte[] encodedPoint) throws HandshakeException {		
		super(supportedGroup, encodedPoint);
		this.hint = PskPublicInformation.fromByteArray(hintEncoded);
	}

	@Override
	public byte[] fragmentToByteArray() {
		DatagramWriter writer = new DatagramWriter();
		writer.writeVarBytes(hint, IDENTITY_HINT_LENGTH_BITS);
		writeNamedCurve(writer);
		return writer.toByteArray();
	}

	/**
	 * Creates a new server key exchange instance from its byte representation.
	 * 
	 * @param reader reader for the binary encoding of the message.
	 * @return {@code EcdhPskServerKeyExchange}
	 * @throws HandshakeException if the byte array includes unsupported curve
	 * @throws NullPointerException if either byteArray or peerAddress is {@code null}
	 */
	public static HandshakeMessage fromReader(DatagramReader reader) throws HandshakeException {
		byte[] hintEncoded = reader.readVarBytes(IDENTITY_HINT_LENGTH_BITS);
		EcdhData ecdhData = readNamedCurve(reader);
		return new EcdhPskServerKeyExchange(hintEncoded, ecdhData.supportedGroup, ecdhData.encodedPoint);
	}

	@Override
	public int getMessageLength() {
		return 2 + hint.length() + getNamedCurveLength();
	}

	/**
	 * This method returns the preshared key hint used by server in {@code ServerKeyExchange}
	 * message. If psk hint not present this will return an empty string.
	 * 
	 * @return preshared key hint as clear text.
	 */
	public PskPublicInformation getHint() {
		return hint;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		if (hint.isEmpty()) {
			sb.append("\t\tPSK Identity Hint: ").append("psk hint not present");
		} else {
			sb.append("\t\tPSK Identity Hint: ").append(hint);
		}
		sb.append(StringUtil.lineSeparator());
		sb.append(super.toString());

		return sb.toString();
	}
}
