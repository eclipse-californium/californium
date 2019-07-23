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
 *    Vikram (University of Rostock)- Initial creation, adapted from ECDHServerKeyExchange
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography.SupportedGroup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Generates server ephemeral ECDH keys for Dtls PSK mode.
 * <p>
 * Server must send the {@code ServerKeyExchange} message even if the PSK identity hint is not provided.
 * 
 * See <a href="https://tools.ietf.org/html/rfc5489#section-2">RFC 5489</a> for details.
 */
public final class EcdhPskServerKeyExchange extends ServerKeyExchange {

	private static final Logger LOGGER = LoggerFactory.getLogger(EcdhPskServerKeyExchange.class.getCanonicalName());

	private static final int IDENTITY_HINT_LENGTH_BITS = 16;
	private static final String MSG_UNKNOWN_CURVE_TYPE = "Unknown curve type [{}]";
	private static final int CURVE_TYPE_BITS = 8;
	private static final int NAMED_CURVE_BITS = 16;
	private static final int PUBLIC_LENGTH_BITS = 8;

	/**
	 * The algorithm name to generate elliptic curve keypairs. See also <a href=
	 * "http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator"
	 * >KeyPairGenerator Algorithms</a>.
	 */
	private static final String KEYPAIR_GENERATOR_INSTANCE = "EC";

	/** The hint in cleartext. */
	private final PskPublicInformation hint;

	/** The ECCurveType */

	/** parameters are conveyed verbosely; underlying finite field is a prime 
	 * field
	*/ 
	private static final int EXPLICIT_PRIME = 1;

	/** parameters are conveyed verbosely; underlying finite field is a 
	 * characteristic-2 field
	*/ 
	private static final int EXPLICIT_CHAR2 = 2;

	/** a named curve is used */
	private static final int NAMED_CURVE = 3;

	/** ephemeral public key */
	private ECPublicKey publicKey = null;

	private ECPoint point = null;
	private byte[] pointEncoded = null;

	private final int curveId;

	// TODO right now only named curve is supported
	private int curveType = NAMED_CURVE;

	/**
	 * Creates a new key exchange message with psk hint as clear text and ServerDHParams.
	 * 
	 * @see <a href="http://tools.ietf.org/html/rfc4279#section-3">RFC 4279</a>
	 * @param pskHint preshared key hint in clear text
	 * @param ecdhe {@code ECDHECryptography}
	 * @param clientRandom nonce
	 * @param serverRandom nonce
	 * @param namedCurveId ec curve used 
	 * @param peerAddress peer's address
	 * @throws NullPointerException if any of the arguments ecdhe, 
	 * clientRandom and serverRandom are {@code null}
	 */
	public EcdhPskServerKeyExchange(PskPublicInformation pskHint, ECDHECryptography ecdhe, Random clientRandom, Random serverRandom, 
			int namedCurveId, InetSocketAddress peerAddress) {	
		super(peerAddress);	
		if (ecdhe == null) {
			throw new NullPointerException("ECDHECryptography class object cannot be null");
		}
		if (clientRandom == null || serverRandom == null) {
			throw new NullPointerException("nonce cannot be null");
		}
		this.hint = pskHint;
		this.curveId = namedCurveId;
		publicKey = ecdhe.getPublicKey();
		ECParameterSpec parameters = publicKey.getParams();
		point = publicKey.getW();
		pointEncoded = ECDHECryptography.encodePoint(point, parameters.getCurve());
	}

	private EcdhPskServerKeyExchange(byte[] hintEncoded, int curveId, byte[] pointEncoded, InetSocketAddress peerAddress) throws HandshakeException {		
		super(peerAddress);
		this.curveId = curveId;
		this.hint = PskPublicInformation.fromByteArray(hintEncoded);
		if (pointEncoded == null) {
			throw new NullPointerException("ephemeral public key cannot be null");
		}
		this.pointEncoded = Arrays.copyOf(pointEncoded, pointEncoded.length);
		// re-create public key from params
		SupportedGroup group = SupportedGroup.fromId(curveId);
		if (group == null || !group.isUsable()) {
			throw new HandshakeException(
				String.format("Server used unsupported elliptic curve (%d) for ECDH", curveId),
				new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, peerAddress));
		} else {
			try {
				point = ECDHECryptography.decodePoint(pointEncoded, group.getEcParams().getCurve());
				KeyFactory keyFactory = KeyFactory.getInstance(KEYPAIR_GENERATOR_INSTANCE);
				publicKey = (ECPublicKey) keyFactory.generatePublic(new ECPublicKeySpec(point, group.getEcParams()));
			} catch (GeneralSecurityException e) {
				LOGGER.debug("Cannot re-create server's public key from params", e);
				throw new HandshakeException(
					String.format("Cannot re-create server's public key from params: %s", e.getMessage()),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, peerAddress));
			}
		}
	}

	// TODO this is called 4 times for Flight 4
	@Override
	public byte[] fragmentToByteArray() {
		DatagramWriter writer = new DatagramWriter();
		writer.write(hint.length(), IDENTITY_HINT_LENGTH_BITS);
		writer.writeBytes(hint.getBytes());
		switch (curveType) {
		// TODO add support for other curve types
		case EXPLICIT_PRIME:
		case EXPLICIT_CHAR2:
			break;
		case NAMED_CURVE:
			writeNamedCurve(writer);
			break;
		default:
			LOGGER.warn(MSG_UNKNOWN_CURVE_TYPE, curveType);
			break;
		}
		return writer.toByteArray();
	}
	
	
	private void writeNamedCurve(DatagramWriter writer) {
		writer.write(NAMED_CURVE, CURVE_TYPE_BITS);
		writer.write(curveId, NAMED_CURVE_BITS);
		writer.write(pointEncoded.length, PUBLIC_LENGTH_BITS);
		writer.writeBytes(pointEncoded);
	}
	
	/**
	 * Deserialize byte array to key exchange message.
	 * 
	 * @param byteArray byte array of key exchange message
	 * @param peerAddress peer address
	 * @return {@code EcdhPskServerKeyExchange}
	 * @throws HandshakeException if the byte array includes unsupported curve
	 * @throws NullPointerException if either byteArray or peerAddress is {@code null}
	 */
	public static HandshakeMessage fromByteArray(byte[] byteArray, InetSocketAddress peerAddress) throws HandshakeException {
		if (byteArray == null) {
			throw new NullPointerException("byte array cannot be null");
		}
		if (peerAddress == null) {
			throw new NullPointerException("peer address cannot be null");
		}
		DatagramReader reader = new DatagramReader(byteArray);
		int hintLength = reader.read(IDENTITY_HINT_LENGTH_BITS);
		byte[] hintEncoded = reader.readBytes(hintLength);
		int curveType = reader.read(CURVE_TYPE_BITS);
		switch (curveType) {
		// TODO right now only named curve supported
		case NAMED_CURVE:
			int curveId = reader.read(NAMED_CURVE_BITS);
			int length = reader.read(PUBLIC_LENGTH_BITS);
			byte[] pointEncoded = reader.readBytes(length);
			return new EcdhPskServerKeyExchange(hintEncoded, curveId, pointEncoded, peerAddress);
		default:
			throw new HandshakeException(
					String.format("Curve type [%s] received in ServerKeyExchange message from peer [%s] is unsupported",
							curveType, peerAddress),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, peerAddress));
		}
	}

	@Override
	public int getMessageLength() {
		int length = 0;
		switch (curveType) {
		case EXPLICIT_PRIME:
		case EXPLICIT_CHAR2:
			break;		
		case NAMED_CURVE:
			length = 6 + hint.length() + pointEncoded.length;
			break;
		default:
			LOGGER.warn(MSG_UNKNOWN_CURVE_TYPE, curveType);
			break;
		}		
		return length;
	}
	
	/**
	 * This method returns the ephemeral (EC) Public key from {@code EcdhPskServerKeyExchange}.
	 * 
	 * @return - EC Public key 
	 */
	public ECPublicKey getPublicKey() {
		return publicKey;
	}
	
	/**
	 * This method returns the EC curve Id used for generating the ephemeral DH key.
	 * 
	 * @return - int curve id
	 */
	public int getCurveId() {
		return curveId;
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
		sb.append(super.toString());
		if (hint.isEmpty()) {
			sb.append("\t\tPSK Identity Hint: ").append("psk hint not present");
		} else {
			sb.append("\t\tPSK Identity Hint: ").append(hint);
		}
		sb.append("\t\tEC Diffie-Hellman public key: ");
		sb.append(getPublicKey().toString());
		// bug in ECPublicKey.toString() gives object pointer
		sb.append(StringUtil.lineSeparator());

		return sb.toString();
	}
}
