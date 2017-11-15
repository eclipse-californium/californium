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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - move EC curve params to SupportedGroup enum
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm.HashAlgorithm;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm.SignatureAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography.SupportedGroup;


/**
 * The server's ephemeral ECDH with ECDSA signatures.
 * 
 * See <a href="http://tools.ietf.org/html/rfc4492#section-5.4">
 * RFC 4492, section 5.4 Server Key Exchange</a> for details regarding
 * the message format.
 */
public final class ECDHServerKeyExchange extends ServerKeyExchange {

	private static final String MSG_UNKNOWN_CURVE_TYPE = "Unknown curve type [{0}]";
	private static final Logger LOGGER = Logger.getLogger(ECDHServerKeyExchange.class.getCanonicalName());

	// DTLS-specific constants ////////////////////////////////////////

	private static final int CURVE_TYPE_BITS = 8;
	private static final int NAMED_CURVE_BITS = 16;
	private static final int PUBLIC_LENGTH_BITS = 8;
	private static final int HASH_ALGORITHM_BITS = 8;
	private static final int SIGNATURE_ALGORITHM_BITS = 8;
	private static final int SIGNATURE_LENGTH_BITS = 16;

	/**
	 * The algorithm name to generate elliptic curve keypairs. See also <a href=
	 * "http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator"
	 * >KeyPairGenerator Algorithms</a>.
	 */
	private static final String KEYPAIR_GENERATOR_INSTANCE = "EC";

	/** The ECCurveType */
	// parameters are conveyed verbosely; underlying finite field is a prime
	// field
	private static final int EXPLICIT_PRIME = 1;
	// parameters are conveyed verbosely; underlying finite field is a
	// characteristic-2 field
	private static final int EXPLICIT_CHAR2 = 2;
	// a named curve is used
	private static final int NAMED_CURVE = 3;

	// Members ////////////////////////////////////////////////////////

	/** ephemeral keys */
	private ECPublicKey publicKey = null;

	private ECPoint point = null;
	private byte[] pointEncoded = null;

	private final int curveId;

	private byte[] signatureEncoded = null;

	/** The signature and hash algorithm which must be included into the digitally-signed struct. */
	private final SignatureAndHashAlgorithm signatureAndHashAlgorithm;

	// TODO right now only named curve is supported
	private int curveType = NAMED_CURVE;

	// Constructors //////////////////////////////////////////////////

	/**
	 * Called by server, generates ephemeral keys and signature.
	 * 
	 * @param signatureAndHashAlgorithm
	 *            the algorithm to use
	 * @param ecdhe
	 *            the ECDHE helper class
	 * @param serverPrivateKey
	 *            the server's private key
	 * @param clientRandom
	 *            the client's random (used for signature)
	 * @param serverRandom
	 *            the server's random (used for signature)
	 * @param namedCurveId
	 *            the named curve's id which will be used for the ECDH
	 * @param peerAddress the IP address and port of the peer this
	 *            message has been received from or should be sent to
	 * @throws GeneralSecurityException if generating the signature providing prove of
	 *            possession of the private key fails, e.g. due to an unsupported
	 *            signature or hash algorithm or an invalid key
	 */
	public ECDHServerKeyExchange(SignatureAndHashAlgorithm signatureAndHashAlgorithm, ECDHECryptography ecdhe,
			PrivateKey serverPrivateKey, Random clientRandom, Random serverRandom, int namedCurveId,
			InetSocketAddress peerAddress) throws GeneralSecurityException {

		this(signatureAndHashAlgorithm, namedCurveId, peerAddress);
		
		publicKey = ecdhe.getPublicKey();
		ECParameterSpec parameters = publicKey.getParams();

		point = publicKey.getW();
		pointEncoded = ECDHECryptography.encodePoint(point, parameters.getCurve());

		// make signature
		// See http://tools.ietf.org/html/rfc4492#section-2.2
		// These parameters MUST be signed with ECDSA using the private key
		// corresponding to the public key in the server's Certificate.
		Signature signature = Signature.getInstance(this.signatureAndHashAlgorithm.jcaName());
		signature.initSign(serverPrivateKey);

		updateSignature(signature, clientRandom, serverRandom);

		signatureEncoded = signature.sign();
	}

	/**
	 * Called when reconstructing the byte array.
	 * 
	 * @param signatureAndHashAlgorithm
	 *            the algorithm to use
	 * @param curveId
	 *            the named curve index
	 * @param pointEncoded
	 *            the point on the curve (encoded)
	 * @param signatureEncoded
	 *            the signature (encoded)
	 * @param peerAddress the IP address and port of the peer this
	 *            message has been received from or should be sent to
	 * @throws HandshakeException if the server's public key could not be re-constructed
	 *            from the parameters contained in the message
	 */
	private ECDHServerKeyExchange(SignatureAndHashAlgorithm signatureAndHashAlgorithm, int curveId, byte[] pointEncoded,
			byte[] signatureEncoded, InetSocketAddress peerAddress) throws HandshakeException {
		this(signatureAndHashAlgorithm, curveId, peerAddress);
		this.pointEncoded = Arrays.copyOf(pointEncoded, pointEncoded.length);
		this.signatureEncoded = Arrays.copyOf(signatureEncoded, signatureEncoded.length);
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
				LOGGER.log(Level.FINE, "Cannot re-create server's public key from params", e);
				throw new HandshakeException(
					String.format("Cannot re-create server's public key from params: %s", e.getMessage()),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, peerAddress));
			}
		}
	}

	private ECDHServerKeyExchange(SignatureAndHashAlgorithm signatureAndHashAlgorithm, int namedCurveId, InetSocketAddress peerAddress) {
		super(peerAddress);
		this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;
		this.curveId = namedCurveId;
	}

	// Serialization //////////////////////////////////////////////////

	// TODO this is called 4 times for Flight 4
	@Override
	public byte[] fragmentToByteArray() {
		DatagramWriter writer = new DatagramWriter();

		switch (curveType) {
		// TODO add support for other curve types
		case EXPLICIT_PRIME:
		case EXPLICIT_CHAR2:
			break;

		case NAMED_CURVE:
			writeNamedCurve(writer);
			break;

		default:
			LOGGER.log(Level.WARNING, MSG_UNKNOWN_CURVE_TYPE, curveType);
			break;
		}

		return writer.toByteArray();
	}

	private void writeNamedCurve(DatagramWriter writer) {
		// http://tools.ietf.org/html/rfc4492#section-5.4
		writer.write(NAMED_CURVE, CURVE_TYPE_BITS);
		writer.write(curveId, NAMED_CURVE_BITS);
		writer.write(pointEncoded.length, PUBLIC_LENGTH_BITS);
		writer.writeBytes(pointEncoded);

		// signature
		if (signatureEncoded != null) {
			// according to http://tools.ietf.org/html/rfc5246#section-A.7 the
			// signature algorithm must also be included
			writer.write(signatureAndHashAlgorithm.getHash().getCode(), HASH_ALGORITHM_BITS);
			writer.write(signatureAndHashAlgorithm.getSignature().getCode(), SIGNATURE_ALGORITHM_BITS);
			
			writer.write(signatureEncoded.length, SIGNATURE_LENGTH_BITS);
			writer.writeBytes(signatureEncoded);
		}
	}

	public static HandshakeMessage fromByteArray(byte[] byteArray, InetSocketAddress peerAddress) throws HandshakeException {
		DatagramReader reader = new DatagramReader(byteArray);
		int curveType = reader.read(CURVE_TYPE_BITS);
		switch (curveType) {
		// TODO right now only named curve supported
		case NAMED_CURVE:
			return readNamedCurve(reader, peerAddress);
		default:
			throw new HandshakeException(
					String.format(
							"Curve type [%s] received in ServerKeyExchange message from peer [%s] is unsupported",
							curveType, peerAddress),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, peerAddress));
		}
	}

	private static ECDHServerKeyExchange readNamedCurve(final DatagramReader reader, final InetSocketAddress peerAddress) throws HandshakeException {
		int curveId = reader.read(NAMED_CURVE_BITS);
		int length = reader.read(PUBLIC_LENGTH_BITS);
		byte[] pointEncoded = reader.readBytes(length);

		byte[] bytesLeft = reader.readBytesLeft();

		// default is SHA256withECDSA
		SignatureAndHashAlgorithm signAndHash = new SignatureAndHashAlgorithm(SignatureAndHashAlgorithm.HashAlgorithm.SHA256, SignatureAndHashAlgorithm.SignatureAlgorithm.ECDSA);

		byte[] signatureEncoded = null;
		if (bytesLeft.length > 0) {
			DatagramReader remainder = new DatagramReader(bytesLeft);
			int hashAlgorithm = remainder.read(HASH_ALGORITHM_BITS);
			int signatureAlgorithm = remainder.read(SIGNATURE_ALGORITHM_BITS);
			signAndHash = new SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm);
			length = remainder.read(SIGNATURE_LENGTH_BITS);
			signatureEncoded = remainder.readBytes(length);
		}

		return new ECDHServerKeyExchange(signAndHash, curveId, pointEncoded, signatureEncoded, peerAddress);
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public int getMessageLength() {
		int length = 0;
		switch (curveType) {
		case EXPLICIT_PRIME:
		case EXPLICIT_CHAR2:
			break;
		
		case NAMED_CURVE:
			// the signature length field uses 2 bytes, if a signature available
			int signatureLength = (signatureEncoded == null) ? 0 : 2 + 2 + signatureEncoded.length;
			length = 4 + pointEncoded.length + signatureLength;
			break;

		default:
			LOGGER.log(Level.WARNING, MSG_UNKNOWN_CURVE_TYPE, curveType);
			break;
		}
		
		return length;
	}

	/**
	 * Called by the client after receiving the server's
	 * {@link ServerKeyExchange} message. Verifies the contained signature.
	 * 
	 * @param serverPublicKey
	 *            the server's public key.
	 * @param clientRandom
	 *            the client's random (used in signature).
	 * @param serverRandom
	 *            the server's random (used in signature).
	 * @throws HandshakeException
	 *             if the signature could not be verified.
	 */
	public void verifySignature(PublicKey serverPublicKey, Random clientRandom, Random serverRandom) throws HandshakeException {
		if (signatureEncoded == null) {
			// no signature available, nothing to verify
			return;
		}
		boolean verified = false;
		try {
			Signature signature = Signature.getInstance(signatureAndHashAlgorithm.jcaName());
			signature.initVerify(serverPublicKey);

			updateSignature(signature, clientRandom, serverRandom);

			verified = signature.verify(signatureEncoded);

		} catch (GeneralSecurityException e) {
			LOGGER.log(Level.SEVERE,"Could not verify the server's signature.",e);
		}
		
		if (!verified) {
			String message = "The server's ECDHE key exchange message's signature could not be verified.";
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, getPeer());
			throw new HandshakeException(message, alert);
		}
	}

	/**
	 * Update the signature: SHA(ClientHello.random + ServerHello.random +
	 * ServerKeyExchange.params). See <a
	 * href="http://tools.ietf.org/html/rfc4492#section-5.4">RFC 4492, Section
	 * 5.4. Server Key Exchange</a> for further details on the signature format.
	 * 
	 * @param signature
	 *            the signature
	 * @param clientRandom
	 *            the client random
	 * @param serverRandom
	 *            the server random
	 * @throws SignatureException
	 *             the signature exception
	 */
	private void updateSignature(Signature signature, Random clientRandom, Random serverRandom) throws SignatureException {
		signature.update(clientRandom.getRandomBytes());
		signature.update(serverRandom.getRandomBytes());

		switch (curveType) {
		case EXPLICIT_PRIME:
		case EXPLICIT_CHAR2:

			break;

		case NAMED_CURVE:
			updateSignatureForNamedCurve(signature);
			break;

		default:
			LOGGER.log(Level.WARNING, MSG_UNKNOWN_CURVE_TYPE, curveType);
			break;
		}
	}

	private void updateSignatureForNamedCurve(Signature signature) throws SignatureException {
		signature.update((byte) NAMED_CURVE);
		signature.update((byte) (curveId >> 8));
		signature.update((byte) curveId);
		signature.update((byte) pointEncoded.length);
		signature.update(pointEncoded);
	}

	public ECPublicKey getPublicKey() {
		return publicKey;
	}

	public int getCurveId() {
		return curveId;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(super.toString());
		sb.append("\t\tDiffie-Hellman public key: ");
		sb.append(getPublicKey().toString());
		// bug in ECPublicKey.toString() gives object pointer
		sb.append(System.lineSeparator());

		return sb.toString();
	}
}
