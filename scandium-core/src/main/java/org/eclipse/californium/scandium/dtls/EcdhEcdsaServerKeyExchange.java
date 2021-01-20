/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 *                    derived from previous ECDHServerKeyExchange
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.NoPublicAPI;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.RandomManager;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalSignature;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The server's ephemeral ECDH with ECDSA signatures.
 * 
 * See <a href="http://tools.ietf.org/html/rfc4492#section-5.4">
 * RFC 4492, section 5.4 Server Key Exchange</a> for details regarding
 * the message format.
 * 
 * According <a href= "https://tools.ietf.org/html/rfc8422#section-5.1.1">RFC
 * 8422, 5.1.1. Supported Elliptic Curves Extension</a> only "named curves" are
 * valid, the "prime" and "char2" curve descriptions are deprecated. Also only
 * "UNCOMPRESSED" as point format is valid, the other formats have been
 * deprecated.
 * 
 * @since 2.3
 */
@NoPublicAPI
public final class EcdhEcdsaServerKeyExchange extends ECDHServerKeyExchange {

	private static final Logger LOGGER = LoggerFactory.getLogger(EcdhEcdsaServerKeyExchange.class);

	// DTLS-specific constants ////////////////////////////////////////

	private static final int HASH_ALGORITHM_BITS = 8;
	private static final int SIGNATURE_ALGORITHM_BITS = 8;
	private static final int SIGNATURE_LENGTH_BITS = 16;

	// Members ////////////////////////////////////////////////////////

	private final byte[] signatureEncoded;

	/** The signature and hash algorithm which must be included into the digitally-signed struct. */
	private final SignatureAndHashAlgorithm signatureAndHashAlgorithm;

	// Constructors //////////////////////////////////////////////////

	/**
	 * Called by server with generated ephemeral keys and generates signature.
	 * 
	 * @param signatureAndHashAlgorithm
	 *            the algorithm to use
	 * @param ecdhe
	 *            the ECDHE helper class. Contains generated ephemeral keys.
	 * @param serverPrivateKey
	 *            the server's private key
	 * @param clientRandom
	 *            the client's random (used for signature)
	 * @param serverRandom
	 *            the server's random (used for signature)
	 * @throws HandshakeException if generating the signature providing prove of
	 *            possession of the private key fails, e.g. due to an unsupported
	 *            signature or hash algorithm or an invalid key
	 */
	public EcdhEcdsaServerKeyExchange(SignatureAndHashAlgorithm signatureAndHashAlgorithm, XECDHECryptography ecdhe,
			PrivateKey serverPrivateKey, Random clientRandom, Random serverRandom) throws HandshakeException {
		super(ecdhe.getSupportedGroup(), ecdhe.getEncodedPoint());
		if (signatureAndHashAlgorithm == null) {
			throw new NullPointerException("signature and hash algorithm cannot be null");
		}
		this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;

		// make signature
		// See http://tools.ietf.org/html/rfc4492#section-2.2
		// These parameters MUST be signed with ECDSA using the private key
		// corresponding to the public key in the server's Certificate.
		ThreadLocalSignature localSignature = signatureAndHashAlgorithm.getThreadLocalSignature();
		try {
			Signature signature = localSignature.currentWithCause();
			signature.initSign(serverPrivateKey, RandomManager.currentSecureRandom());
			updateSignature(signature, clientRandom, serverRandom);
			signatureEncoded = signature.sign();
		} catch (GeneralSecurityException e) {
			throw new HandshakeException(
					String.format("Server failed to sign key exchange: %s", e.getMessage()),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER));
		}
	}

	/**
	 * Called when reconstructing from the byte array.
	 * 
	 * @param signatureAndHashAlgorithm
	 *            the algorithm to use
	 * @param supportedGroup
	 *            the supported group (curve)
	 * @param encodedPoint
	 *            the encoded point of the other peeer (public key)
	 * @param signatureEncoded
	 *            the signature (encoded)
	 * @throws HandshakeException if the server's public key could not be re-constructed
	 *            from the parameters contained in the message
	 */
	private EcdhEcdsaServerKeyExchange(SignatureAndHashAlgorithm signatureAndHashAlgorithm, SupportedGroup supportedGroup, byte[] encodedPoint,
			byte[] signatureEncoded) {
		super(supportedGroup, encodedPoint);
		if (signatureAndHashAlgorithm == null) {
			throw new NullPointerException("signature and hash algorithm cannot be null");
		}
		this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;
		this.signatureEncoded = signatureEncoded;
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	public int getMessageLength() {
		// the signature length field uses 2 bytes, if a signature available
		int signatureLength = (signatureEncoded == null) ? 0 : 2 + 2 + signatureEncoded.length;
		return getNamedCurveLength() + signatureLength;
	}

	@Override
	public byte[] fragmentToByteArray() {
		DatagramWriter writer = new DatagramWriter();
		writeNamedCurve(writer);

		// signature
		if (signatureEncoded != null) {
			// according to http://tools.ietf.org/html/rfc5246#section-A.7 the
			// signature algorithm must also be included
			writer.write(signatureAndHashAlgorithm.getHash().getCode(), HASH_ALGORITHM_BITS);
			writer.write(signatureAndHashAlgorithm.getSignature().getCode(), SIGNATURE_ALGORITHM_BITS);

			writer.writeVarBytes(signatureEncoded, SIGNATURE_LENGTH_BITS);
		}
		return writer.toByteArray();
	}

	public static HandshakeMessage fromReader(DatagramReader reader) throws HandshakeException {
		EcdhData ecdhData = readNamedCurve(reader);
		// default is SHA256withECDSA
		SignatureAndHashAlgorithm signAndHash = new SignatureAndHashAlgorithm(SignatureAndHashAlgorithm.HashAlgorithm.SHA256, SignatureAndHashAlgorithm.SignatureAlgorithm.ECDSA);

		byte[] signatureEncoded = null;
		if (reader.bytesAvailable()) {
			int hashAlgorithm = reader.read(HASH_ALGORITHM_BITS);
			int signatureAlgorithm = reader.read(SIGNATURE_ALGORITHM_BITS);
			signAndHash = new SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm);
			signatureEncoded = reader.readVarBytes(SIGNATURE_LENGTH_BITS);
		}
		return new EcdhEcdsaServerKeyExchange(signAndHash, ecdhData.supportedGroup, ecdhData.encodedPoint, signatureEncoded);
	}

	// Methods ////////////////////////////////////////////////////////

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
			ThreadLocalSignature localSignature = signatureAndHashAlgorithm.getThreadLocalSignature();
			Signature signature = localSignature.currentWithCause();
			signature.initVerify(serverPublicKey);

			updateSignature(signature, clientRandom, serverRandom);

			verified = signature.verify(signatureEncoded);

		} catch (GeneralSecurityException e) {
			LOGGER.error("Could not verify the server's signature.",e);
		}

		if (!verified) {
			String message = "The server's ECDHE key exchange message's signature could not be verified.";
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.DECRYPT_ERROR);
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
		signature.update(clientRandom.getBytes());
		signature.update(serverRandom.getBytes());
		updateSignatureForNamedCurve(signature);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(super.toString());
		if (signatureEncoded != null)
		sb.append("\t\tSignature: ");
		sb.append(signatureAndHashAlgorithm.toString()).append("-").append(StringUtil.byteArray2HexString(signatureEncoded, StringUtil.NO_SEPARATOR, 10));
		sb.append(StringUtil.lineSeparator());

		return sb.toString();
	}
}
