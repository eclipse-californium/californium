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
package org.eclipse.californium.scandium.dtls.cipher;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import org.eclipse.californium.scandium.util.ByteArrayUtils;

/**
 * A helper class to execute the ECDHE key agreement and key generation.
 */
public class ECDHECryptography {

	// Logging ////////////////////////////////////////////////////////

	protected static final Logger LOGGER = Logger.getLogger(ECDHECryptography.class.getCanonicalName());

	// Static members /////////////////////////////////////////////////

	/**
	 * The algorithm for the elliptic curve keypair generation. See also <a
	 * href=
	 * "http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator"
	 * >KeyPairGenerator Algorithms</a>.
	 */
	private static final String KEYPAIR_GENERATOR_INSTANCE = "EC";

	/**
	 * Elliptic Curve Diffie-Hellman algorithm name. See also <a href=
	 * "http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyAgreement"
	 * >KeyAgreement Algorithms</a>.
	 */
	private static final String KEY_AGREEMENT_INSTANCE = "ECDH";

	/**
	 * Maps the named curves indices to their names.
	 * 
	 * See <a href="http://tools.ietf.org/html/rfc4492#section-5.1.1">RFC 4492,
	 * Section 5.1.1 Supported Elliptic Curves Extension</a>
	 */
	public final static String[] NAMED_CURVE_TABLE = new String[] { null, // 0
			"sect163k1", // 1
			"sect163r1", // 2
			"sect163r2", // 3
			"sect193r1", // 4
			"sect193r2", // 5
			"sect233k1", // 6
			"sect233r1", // 7
			"sect239k1", // 8
			"sect283k1", // 9
			"sect283r1", // 10
			"sect409k1", // 11
			"sect409r1", // 12
			"sect571k1", // 13
			"sect571r1", // 14
			"secp160k1", // 15
			"secp160r1", // 16
			"secp160r2", // 17
			"secp192k1", // 18
			"secp192r1", // 19
			"secp224k1", // 20
			"secp224r1", // 21
			"secp256k1", // 22
			"secp256r1", // 23
			"secp384r1", // 24
			"secp521r1" // 25
	};

	// Members ////////////////////////////////////////////////////////
	
	/** The ephemeral private key. */
	private ECPrivateKey privateKey;
	
	/** The ephemeral public key. */
	private ECPublicKey publicKey;

	// Constructors ///////////////////////////////////////////////////

	/**
	 * Called by Server, create ephemeral key ECDH keypair.
	 * 
	 * @param namedCurveId
	 *            the ID of the named curve which will be used.
	 */
	public ECDHECryptography(int namedCurveId) {
		// create ephemeral key pair
		try {
			String namedCurve = NAMED_CURVE_TABLE[namedCurveId];

			// initialize the key pair generator
			KeyPairGenerator kpg;
			kpg = KeyPairGenerator.getInstance(KEYPAIR_GENERATOR_INSTANCE);
			ECGenParameterSpec params = new ECGenParameterSpec(namedCurve);
			kpg.initialize(params, new SecureRandom());

			KeyPair kp = kpg.generateKeyPair();

			privateKey = (ECPrivateKey) kp.getPrivate();
			publicKey = (ECPublicKey) kp.getPublic();
		} catch (GeneralSecurityException e) {
			LOGGER.log(Level.SEVERE,"Could not generate the ECDHE keypair.",e);
		}

	}

	/**
	 * Called by client, with parameters provided by server.
	 * 
	 * @param params
	 *            the parameters provided by the server's ephemeral public key.
	 */
	public ECDHECryptography(ECParameterSpec params) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEYPAIR_GENERATOR_INSTANCE);
			keyPairGenerator.initialize(params, new SecureRandom());

			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			privateKey = (ECPrivateKey) keyPair.getPrivate();
			publicKey = (ECPublicKey) keyPair.getPublic();

		} catch (GeneralSecurityException e) {
			LOGGER.log(Level.SEVERE,"Could not generate the ECDHE keypair.",e);
		}
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(ECPrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public ECPublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(ECPublicKey publicKey) {
		this.publicKey = publicKey;
	}

	/**
	 * Called by the server. Extracts the client's public key from the encoded
	 * point and then runs the specified key agreement algorithm (ECDH) to
	 * generate the premaster secret.
	 * 
	 * @param encodedPoint
	 *            the client's public key (encoded)
	 * @return the premaster secret
	 */
	public SecretKey getSecret(byte[] encodedPoint) {
		SecretKey secretKey = null;
		try {
			// extract public key
			ECParameterSpec params = publicKey.getParams();
			ECPoint point = decodePoint(encodedPoint, params.getCurve());

			KeyFactory keyFactory = KeyFactory.getInstance(KEYPAIR_GENERATOR_INSTANCE);
			ECPublicKeySpec keySpec = new ECPublicKeySpec(point, params);
			PublicKey peerPublicKey = keyFactory.generatePublic(keySpec);

			secretKey = getSecret(peerPublicKey);

		} catch (Exception e) {
			LOGGER.log(Level.SEVERE,"Could not generate the premaster secret.",e);
		}
		return secretKey;
	}

	/**
	 * Runs the specified key agreement algorithm (ECDH) to generate the
	 * premaster secret.
	 * 
	 * @param peerPublicKey
	 *            the peer's ephemeral public key.
	 * @return the premaster secret.
	 */
	public SecretKey getSecret(PublicKey peerPublicKey) {
		SecretKey secretKey = null;
		try {
			KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_INSTANCE);
			keyAgreement.init(privateKey);
			keyAgreement.doPhase(peerPublicKey, true);
			
			secretKey = keyAgreement.generateSecret("TlsPremasterSecret");
		} catch (Exception e) {
			LOGGER.log(Level.SEVERE,"Could not generate the premaster secret.",e);
		}
		return secretKey;
	}
	
	// Serialization //////////////////////////////////////////////////
	
	/**
	 * Decodes an EC point according to the X9.62 specification.
	 * 
	 * @param encoded
	 *            the encoded EC point.
	 * @param curve
	 *            the elliptic curve the point lies on.
	 * @return the EC point.
	 */
	public static ECPoint decodePoint(byte[] encoded, EllipticCurve curve) {
		if ((encoded.length == 0) || (encoded[0] != 0x04)) {
			LOGGER.severe("Only uncompressed point format supported.");
			return null;
		}
		
		int fieldSize = (curve.getField().getFieldSize() + 7) / 8;
		if (encoded.length != (fieldSize * 2) + 1) {
			LOGGER.severe("Point does not match field size.");
			return null;
		}
		byte[] xb = new byte[fieldSize];
		byte[] yb = new byte[fieldSize];
		
		System.arraycopy(encoded, 1, xb, 0, fieldSize);
		System.arraycopy(encoded, fieldSize + 1, yb, 0, fieldSize);
		
		return new ECPoint(new BigInteger(1, xb), new BigInteger(1, yb));
	}
	
	/**
	 * Encodes an EC point according to the X9.62 specification.
	 * 
	 * @param point
	 *            the EC point to be encoded.
	 * @param curve
	 *            the elliptic curve the point lies on.
	 * @return the encoded EC point.
	 */
	public static byte[] encodePoint(ECPoint point, EllipticCurve curve) {
		// get field size in bytes (rounding up)
		int fieldSize = (curve.getField().getFieldSize() + 7) / 8;
		
		byte[] xb = ByteArrayUtils.trimZeroes(point.getAffineX().toByteArray());
		byte[] yb = ByteArrayUtils.trimZeroes(point.getAffineY().toByteArray());
		
		if ((xb.length > fieldSize) || (yb.length > fieldSize)) {
			LOGGER.severe("Point coordinates do not match field size.");
			return null;
		}
		
		// 1 byte (compression state) + twice field size
		byte[] encoded = new byte[1 + (fieldSize * 2)];
		encoded[0] = 0x04; // uncompressed
		System.arraycopy(xb, 0, encoded, fieldSize - xb.length + 1, xb.length);
		System.arraycopy(yb, 0, encoded, encoded.length - yb.length, yb.length);
		
		return encoded;
	}

}
