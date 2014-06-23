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

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.CertificateRequest.HashAlgorithm;
import org.eclipse.californium.scandium.dtls.CertificateRequest.SignatureAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography;
import org.eclipse.californium.scandium.util.DatagramReader;
import org.eclipse.californium.scandium.util.DatagramWriter;


/**
 * 
 * The server's Ephemeral ECDH with ECDSA signatures. See <a
 * href="http://tools.ietf.org/html/rfc4492">RFC 4492</a>, <a
 * href="http://tools.ietf.org/html/rfc4492#section-5.4">Section 5.4. Server Key
 * Exchange</a>, for details on the message format.
 */
public class ECDHServerKeyExchange extends ServerKeyExchange {

	// Logging ////////////////////////////////////////////////////////

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

	private int curveId;

	private byte[] signatureEncoded = null;

	/** The signature and hash algorithm which must be included into the digitally-signed struct. */
	private SignatureAndHashAlgorithm signatureAndHashAlgorithm;

	// TODO right now only named curve is supported
	private int curveType = NAMED_CURVE;

	// Constructors //////////////////////////////////////////////////

	/**
	 * Called by server, generates ephemeral keys and signature.
	 * 
	 * @param ecdhe
	 *            the ECDHE helper class.
	 * @param serverPrivateKey
	 *            the server's private key.
	 * @param clientRandom
	 *            the client's random (used for signature).
	 * @param serverRandom
	 *            the server's random (used for signature).
	 * @param namedCurveId
	 *            the named curve's id which will be used for the ECDH.
	 */
	public ECDHServerKeyExchange(SignatureAndHashAlgorithm signatureAndHashAlgorithm, ECDHECryptography ecdhe, PrivateKey serverPrivateKey, Random clientRandom, Random serverRandom, int namedCurveId) {

		this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;
		
		try {
			publicKey = ecdhe.getPublicKey();
			ECParameterSpec parameters = publicKey.getParams();

			curveId = namedCurveId;
			point = publicKey.getW();
			pointEncoded = ECDHECryptography.encodePoint(point, parameters.getCurve());

			// make signature
			// See http://tools.ietf.org/html/rfc4492#section-2.2
			// These parameters MUST be signed with ECDSA using the private key
			// corresponding to the public key in the server's Certificate.
			Signature signature = Signature.getInstance(this.signatureAndHashAlgorithm.toString());
			signature.initSign(serverPrivateKey);

			updateSignature(signature, clientRandom, serverRandom);

			signatureEncoded = signature.sign();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Called when reconstructing the byte array.
	 * 
	 * @param curveId
	 *            the named curve index
	 * @param pointEncoded
	 *            the point on the curve (encoded)
	 * @param signatureEncoded
	 *            the signature (encoded)
	 */
	public ECDHServerKeyExchange(SignatureAndHashAlgorithm signatureAndHashAlgorithm, int curveId, byte[] pointEncoded, byte[] signatureEncoded) {
		this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;
		this.curveId = curveId;
		this.pointEncoded = pointEncoded;
		this.signatureEncoded = signatureEncoded;
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
			break;

		default:
			LOGGER.severe("Unknown curve type: " + curveId);
			break;
		}

		return writer.toByteArray();
	}

	public static HandshakeMessage fromByteArray(byte[] byteArray) throws HandshakeException {
		DatagramReader reader = new DatagramReader(byteArray);
		int curveType = reader.read(CURVE_TYPE_BITS);
		switch (curveType) {
		// TODO right now only named curve supported
		case EXPLICIT_PRIME:
		case EXPLICIT_CHAR2:
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE);
			throw new HandshakeException("Not supported curve type in ServerKeyExchange message", alert);
			
		case NAMED_CURVE:
			int curveId = reader.read(NAMED_CURVE_BITS);
			int length = reader.read(PUBLIC_LENGTH_BITS);
			byte[] pointEncoded = reader.readBytes(length);

			byte[] bytesLeft = reader.readBytesLeft();
			
			// default is SHA256withECDSA
			SignatureAndHashAlgorithm signAndHash = new SignatureAndHashAlgorithm(HashAlgorithm.SHA256, SignatureAlgorithm.ECDSA);
			
			byte[] signatureEncoded = null;
			if (bytesLeft.length > 0) {
				reader = new DatagramReader(bytesLeft);
				int hashAlgorithm = reader.read(HASH_ALGORITHM_BITS);
				int signatureAlgorithm = reader.read(SIGNATURE_ALGORITHM_BITS);
				signAndHash = new SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm);
				length = reader.read(SIGNATURE_LENGTH_BITS);
				signatureEncoded = reader.readBytes(length);
			}

			return new ECDHServerKeyExchange(signAndHash, curveId, pointEncoded, signatureEncoded);

		default:
			LOGGER.severe("Unknown curve type: " + curveType);
			break;
		}

		return null;
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
			LOGGER.severe("Unknown curve type: " + curveType);
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
			Signature signature = Signature.getInstance(signatureAndHashAlgorithm.toString());
			signature.initVerify(serverPublicKey);

			updateSignature(signature, clientRandom, serverRandom);

			verified = signature.verify(signatureEncoded);

		} catch (Exception e) {
			LOGGER.log(Level.SEVERE,"Could not verify the server's signature.",e);
		}
		
		if (!verified) {
			String message = "The server's ECDHE key exchange message's signature could not be verified.";
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE);
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

			break;

		case EXPLICIT_CHAR2:

			break;

		case NAMED_CURVE:
			signature.update((byte) NAMED_CURVE);
			signature.update((byte) (curveId >> 8));
			signature.update((byte) curveId);
			signature.update((byte) pointEncoded.length);
			signature.update(pointEncoded);
			break;

		default:
			LOGGER.severe("Unknown curve type: " + curveId);
			break;
		}
	}

	/**
	 * Called by the client after receiving the {@link ServerKeyExchange}
	 * message and verification.
	 * 
	 * @return the server's ephemeral public key.
	 */
	public ECPublicKey getPublicKey(ECParameterSpec params) {
		if (publicKey == null) {
			
			try {
				point = ECDHECryptography.decodePoint(pointEncoded, params.getCurve());

				KeyFactory keyFactory = KeyFactory.getInstance(KEYPAIR_GENERATOR_INSTANCE);
				publicKey = (ECPublicKey) keyFactory.generatePublic(new ECPublicKeySpec(point, params));
			} catch (Exception e) {
				LOGGER.log(Level.SEVERE,"Could not reconstruct the server's ephemeral public key.",e);
			}

		}
		return publicKey;
	}
	
	private ECPublicKey getPublicKey() {
		return publicKey;
	}
	
	public int getCurveId() {
		return curveId;
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(super.toString());
		sb.append("\t\t" + getPublicKey().toString() + "\n");

		return sb.toString();
	}


	/**
	 * Maps the named curves names to its indices. This is done statically
	 * according to the named curve table.
	 */
	public final static Map<String, Integer> NAMED_CURVE_INDEX;

	static {
		NAMED_CURVE_INDEX = new HashMap<String, Integer>();
		for (int i = 1; i < ECDHECryptography.NAMED_CURVE_TABLE.length; i++) {
			NAMED_CURVE_INDEX.put(ECDHECryptography.NAMED_CURVE_TABLE[i], i);
		}
	}
	
	/**
	 * The parameter specifications for the different named curves.
	 */
	public final static Map<Integer, ECParameterSpec> NAMED_CURVE_PARAMETERS;
	
	private static void addParameterSpec(int namedCurveId, String p, String a, String b, String x, String y, String n, int h) {
		ECField field = new ECFieldFp(new BigInteger(p, 16));
		EllipticCurve curve = new EllipticCurve(field, new BigInteger(a, 16), new BigInteger(b, 16));
		ECPoint g = new ECPoint(new BigInteger(x, 16), new BigInteger(y, 16));
		ECParameterSpec params = new ECParameterSpec(curve, g, new BigInteger(n, 16), h);
		NAMED_CURVE_PARAMETERS.put(namedCurveId, params);
	}
	
	static {
		NAMED_CURVE_PARAMETERS = new HashMap<Integer, ECParameterSpec>();
		
		/*
		 * See http://www.secg.org/collateral/sec2_final.pdf for the parameters
		 */
		
		// TODO add more curves
		
		// secp224k1
		addParameterSpec(20,
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D",
				"00000000000000000000000000000000000000000000000000000000",
				"00000000000000000000000000000000000000000000000000000005",
				"A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C",
				"7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5",
				"010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7",
				1);
		
		// secp224r1 [NIST P-224]
		addParameterSpec(21,
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
				"B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
				"B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
				"BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
				1);
		
		// secp256k1
		addParameterSpec(22,
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
				"0000000000000000000000000000000000000000000000000000000000000000",
				"0000000000000000000000000000000000000000000000000000000000000007",
				"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
				"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
				1);
		
		// secp256r1 [NIST P-256, X9.62 prime256v1]
		addParameterSpec(23,
				"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
				"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
				"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
				"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
				"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
				"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
				1);
		
		// secp384r1 [NIST P-384]
		addParameterSpec(24,
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
				"B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
				"AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
				"3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
				1);
		
		// secp521r1 [NIST P-521]
		addParameterSpec(25,
				"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
				"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
				"0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
				"00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
				"011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
				"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
				1);
	}
	
}
