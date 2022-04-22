/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;

/**
 * ASN.1 DER decoder for SEQUENCEs and OIDs.
 */
public class Asn1DerDecoder {

	/**
	 * Key algorithm EC to be used by KeyFactory.
	 * 
	 * @deprecated use {@link JceNames#EC} instead
	 */
	@Deprecated
	public static final String EC = JceNames.EC;
	/**
	 * Key algorithm RSA to be used by KeyFactory.
	 * 
	 * @deprecated use {@link JceNames#RSA} instead
	 */
	@Deprecated
	public static final String RSA = JceNames.RSA;
	/**
	 * Key algorithm DSA to be used by KeyFactory.
	 * 
	 * @deprecated use {@link JceNames#DSA} instead
	 */
	@Deprecated
	public static final String DSA = "DSA";
	/**
	 * Key algorithm DH to be used by KeyFactory.
	 * 
	 * @deprecated use {@link JceNames#DH} instead
	 */
	@Deprecated
	public static final String DH = "DH";
	/**
	 * Key algorithm EC v2 (RFC 5958), not to be used by KeyFactory.
	 * 
	 * @see #readEcPrivateKeyV2(byte[])
	 * @deprecated use {@link JceNames#ECv2} instead
	 */
	@Deprecated
	public static final String ECv2 = JceNames.ECv2;
	/**
	 * Key algorithm ED25519 (RFC 8422).
	 * 
	 * @deprecated use {@link JceNames#ED25519} instead
	 * @since 2.4
	 */
	@Deprecated
	public static final String ED25519 = JceNames.ED25519;
	/**
	 * Key algorithm Ed25519 v2 (RFC 8410), not to be used by KeyFactory.
	 * 
	 * @see #readEdDsaPrivateKeyV2(byte[])
	 * 
	 * @deprecated use {@link JceNames#ED25519v2} instead
	 * @since 3.0
	 */
	@Deprecated
	public static final String ED25519v2 = JceNames.ED25519v2;
	/**
	 * Key algorithm ED448 (RFC 8422).
	 * 
	 * @deprecated use {@link JceNames#ED448} instead
	 * @since 2.4
	 */
	@Deprecated
	public static final String ED448 = JceNames.ED448;
	/**
	 * Key algorithm Ed448 v2 (RFC 8410), not to be used by KeyFactory.
	 * 
	 * @see #readEdDsaPrivateKeyV2(byte[])
	 * 
	 * @deprecated use {@link JceNames#ED448v2} instead
	 * @since 3.0
	 */
	@Deprecated
	public static final String ED448v2 = JceNames.ED448v2;
	/**
	 * Key algorithm X25519 (RFC 8422).
	 * 
	 * @deprecated use {@link JceNames#X25519} instead
	 * @since 3.0
	 */
	@Deprecated
	public static final String X25519 = JceNames.X25519;
	/**
	 * Key algorithm X25519 v2 (RFC 8410), not to be used by KeyFactory.
	 * 
	 * @deprecated use {@link JceNames#X25519v2} instead
	 * @since 3.0
	 */
	@Deprecated
	public static final String X25519v2 = JceNames.X25519v2;
	/**
	 * Key algorithm X448 (RFC 8422).
	 * 
	 * @deprecated use {@link JceNames#X448} instead
	 * @since 3.0
	 */
	@Deprecated
	public static final String X448 = JceNames.X448;
	/**
	 * Key algorithm X448 v2 (RFC 8410), not to be used by KeyFactory.
	 * 
	 * @deprecated use {@link JceNames#X448v2} instead
	 * @since 3.0
	 */
	@Deprecated
	public static final String X448v2 = JceNames.X448v2;
	/**
	 * OID key algorithm X25519
	 * (<a href="https://datatracker.ietf.org/doc/html/rfc8410#section-3" target
	 * ="_blank"> RFC 8410, 3. Curve25519 and Curve448 Algorithm
	 * Identifiers</a>).
	 * 
	 * @deprecated use {@link JceNames#OID_X25519} instead
	 * @since 3.0
	 */
	@Deprecated
	public static final String OID_X25519 = JceNames.OID_X25519;
	/**
	 * OID key algorithm X448
	 * (<a href="https://datatracker.ietf.org/doc/html/rfc8410#section-3" target
	 * ="_blank"> RFC 8410, 3. Curve25519 and Curve448 Algorithm
	 * Identifiers</a>).
	 * 
	 * @deprecated use {@link JceNames#OID_X448} instead
	 * @since 3.0
	 */
	@Deprecated
	public static final String OID_XD448 = JceNames.OID_X448;
	/**
	 * OID key algorithm ED25519
	 * (<a href="https://datatracker.ietf.org/doc/html/rfc8410#section-3" target
	 * ="_blank"> RFC 8410, 3. Curve25519 and Curve448 Algorithm
	 * Identifiers</a>).
	 * 
	 * @deprecated use {@link JceNames#OID_ED25519} instead
	 * @since 2.4
	 */
	@Deprecated
	public static final String OID_ED25519 = JceNames.OID_ED25519;
	/**
	 * OID key algorithm ED448
	 * (<a href="https://datatracker.ietf.org/doc/html/rfc8410#section-3" target
	 * ="_blank"> RFC 8410, 3. Curve25519 and Curve448 Algorithm
	 * Identifiers</a>).
	 * 
	 * @deprecated use {@link JceNames#OID_ED448} instead
	 * @since 2.4
	 */
	@Deprecated
	public static final String OID_ED448 = JceNames.OID_ED448;
	/**
	 * Key algorithm EdDSA (RFC 8422).
	 * 
	 * @deprecated use {@link JceNames#EDDSA} instead
	 * @since 2.4
	 */
	@Deprecated
	public static final String EDDSA = JceNames.EDDSA;
	/**
	 * ECPoint uncompressed.
	 * <a href="https://tools.ietf.org/html/rfc5480#section-2.2" target=
	 * "_blank">RFC 5480, Section 2.2</a>
	 * 
	 * @since 2.3
	 */
	public static final int EC_PUBLIC_KEY_UNCOMPRESSED = 4;
	/**
	 * Maximum supported default length for ASN.1.
	 */
	private static final int MAX_DEFAULT_LENGTH = 0x10000;
	/**
	 * Tag for ASN.1 SEQUENCE.
	 */
	private static final int TAG_SEQUENCE = 0x30;
	/**
	 * Tag for ASN.1 SET.
	 * 
	 * @since 3.0
	 */
	private static final int TAG_SET = 0x31;
	/**
	 * Maximum supported length for ASN.1 OID.
	 */
	private static final int MAX_OID_LENGTH = 0x20;
	/**
	 * Tag for ASN.1 OIDE.
	 */
	private static final int TAG_OID = 0x06;
	/**
	 * Tag for ASN.1 INTEGER.
	 */
	private static final int TAG_INTEGER = 0x02;
	/**
	 * Tag for ASN.1 OCTET STRING.
	 */
	private static final int TAG_OCTET_STRING = 0x04;
	/**
	 * Tag for ASN.1 OCTET STRING.
	 */
	private static final int TAG_BIT_STRING = 0x03;
	/**
	 * Tag for ASN.1 UTF-8 STRING.
	 * 
	 * @since 3.0
	 */
	private static final int TAG_UTF8_STRING = 0x0C;
	/**
	 * Tag for ASN.1 PRINTABLE STRING.
	 * 
	 * @since 3.0
	 */
	private static final int TAG_PRINTABLE_STRING = 0x13;
	/**
	 * Tag for ASN.1 TELETEX STRING.
	 * 
	 * Support for deprecated CAs.
	 * 
	 * @since 3.0
	 */
	private static final int TAG_TELETEX_STRING = 0x14;
	/**
	 * Tag for ASN.1 UNIVERSAL STRING.
	 * 
	 * Support for deprecated CAs.
	 * 
	 * @since 3.0
	 */
	private static final int TAG_UNIVERSAL_STRING = 0x1C;
	/**
	 * Tag for ASN.1 BMP STRING.
	 * 
	 * Support for deprecated CAs.
	 * 
	 * @since 3.0
	 */
	private static final int TAG_BMP_STRING = 0x1E;
	/**
	 * List of supported Tag for ASN.1 STRING.
	 * 
	 * @since 3.0
	 */
	private static final int[] TAGS_STRING = { TAG_UTF8_STRING, TAG_PRINTABLE_STRING, TAG_BMP_STRING,
			TAG_UNIVERSAL_STRING, TAG_TELETEX_STRING };
	/**
	 * Tag for ASN.1 CONTEXT SPECIFIC 0.
	 */
	private static final int TAG_CONTEXT_0_SPECIFIC = 0xA0;
	/**
	 * Tag for ASN.1 CONTEXT SPECIFIC 1.
	 */
	private static final int TAG_CONTEXT_1_SPECIFIC = 0xA1;
	/**
	 * Tag for ASN.1 CONTEXT SPECIFIC PRIMITIVE 1.
	 * 
	 * @since 3.0
	 */
	private static final int TAG_CONTEXT_1_SPECIFIC_PRIMITIVE = 0x81;
	/**
	 * ASN.1 OID for RSA public key.
	 */
	private static final byte[] OID_RSA_PUBLIC_KEY = { 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01,
			0x01, 0x01 };
	/**
	 * ASN.1 OID for DH key agreement.
	 * 
	 * @since 3.0 (renamed, was OID_DH_PUBLIC_KEY)
	 */
	private static final byte[] OID_DH_KEY_AGREEMENT = { 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01,
			0x03, 0x01 };
	/**
	 * ASN.1 OID for DH public key.
	 * 
	 * @since 3.0
	 */
	private static final byte[] OID_DH_PUBLIC_KEY = { 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, (byte) 0x3E, 0x02, 0x01 };
	/**
	 * ASN.1 OID for DSA public key.
	 */
	private static final byte[] OID_DSA_PUBLIC_KEY = { 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x38, 0x04, 0x01 };
	/**
	 * ASN.1 OID for EC public key.
	 */
	private static final byte[] OID_EC_PUBLIC_KEY = { 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x02, 0x01 };
	/**
	 * ASN.1 OID for X25519 public key.
	 * 
	 * @since 3.0
	 */
	private static final byte[] OID_X25519_PUBLIC_KEY = { 0x2b, 0x65, 0x6e };
	/**
	 * ASN.1 OID for X448 public key.
	 * 
	 * @since 3.0
	 */
	private static final byte[] OID_X448_PUBLIC_KEY = { 0x2b, 0x65, 0x6f };
	/**
	 * ASN.1 OID for ED25519 public key.
	 * 
	 * @since 2.4
	 */
	private static final byte[] OID_ED25519_PUBLIC_KEY = { 0x2b, 0x65, 0x70 };
	/**
	 * ASN.1 OID for ED448 public key.
	 * 
	 * @since 2.4
	 */
	private static final byte[] OID_ED448_PUBLIC_KEY = { 0x2b, 0x65, 0x71 };
	/**
	 * ASN.1 OID for CN.
	 * 
	 * @since 3.0
	 */
	private static final byte[] OID_CN = { 0x55, 4, 3 };
	/**
	 * ASN.1 entity definition for SEQUENCE.
	 */
	private static final EntityDefinition SEQUENCE = new EntityDefinition(TAG_SEQUENCE, MAX_DEFAULT_LENGTH, "SEQUENCE");
	/**
	 * ASN.1 entity definition for SET.
	 */
	private static final EntityDefinition SET = new EntityDefinition(TAG_SET, MAX_DEFAULT_LENGTH, "SET");
	/**
	 * ASN.1 entity definition for OID.
	 */
	private static final OidEntityDefinition OID = new OidEntityDefinition();
	/**
	 * ASN.1 entity definition for INTEGER.
	 * 
	 * Converts values up to 4 bytes into {@code int}.
	 */
	private static final IntegerEntityDefinition INTEGER = new IntegerEntityDefinition();
	/**
	 * ASN.1 entity definition for OCTET_STRING.
	 */
	private static final EntityDefinition BIT_STRING = new EntityDefinition(TAG_BIT_STRING, MAX_DEFAULT_LENGTH,
			"BIT STRING");
	/**
	 * ASN.1 entity definition for OCTET_STRING.
	 */
	private static final EntityDefinition OCTET_STRING = new EntityDefinition(TAG_OCTET_STRING, MAX_DEFAULT_LENGTH,
			"OCTET STRING");
	/**
	 * ASN.1 entity definition for CONTEXT_SPECIFIC_0.
	 */
	private static final EntityDefinition CONTEXT_SPECIFIC_0 = new EntityDefinition(TAG_CONTEXT_0_SPECIFIC,
			MAX_DEFAULT_LENGTH, "CONTEXT SPECIFIC 0");
	/**
	 * ASN.1 entity definition for CONTEXT_SPECIFIC_1.
	 */
	private static final EntityDefinition CONTEXT_SPECIFIC_1 = new EntityDefinition(TAG_CONTEXT_1_SPECIFIC,
			MAX_DEFAULT_LENGTH, "CONTEXT SPECIFIC 1");
	/**
	 * ASN.1 entity definition for CONTEXT_SPECIFIC_PRIMITIVE_1.
	 * 
	 * @since 3.0
	 */
	private static final EntityDefinition CONTEXT_SPECIFIC_PRIMITIVE_1 = new EntityDefinition(
			TAG_CONTEXT_1_SPECIFIC_PRIMITIVE, MAX_DEFAULT_LENGTH, "CONTEXT SPECIFIC PRIMITIVE 1");

	/**
	 * ISO-10646-UCS-2 charset, if supported.
	 * 
	 * @since 3.0
	 */
	private static final Charset UCS_2;
	/**
	 * ISO-10646-UCS-4 charset, if supported.
	 * 
	 * @since 3.0
	 */
	private static final Charset UCS_4;

	static {
		Charset charset = null;
		try {
			charset = Charset.forName("ISO-10646-UCS-2");
		} catch (Throwable t) {
		}
		UCS_2 = charset;
		charset = null;
		try {
			charset = Charset.forName("ISO-10646-UCS-4");
		} catch (Throwable t) {
		}
		UCS_4 = charset;
		JceProviderUtil.init();
	}

	/**
	 * Gets the algorithm of the public key.
	 * 
	 * The v2 variants are not supported by the java 7 KeyFactory.
	 * 
	 * @param oid OID of public key.
	 * @param version version of format. {@code 0}, for v1, {@code 2} for v2.
	 * @return {@link JceNames#EC}, {@link JceNames#RSA}, {@link JceNames#DSA},
	 *         {@link JceNames#DH}, {@link JceNames#ED25519},
	 *         {@link JceNames#ED448}, {@link JceNames#X25519}, and
	 *         {@link JceNames#X448} for v1, {@link JceNames#ECv2},
	 *         {@link JceNames#ED25519v2}, and {@link JceNames#ED448v2},
	 *         {@link JceNames#X25519v2}, and {@link JceNames#X448v2} for v2,
	 *         {@code null}, if unknown.
	 * @since 3.0
	 */
	private static String getPublicKeyAlgorithm(final byte[] oid, int version) {
		String algorithm = null;
		if (Arrays.equals(oid, OID_EC_PUBLIC_KEY)) {
			algorithm = version == 0 ? JceNames.EC : JceNames.ECv2;
		} else if (Arrays.equals(oid, OID_RSA_PUBLIC_KEY)) {
			algorithm = version == 0 ? JceNames.RSA : null;
		} else if (Arrays.equals(oid, OID_DSA_PUBLIC_KEY)) {
			algorithm = version == 0 ? JceNames.DSA : null;
		} else if (Arrays.equals(oid, OID_DH_PUBLIC_KEY)) {
			algorithm = version == 0 ? JceNames.DH : null;
		} else if (Arrays.equals(oid, OID_DH_KEY_AGREEMENT)) {
			algorithm = version == 0 ? JceNames.DH : null;
		} else if (Arrays.equals(oid, OID_ED25519_PUBLIC_KEY)) {
			algorithm = version == 0 ? JceNames.ED25519 : JceNames.ED25519v2;
		} else if (Arrays.equals(oid, OID_ED448_PUBLIC_KEY)) {
			algorithm = version == 0 ? JceNames.ED448 : JceNames.ED448v2;
		} else if (Arrays.equals(oid, OID_X25519_PUBLIC_KEY)) {
			algorithm = version == 0 ? JceNames.X25519 : JceNames.X25519v2;
		} else if (Arrays.equals(oid, OID_X448_PUBLIC_KEY)) {
			algorithm = version == 0 ? JceNames.X448 : JceNames.X448v2;
		}
		return algorithm;
	}

	/**
	 * Check, if key algorithm is EC based.
	 * 
	 * @param algorithm key algorithm
	 * @return {@code true}, if EC based, {@code false}, otherwise.
	 * @since 3.0
	 */
	public static boolean isEcBased(String algorithm) {
		if (JceNames.EC.equalsIgnoreCase(algorithm)) {
			return true;
		} else {
			return getEdDsaStandardAlgorithmName(algorithm, null) != null;
		}
	}

	/**
	 * Read entity of ASN.1 SEQUENCE into byte array.
	 * 
	 * Returns entity, including tag and length. Intended to be passed to other
	 * security readers as KeyFacotry or X509CertPath.
	 * 
	 * @param reader reader containing the bytes to read.
	 * @return byte array containing the SEQUENCE entity.
	 * @throws IllegalArgumentException if provided bytes doesn't contain a
	 *             SEQUENCE.
	 */
	public static byte[] readSequenceEntity(final DatagramReader reader) {
		return SEQUENCE.readEntity(reader);
	}

	/**
	 * Read value of ASN.1 SEQUENCE into byte array.
	 * 
	 * Returns only the value, excluding tag and length.
	 * 
	 * @param reader reader containing the bytes to read.
	 * @return byte array containing the SEQUENCE value.
	 * @throws IllegalArgumentException if provided bytes doesn't contain a
	 *             SEQUENCE.
	 */
	public static byte[] readSequenceValue(final DatagramReader reader) {
		return SEQUENCE.readValue(reader);
	}

	/**
	 * Read value of ASN.1 OID into byte array.
	 * 
	 * Read only value, excluding tag and length.
	 * 
	 * @param reader reader containing the bytes to read.
	 * @return byte array containing the OID value.
	 * @throws IllegalArgumentException if provided bytes doesn't contain a OID.
	 */
	public static byte[] readOidValue(final DatagramReader reader) {
		return OID.readValue(reader);
	}

	/**
	 * Read value of ASN.1 OID into string.
	 * 
	 * @param reader reader containing the bytes to read.
	 * @return oid as string
	 * @throws IllegalArgumentException if oid is invalid.
	 */
	public static String readOidString(final DatagramReader reader) {
		byte[] oid = OID.readValue(reader);
		return OID.toString(oid);
	}

	/**
	 * Read key algorithm from subjects public key.
	 * 
	 * Read key algorithm from subjects public key encoded in ASN.1 DER.
	 * 
	 * <pre>
	 * <a href="https://tools.ietf.org/html/rfc5480" target=
	"_blank">RFC 5480</a>
	 * SubjectPublicKeyInfo ::= SEQUENCE { 
	 *    algorithm AlgorithmIdentifier,
	 *    subjectPublicKey BIT STRING 
	 * } 
	 * 
	 * AlgorithmIdentifier ::= SEQUENCE {
	 *    algorithm OBJECT IDENTIFIER, 
	 *    parameters ANY DEFINED BY algorithm OPTIONAL
	 * }
	 * </pre>
	 * 
	 * Figure 2: SubjectPublicKeyInfo ASN.1 Structure
	 * 
	 * @param data byte array containing the subject public key.
	 * @return key algorithm name to be used by KeyFactory. Or {@code null}, if
	 *         the OID of the subject public key is unknown.
	 * @throws IllegalArgumentException if provided bytes doesn't contain a
	 *             subject public key.
	 */
	public static String readSubjectPublicKeyAlgorithm(final byte[] data) {
		// outer sequence, SubjectPublicKeyInfo
		DatagramReader reader = new DatagramReader(data, false);
		reader = SEQUENCE.createRangeReader(reader, false);
		// inner sequence, AlgorithmIdentifier
		reader = SEQUENCE.createRangeReader(reader, false);
		// oid, algorithm
		byte[] value = readOidValue(reader);

		return getPublicKeyAlgorithm(value, 0);
	}

	/**
	 * Read public key from subjects public key.
	 * 
	 * Read public key from subjects public key encoded in ASN.1 DER.
	 * 
	 * <pre>
	 * <a href="https://tools.ietf.org/html/rfc5480" target=
	"_blank">RFC 5480</a>
	 * SubjectPublicKeyInfo ::= SEQUENCE { 
	 *    algorithm AlgorithmIdentifier,
	 *    subjectPublicKey BIT STRING 
	 * } 
	 * 
	 * AlgorithmIdentifier ::= SEQUENCE {
	 *    algorithm OBJECT IDENTIFIER, 
	 *    parameters ANY DEFINED BY algorithm OPTIONAL
	 * }
	 * </pre>
	 * 
	 * Figure 2: SubjectPublicKeyInfo ASN.1 Structure
	 * 
	 * @param data byte array containing the subject public key.
	 * @return public key, or {@code null}, if the OID of the subject public key
	 *         is unknown.
	 * @throws IllegalArgumentException if provided bytes doesn't contain a
	 *             subject public key.
	 * @throws GeneralSecurityException public key could not be read
	 */
	public static PublicKey readSubjectPublicKey(final byte[] data) throws GeneralSecurityException {
		PublicKey publicKey = null;
		String algorithm = readSubjectPublicKeyAlgorithm(data);
		if (algorithm != null) {
			KeyFactory factory = getKeyFactory(algorithm);
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(data);
			publicKey = factory.generatePublic(publicKeySpec);
		}
		return publicKey;
	}

	/**
	 * Read key algorithm from private key.
	 * 
	 * Read key algorithm from private key encoded in ASN.1 DER according
	 * 
	 * Supports:
	 * 
	 * <pre>
	 * v1 (PKCS8), <a href="https://tools.ietf.org/html/rfc5208" target=
	"_blank">RFC 5208</a>
	 * PrivateKeyInfo ::= SEQUENCE {
	 *  version                   Version,
	 *  privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
	 *  privateKey                PrivateKey,
	 *  attributes           [0]  IMPLICIT Attributes OPTIONAL }
	 * 
	 * v2 (PKCS12), 
	 * <a href="https://tools.ietf.org/html/rfc5958" target=
	"_blank">RFC 5958 - (EC only!)</a>,
	 * <a href="https://tools.ietf.org/html/rfc8410" target=
	"_blank">RFC 8410 - EdDSA</a>
	 * OneAsymmetricKey ::= SEQUENCE {
	 *  version                   Version,
	 *  privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
	 *  privateKey                PrivateKey,
	 *  attributes            [0] Attributes OPTIONAL,
	 *  ...,
	 *  [[2: publicKey        [1] PublicKey OPTIONAL ]],
	 *  ...
	 * }
	 * </pre>
	 * 
	 * @param data private key encoded in ASN.1 DER
	 * @return key algorithm name to be used by KeyFactory, or
	 *         {@link JceNames#ECv2}, {@link JceNames#ED25519v2}, and
	 *         {@link JceNames#ED448v2} for v2, which are not supported by the
	 *         java 7 KeyFactory, or {@code null}, if unknown.
	 * @throws IllegalArgumentException if the private key algorithm could not
	 *             be read
	 * @see #readEcPrivateKeyV2(byte[])
	 * @see #readEdDsaPrivateKeyV2(byte[])
	 * @see #readPrivateKey(byte[])
	 */
	public static String readPrivateKeyAlgorithm(final byte[] data) {
		String algorithm = null;
		// outer sequence, PrivateKeyInfo
		DatagramReader reader = new DatagramReader(data, false);
		reader = SEQUENCE.createRangeReader(reader, false);
		// INTEGER version
		byte[] readValue = INTEGER.readValue(reader);
		int version = INTEGER.toInteger(readValue);
		if (version < 0 || version > 1) {
			throw new IllegalArgumentException("Version 0x" + Integer.toHexString(version) + " not supported!");
		}
		try {
			// inner sequence, AlgorithmIdentifier
			DatagramReader sequenceReader = SEQUENCE.createRangeReader(reader, false);
			// oid, algorithm
			byte[] value = readOidValue(sequenceReader);
			algorithm = getPublicKeyAlgorithm(value, version);
		} catch (IllegalArgumentException ex) {
			if (version == 1) {
				// RFC 5958

				// OCTET_STRING, skip private key
				OCTET_STRING.createRangeReader(reader, false);
				// oid, algorithm
				byte[] oid = readOidValue(CONTEXT_SPECIFIC_0.createRangeReader(reader, false));
				String oidAsString = "0x" + StringUtil.byteArray2Hex(oid);
				try {
					oidAsString = OID.toString(oid);
					try {
						ECParameterSpec ecParameterSpec = getECParameterSpec(oidAsString);
						if (ecParameterSpec != null) {
							algorithm = JceNames.ECv2;
						}
					} catch (GeneralSecurityException e) {
					}
				} catch (IllegalArgumentException e) {
					// if oid byte array is invalid
				}
				if (algorithm == null) {
					throw new IllegalArgumentException("OID " + oidAsString + " not supported!");
				}
			} else {
				throw ex;
			}
		}
		return algorithm;
	}

	/**
	 * Read private key.
	 * 
	 * Read private key encoded in ASN.1 DER according
	 * 
	 * Supports:
	 * 
	 * <pre>
	 * v1 (PKCS8), <a href="https://tools.ietf.org/html/rfc5208" target=
	"_blank">RFC 5208</a>
	 * PrivateKeyInfo ::= SEQUENCE {
	 *  version                   Version,
	 *  privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
	 *  privateKey                PrivateKey,
	 *  attributes           [0]  IMPLICIT Attributes OPTIONAL }
	 * 
	 * v2 (PKCS12), 
	 * <a href="https://tools.ietf.org/html/rfc5958" target=
	"_blank">RFC 5958 - (EC only!)</a>,
	 * <a href="https://tools.ietf.org/html/rfc8410" target=
	"_blank">RFC 8410 - EdDSA</a>
	 * OneAsymmetricKey ::= SEQUENCE {
	 *  version                   Version,
	 *  privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
	 *  privateKey                PrivateKey,
	 *  attributes            [0] Attributes OPTIONAL,
	 *  ...,
	 *  [[2: publicKey        [1] PublicKey OPTIONAL ]],
	 *  ...
	 * }
	 * </pre>
	 * 
	 * @param data private key encoded in ASN.1 DER
	 * @return keys with private key for RFC 5208 encoding and optional public
	 *         key for RFC 5958 or RFC8410 encoding. Or {@code null}, if the OID
	 *         of the private key is unknown.
	 * @throws GeneralSecurityException if private key could not be read
	 */
	public static Keys readPrivateKey(final byte[] data) throws GeneralSecurityException {
		Keys keys = null;
		String algorithm = readPrivateKeyAlgorithm(data);
		if (algorithm != null) {
			if (algorithm == JceNames.ED25519v2 || algorithm == ED448v2) {
				keys = readEdDsaPrivateKeyV2(data);
			} else if (algorithm == JceNames.ECv2) {
				keys = readEcPrivateKeyV2(data);
			} else {
				KeyFactory factory = getKeyFactory(algorithm);
				EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(data);
				keys = new Keys();
				keys.privateKey = factory.generatePrivate(privateKeySpec);
			}
		}
		return keys;
	}

	/**
	 * Read EC private key (and public key) from PKCS12 / RFC 5958 v2 format.
	 * 
	 * @param data ec private key encoded according RFC 5958 v2
	 * @return keys with private and public key. {@code null}, if keys could not
	 *         be read.
	 * @throws GeneralSecurityException if decoding fails.
	 */
	public static Keys readEcPrivateKeyV2(final byte[] data) throws GeneralSecurityException {
		Keys keys = null;
		// outer sequence, PrivateKeyInfo
		DatagramReader reader = new DatagramReader(data, false);
		reader = SEQUENCE.createRangeReader(reader, false);
		// INTEGER version
		byte[] readValue = INTEGER.readValue(reader);
		if (readValue.length == 1 && readValue[0] == 1) {
			try {
				SEQUENCE.createRangeReader(reader, false);
			} catch (IllegalArgumentException ex) {
				// ignore, optional
			}
			// RFC 5958
			// OCTET_STRING
			byte[] privateKeyValue = OCTET_STRING.readValue(reader);
			// oid, algorithm
			byte[] oid = readOidValue(CONTEXT_SPECIFIC_0.createRangeReader(reader, false));
			try {
				ECParameterSpec ecParameterSpec = getECParameterSpec(OID.toString(oid));
				int keySize = (ecParameterSpec.getCurve().getField().getFieldSize() + Byte.SIZE - 1) / Byte.SIZE;
				if (privateKeyValue.length != keySize) {
					throw new GeneralSecurityException(
							"private key size " + privateKeyValue.length + " doesn't match " + keySize);
				}
				KeySpec privateKeySpec = new ECPrivateKeySpec(new BigInteger(1, privateKeyValue), ecParameterSpec);
				keys = new Keys();
				keys.privateKey = KeyFactory.getInstance(JceNames.EC).generatePrivate(privateKeySpec);
				// BIT_STRING
				DatagramReader value = CONTEXT_SPECIFIC_1.createRangeReader(reader, false);
				value = BIT_STRING.createRangeReader(value, false);
				// BIT_STRING, unused bits in last byte
				int unusedBits = value.read(Byte.SIZE);
				if (unusedBits == 0) {
					keys.publicKey = readEcPublicKey(value, ecParameterSpec);
				}
			} catch (IllegalArgumentException e) {
				throw new GeneralSecurityException(e.getMessage(), e);
			} catch (GeneralSecurityException e) {
				// currently only EC is supported for RFC 5958 v2
				throw e;
			}
		}
		return keys;
	}

	/**
	 * Read EC public key from encoded ec public key.
	 * 
	 * <pre>
	 * <a href="https://tools.ietf.org/html/rfc5480#section-2.2" target=
	"_blank">RFC 5480, Section 2.2</a>
	 *  byte[0]        : compression := 4 (not compressed)
	 *  byte[1..n]     : x
	 *  byte[n+1..n+n] : y
	 * </pre>
	 * 
	 * @param reader reader with encoded ec public key
	 * @param ecParameterSpec parameter specification for public key
	 * @return ec public key
	 * @throws GeneralSecurityException if public key could not be read
	 */
	public static ECPublicKey readEcPublicKey(DatagramReader reader, ECParameterSpec ecParameterSpec)
			throws GeneralSecurityException {
		// outer sequence, PrivateKeyInfo
		int keySize = (ecParameterSpec.getCurve().getField().getFieldSize() + Byte.SIZE - 1) / Byte.SIZE;
		// PUBLIC KEY, compression, 4 := uncompressed
		int compress = reader.read(Byte.SIZE);
		int left = reader.bitsLeft() / Byte.SIZE;
		if (compress == EC_PUBLIC_KEY_UNCOMPRESSED && left % 2 == 0) {
			left /= 2;
			if (left == keySize) {
				BigInteger x = new BigInteger(1, reader.readBytes(left));
				BigInteger y = new BigInteger(1, reader.readBytes(left));
				KeySpec publicKeySpec = new ECPublicKeySpec(new ECPoint(x, y), ecParameterSpec);
				return (ECPublicKey) KeyFactory.getInstance(JceNames.EC).generatePublic(publicKeySpec);
			}
		}
		return null;
	}

	/**
	 * Read EdDSA private key (and public key) from PKCS12 / RFC 8410 v2 format.
	 * 
	 * See <a href="https://tools.ietf.org/html/rfc8410" target="_blank">RFC
	 * 8410 - EdDSA</a>.
	 * 
	 * @param data eddsa private key encoded according RFC 8410 v2
	 * @return keys with private and public key. {@code null}, if keys could not
	 *         be read.
	 * @throws GeneralSecurityException if decoding fails.
	 * @since 3.0
	 */
	public static Keys readEdDsaPrivateKeyV2(final byte[] data) throws GeneralSecurityException {
		Keys keys = null;
		// outer sequence, PrivateKeyInfo
		DatagramReader reader = new DatagramReader(data, false);
		reader = SEQUENCE.createRangeReader(reader, false);
		// INTEGER version
		byte[] readValue = INTEGER.readValue(reader);
		if (readValue.length == 1 && readValue[0] == 1) {
			// inner sequence, AlgorithmIdentifier
			byte[] keyAlgorithm = SEQUENCE.readEntity(reader);

			// read algorithm identifier from inner sequence
			DatagramReader oidReader = new DatagramReader(keyAlgorithm, false);
			oidReader = SEQUENCE.createRangeReader(oidReader, false);
			// oid, algorithm
			byte[] oidValue = readOidValue(oidReader);
			String algorithm = OID.toString(oidValue);

			// RFC 8410
			// OCTET_STRING
			byte[] privateKeyValue = OCTET_STRING.readEntity(reader);
			// context 0, skip
			CONTEXT_SPECIFIC_0.createRangeReader(reader, false);
			KeyFactory factory = getKeyFactory(algorithm);
			keys = new Keys();
			{
				// convert to EdDSA v1 - PKCS8
				DatagramWriter privateKey = new DatagramWriter(48);
				privateKey.writeByte((byte) TAG_SEQUENCE);
				int positionLen = privateKey.space(Byte.SIZE);
				privateKey.writeByte((byte) TAG_INTEGER);
				privateKey.writeByte((byte) 1); // version length
				privateKey.writeByte((byte) 0); // version 0
				privateKey.writeBytes(keyAlgorithm);
				privateKey.writeBytes(privateKeyValue);
				privateKey.writeSize(positionLen, Byte.SIZE);

				EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKey.toByteArray());
				keys.privateKey = factory.generatePrivate(privateKeySpec);
			}
			{
				// convert to X509
				DatagramWriter publicKey = new DatagramWriter(44);
				publicKey.writeByte((byte) TAG_SEQUENCE);
				int positionLen = publicKey.space(Byte.SIZE);
				publicKey.writeBytes(keyAlgorithm);
				publicKey.writeByte((byte) TAG_BIT_STRING);
				int positionBits = publicKey.space(Byte.SIZE);
				publicKey.writeBytes(CONTEXT_SPECIFIC_PRIMITIVE_1.readValue(reader));
				publicKey.writeSize(positionBits, Byte.SIZE);
				publicKey.writeSize(positionLen, Byte.SIZE);
				X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKey.toByteArray());
				keys.publicKey = factory.generatePublic(publicKeySpec);
			}
		}
		return keys;
	}

	/**
	 * Checks, if chain contains a vulnerable ECDSA signature.
	 * 
	 * @param chain certificate chain to check.
	 * @param trust trusted certificate
	 * @param last number of certificates to check in chain.
	 * @throws CertPathValidatorException if signature contains INTEGER values
	 *             not in range {@code [1, N-1]}.
	 * @see #checkEcDsaSignature(byte[], PublicKey)
	 * @since 3.5
	 */
	public static void checkCertificateChain(List<X509Certificate> chain, X509Certificate trust, int last)
			throws CertPathValidatorException {
		try {
			for (int index = 0; index < last; ++index) {
				X509Certificate certificate = chain.get(index);
				String signatureAlgorithm = certificate.getSigAlgName();
				if (signatureAlgorithm.endsWith("withECDSA") || signatureAlgorithm.endsWith("WITHECDSA")) {
					X509Certificate issuerCertificate;
					if (index + 1 < chain.size()) {
						issuerCertificate = chain.get(index + 1);
					} else {
						issuerCertificate = trust;
					}
					Asn1DerDecoder.checkEcDsaSignature(certificate.getSignature(), issuerCertificate.getPublicKey());
				}
			}
		} catch (GeneralSecurityException ex) {
			throw new CertPathValidatorException(ex.getMessage());
		}
	}

	/**
	 * Check, if provided ECDSA signature is vulnerable.
	 * 
	 * Some java JCE versions 15 to 18 fail to check the signature for 0 and n.
	 * This method adds that check.
	 * 
	 * @param signature received signature.
	 * @param publicKey public key to read the order (N)
	 * @throws GeneralSecurityException if signature contains INTEGER values not
	 *             in range {@code [1, N-1]}.
	 * @see JceProviderUtil#isEcdsaVulnerable()
	 * @see <a href=
	 *      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21449"
	 *      target="_blank">CVE-2022-21449</a>
	 * @since 3.5
	 */
	public static void checkEcDsaSignature(byte[] signature, PublicKey publicKey) throws GeneralSecurityException {
		DatagramReader reader = new DatagramReader(signature, false);
		reader = SEQUENCE.createRangeReader(reader, false);
		byte[] valueR = INTEGER.read(reader, false);
		byte[] valueS = INTEGER.read(reader, false);
		BigInteger order = ((ECPublicKey) publicKey).getParams().getOrder();
		checkSignatureInteger("R", valueR, order);
		checkSignatureInteger("S", valueS, order);
	}

	/**
	 * Checks, if the provided ASN.1 INTEGER is valid for a signature.
	 * 
	 * @param name name of signature parameter
	 * @param value byte value of signature parameter
	 * @param order order of the public key (N)
	 * @throws GeneralSecurityException if the signature parameter is not in
	 *             range {@code [1, N-1]}.
	 * @since 3.5
	 */
	private static void checkSignatureInteger(String name, byte[] value, BigInteger order)
			throws GeneralSecurityException {
		if (value.length == 0) {
			throw new GeneralSecurityException("ECDSA signature " + name + " is 0!");
		}
		BigInteger big = new BigInteger(value);
		if (big.compareTo(BigInteger.ONE) < 0) {
			throw new GeneralSecurityException("ECDSA signature " + name + " is less than 1!");
		}
		if (big.compareTo(order) >= 0) {
			throw new GeneralSecurityException("ECDSA signature " + name + " is not less than N!");
		}
	}

	/**
	 * Check for equal key algorithm synonyms.
	 * 
	 * @param keyAlgorithm1 key algorithm 1
	 * @param keyAlgorithm2 key algorithm 2
	 * @return {@code true}, if the key algorithms are equal or synonyms,
	 *         {@code false}, otherwise.
	 * @deprecated use
	 *             {@link JceProviderUtil#equalKeyAlgorithmSynonyms(String, String)}
	 *             instead
	 */
	@Deprecated
	public static boolean equalKeyAlgorithmSynonyms(String keyAlgorithm1, String keyAlgorithm2) {
		return JceProviderUtil.equalKeyAlgorithmSynonyms(keyAlgorithm1, keyAlgorithm2);
	}

	/**
	 * Get EC parameter spec for named curve.
	 * 
	 * Creates key pair to access the resulting EC parameter spec.
	 * 
	 * @param oid oid name of curve
	 * @return EC parameter spec
	 * @throws GeneralSecurityException if curve ist not available
	 */
	public static ECParameterSpec getECParameterSpec(String oid) throws GeneralSecurityException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(JceNames.EC);
		keyPairGenerator.initialize(new ECGenParameterSpec(oid));
		ECPublicKey apub = (ECPublicKey) keyPairGenerator.generateKeyPair().getPublic();
		return apub.getParams();
	}

	/**
	 * Get EdDSA standard algorithm name.
	 * 
	 * Supports {@link JceNames#ED25519v2} and {@link JceNames#ED448v2} as well.
	 * 
	 * @param algorithm algorithm
	 * @param def default algorithm
	 * @return Either {@link JceNames#OID_ED25519}, {@link JceNames#OID_ED448},
	 *         {@link JceNames#EDDSA}, or the provided default algorithm
	 * @see JceProviderUtil#getEdDsaStandardAlgorithmName(String, String)
	 * @deprecated use
	 *             {@link JceProviderUtil#getEdDsaStandardAlgorithmName(String, String)}
	 *             instead
	 * @since 2.4
	 */
	@Deprecated
	public static String getEdDsaStandardAlgorithmName(String algorithm, String def) {
		return JceProviderUtil.getEdDsaStandardAlgorithmName(algorithm, def);
	}

	/**
	 * Get KeyFactory for algorithm.
	 * 
	 * @param algorithm key algorithm
	 * @return key factory
	 * @throws NoSuchAlgorithmException if key algorithm is not supported
	 * @since 2.4
	 */
	public static KeyFactory getKeyFactory(String algorithm) throws NoSuchAlgorithmException {
		String standardAlgorithm = JceProviderUtil.getEdDsaStandardAlgorithmName(algorithm, algorithm);
		return KeyFactory.getInstance(standardAlgorithm);
	}

	/**
	 * Get KeyPairGenerator for algorithm.
	 * 
	 * @param algorithm key algorithm
	 * @return key pair generator
	 * @throws NoSuchAlgorithmException if key algorithm is not supported
	 * @since 3.0
	 */
	public static KeyPairGenerator getKeyPairGenerator(String algorithm) throws NoSuchAlgorithmException {
		String standardAlgorithm = JceProviderUtil.getEdDsaStandardAlgorithmName(algorithm, algorithm);
		return KeyPairGenerator.getInstance(standardAlgorithm);
	}

	/**
	 * Read CN from ASN.1 encoded DN.
	 * 
	 * @param data ASN.1 encoded DN
	 * @return CN, or {@code null}, if not found.
	 * @throws IllegalArgumentException if DN could not be read
	 * @since 3.0
	 */
	public static String readCNFromDN(byte[] data) {
		DatagramReader reader = new DatagramReader(data, false);
		reader = SEQUENCE.createRangeReader(reader, false);
		while (reader.bytesAvailable()) {
			DatagramReader setReader = SET.createRangeReader(reader, false);
			while (setReader.bytesAvailable()) {
				DatagramReader subReader = SEQUENCE.createRangeReader(setReader, false);
				byte[] oid = OID.readValue(subReader);
				if (Arrays.equals(oid, OID_CN)) {
					try {
						StringEntityDefinition value = new StringEntityDefinition(TAGS_STRING);
						return value.readStringValue(subReader);
					} catch (IllegalArgumentException ex) {
					}
				}
			}
		}
		return null;
	}

	/**
	 * Decoded keys.
	 * 
	 * May contain a private key, or public key, or both.
	 */
	public static class Keys {

		/**
		 * Private key.
		 */
		private PrivateKey privateKey;
		/**
		 * Public key.
		 */
		private PublicKey publicKey;

		/**
		 * Create empty keys.
		 * 
		 * The keys may be added later using {@link #add}.
		 */
		public Keys() {

		}

		/**
		 * Create keys.
		 * 
		 * @param privateKey private key. Maybe {@code null}.
		 * @param publicKey public key. Maybe {@code null}.
		 */
		public Keys(PrivateKey privateKey, PublicKey publicKey) {
			this.privateKey = privateKey;
			this.publicKey = publicKey;
		}

		/**
		 * Add keys.
		 * 
		 * Set the private and/or public key from the provided keys, if
		 * available.
		 * 
		 * @param keys keys t be added
		 */
		public void add(Keys keys) {
			if (keys.privateKey != null) {
				this.privateKey = keys.privateKey;
			}
			if (keys.publicKey != null) {
				this.publicKey = keys.publicKey;
			}
		}

		/**
		 * Get private key-
		 * 
		 * @return private key. Maybe {@code null}.
		 */
		public PrivateKey getPrivateKey() {
			return privateKey;
		}

		/**
		 * Set private key
		 * 
		 * @param privateKey private key
		 */
		public void setPrivateKey(PrivateKey privateKey) {
			this.privateKey = privateKey;
		}

		/**
		 * Get public key-
		 * 
		 * @return public key. Maybe {@code null}.
		 */
		public PublicKey getPublicKey() {
			return publicKey;
		}

		/**
		 * Set public key.
		 * 
		 * @param publicKey public key
		 */
		public void setPublicKey(PublicKey publicKey) {
			this.publicKey = publicKey;
		}
	}

	/**
	 * ASN.1 entity definition.
	 */
	private static class EntityDefinition {

		/**
		 * Header length of an entity. Tag and length bytes.
		 */
		private static final int HEADER_LENGTH = 2;
		/**
		 * Expected tag.
		 */
		private final int expectedTag;
		/**
		 * Maximum supported length.
		 */
		private final int maxLength;
		/**
		 * Entity description for error handling.
		 */
		private final String description;

		/**
		 * Create specific entity description.
		 * 
		 * @param expectedTag expected tag for this entity.
		 * @param maxLength maximum length for this entity.
		 * @param description description for error handling
		 */
		public EntityDefinition(int expectedTag, int maxLength, String description) {
			this.expectedTag = expectedTag;
			this.maxLength = maxLength;
			this.description = description;
		}

		/**
		 * Check read tag.
		 * 
		 * @param tag read tag
		 * @return {@code true}, if matching the {@link #expectedTag},
		 *         {@code false}, otherwise.
		 * @since 3.0
		 */
		public boolean checkTag(int tag) {
			return tag == expectedTag;
		}

		/**
		 * Read entity including tag and length into byte array.
		 * 
		 * @param reader reader containing the bytes to read.
		 * @return byte array containing the entity.
		 * @throws IllegalArgumentException if provided bytes doesn't contain
		 *             this valid entity.
		 */
		public byte[] readEntity(DatagramReader reader) {
			return read(reader, true);
		}

		/**
		 * Read value excluding tag and length into byte array.
		 * 
		 * @param reader reader containing the bytes to read.
		 * @return byte array containing the value.
		 * @throws IllegalArgumentException if provided bytes doesn't contain
		 *             this valid entity.
		 */
		public byte[] readValue(DatagramReader reader) {
			return read(reader, false);
		}

		/**
		 * Read value or entity.
		 * 
		 * @param reader reader containing the bytes to read.
		 * @param entity {@code true} to return the entity including the tag and
		 *            length, {@code false} to return the value excluding the
		 *            tag and length
		 * @return byte array containing the value or entity.
		 * @throws IllegalArgumentException if provided bytes doesn't contain
		 *             this valid entity.
		 */
		public byte[] read(DatagramReader reader, boolean entity) {
			int length = readLength(reader, entity);
			return reader.readBytes(length);
		}

		/**
		 * Create a range reader for value or entity.
		 * 
		 * @param reader reader containing the bytes to read.
		 * @param entity {@code true} to return the entity including the tag and
		 *            length, {@code false} to return the value excluding the
		 *            tag and length
		 * @return range reader for the value or entity.
		 * @throws IllegalArgumentException if provided bytes doesn't contain
		 *             this valid entity.
		 */
		public DatagramReader createRangeReader(DatagramReader reader, boolean entity) {
			int length = readLength(reader, entity);
			return reader.createRangeReader(length);
		}

		/**
		 * Read length value or entity.
		 * 
		 * @param reader reader containing the bytes to read.
		 * @param entity {@code true} to return the entity including the tag and
		 *            length, {@code false} to return the value excluding the
		 *            tag and length
		 * @return length of the value or entity.
		 * @throws IllegalArgumentException if provided bytes doesn't contain
		 *             this valid entity.
		 */
		public int readLength(DatagramReader reader, boolean entity) {
			int leftBytes = reader.bitsLeft() / Byte.SIZE;
			if (leftBytes < HEADER_LENGTH) {
				throw new IllegalArgumentException(String.format("Not enough bytes for %s! Required %d, available %d.",
						description, HEADER_LENGTH, leftBytes));
			}
			// mark reader, if the entity must be returned, or the tag doesn't
			// match
			reader.mark();
			// check tag
			int tag = reader.read(Byte.SIZE);
			if (!checkTag(tag)) {
				reader.reset();
				throw new IllegalArgumentException(
						String.format("No %s, found %02x instead of %02x!", description, tag, expectedTag));
			}
			// read length
			int length = reader.read(Byte.SIZE);
			int entityLength = length + HEADER_LENGTH;
			if (length > 127) {
				// multi bytes length
				length &= 0x7f;
				if (length > 4) {
					throw new IllegalArgumentException(
							String.format("%s length-size %d too long!", description, length));
				}
				leftBytes = reader.bitsLeft() / Byte.SIZE;
				if (length > leftBytes) {
					throw new IllegalArgumentException(
							String.format("%s length %d exceeds available bytes %d!", description, length, leftBytes));
				}
				byte[] lengthBytes = reader.readBytes(length);
				// decode multi bytes length
				length = 0;
				for (int index = 0; index < lengthBytes.length; ++index) {
					length <<= 8;
					length += (lengthBytes[index] & 0xff);
				}
				entityLength = length + HEADER_LENGTH + lengthBytes.length;
			}
			if (length > maxLength) {
				throw new IllegalArgumentException(
						String.format("%s lenght %d too large! (supported maxium %d)", description, length, maxLength));
			}
			leftBytes = reader.bitsLeft() / Byte.SIZE;
			if (length > leftBytes) {
				throw new IllegalArgumentException(
						String.format("%s lengh %d exceeds available bytes %d!", description, length, leftBytes));
			}
			if (entity) {
				reader.reset();
				length = entityLength;
			}
			return length;
		}
	}

	private static class OidEntityDefinition extends EntityDefinition {

		public OidEntityDefinition() {
			super(TAG_OID, MAX_OID_LENGTH, "OID");
		}

		/**
		 * Convert oid into string representation.
		 * 
		 * @param oid oid as byte array
		 * @return oid as string
		 * @throws IllegalArgumentException if oid is invalid.
		 */
		public String toString(byte[] oid) {
			StringBuilder result = new StringBuilder();
			int value = oid[0] & 0xff;
			result.append(value / 40).append(".").append(value % 40);
			for (int index = 1; index < oid.length; ++index) {
				byte bValue = oid[index];
				if (bValue < 0) {
					value = (bValue & 0b01111111);
					++index;
					if (index == oid.length) {
						throw new IllegalArgumentException("Invalid OID 0x" + StringUtil.byteArray2Hex(oid));
					}
					value <<= 7;
					value |= (oid[index] & 0b01111111);
					result.append(".").append(value);
				} else {
					result.append(".").append(bValue);
				}
			}
			return result.toString();
		}
	}

	private static class IntegerEntityDefinition extends EntityDefinition {

		public IntegerEntityDefinition() {
			super(TAG_INTEGER, MAX_DEFAULT_LENGTH, "INTEGER");
		}

		/**
		 * Convert integer byte array into int.
		 * 
		 * @param integerByteArray integer as byte array
		 * @return int
		 */
		public int toInteger(byte[] integerByteArray) {
			if (integerByteArray == null) {
				throw new NullPointerException("INTEGER byte array must not be null!");
			}
			if (integerByteArray.length == 0) {
				throw new IllegalArgumentException("INTEGER byte array must not be empty!");
			}
			if (integerByteArray.length > 4) {
				throw new IllegalArgumentException("INTEGER byte array " + integerByteArray.length
						+ " bytes is too large for int (max. 4 bytes)!");
			}
			byte sign = integerByteArray[0];
			int result = sign;
			for (int index = 1; index < integerByteArray.length; ++index) {
				result <<= Byte.SIZE;
				result |= (integerByteArray[index] & 0xff);
			}
			if (sign >= 0 ^ result >= 0) {
				throw new IllegalArgumentException("INTEGER byte array value overflow!");
			}
			return result;
		}
	}

	/**
	 * String entity.
	 * 
	 * @since 3,0
	 */
	private static class StringEntityDefinition extends EntityDefinition {

		private int tag;
		private int[] expectedTags;

		public StringEntityDefinition(int... expectedTags) {
			super(expectedTags[0], MAX_DEFAULT_LENGTH, "STRING");
			this.expectedTags = expectedTags;
		}

		@Override
		public boolean checkTag(int tag) {
			for (int expectedTag : expectedTags) {
				if (expectedTag == tag) {
					this.tag = tag;
					return true;
				}
			}
			return false;
		}

		/**
		 * Read string.
		 * 
		 * @param reader reader containing the bytes to read.
		 * @return string value.
		 * @throws IllegalArgumentException if provided bytes doesn't contain a
		 *             valid string entity.
		 */
		public String readStringValue(DatagramReader reader) {
			byte[] stringByteArray = readValue(reader);
			if (stringByteArray != null) {
				if (tag == TAG_PRINTABLE_STRING) {
					return new String(stringByteArray, StandardCharsets.US_ASCII);
				} else if (tag == TAG_UTF8_STRING) {
					return new String(stringByteArray, StandardCharsets.UTF_8);
				} else if (tag == TAG_BMP_STRING) {
					if (UCS_2 == null) {
						throw new IllegalArgumentException("BMP_STRING not supported!");
					}
					return new String(stringByteArray, UCS_2);
				} else if (tag == TAG_UNIVERSAL_STRING) {
					if (UCS_2 == null) {
						throw new IllegalArgumentException("UNIVERSAL_STRING not supported!");
					}
					return new String(stringByteArray, UCS_4);
				} else if (tag == TAG_TELETEX_STRING) {
					throw new IllegalArgumentException("TELETEX_STRING not supported!");
				}
			}
			return null;
		}
	}
}
