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

import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ASN.1 DER decoder for SEQUENCEs and OIDs.
 * <p>
 * To support EdDSA, either java 15, or java 11 with
 * <a href="https://github.com/str4d/ed25519-java">ed25519-java</a> is required
 * at runtime. Using java 15 to build Californium, leaves out {@code ed25519-java}, using
 * java 11 for building, includes {@code ed25519-java} by default. If
 * {@code ed25519-java} should <b>NOT</b> be included into the Californium's
 * jars, add {@code -Dno.net.i2p.crypto.eddsa=true} to maven's arguments. In
 * that case, it's still possible to use {@code ed25519-java}, if the <a href=
 * "https://repo1.maven.org/maven2/net/i2p/crypto/eddsa/0.3.0/eddsa-0.3.0.jar">eddsa-0.3.0.jar</a>
 * is provided to the classpath separately.
 * </p>
 */
public class Asn1DerDecoder {
	/**
	 * Key algorithm EC to be used by KeyFactory.
	 */
	public static final String EC = "EC";
	/**
	 * Key algorithm RSA to be used by KeyFactory.
	 */
	public static final String RSA = "RSA";
	/**
	 * Key algorithm DSA to be used by KeyFactory.
	 */
	public static final String DSA = "DSA";
	/**
	 * Key algorithm DH to be used by KeyFactory.
	 */
	public static final String DH = "DH";
	/**
	 * Key algorithm EC v2 (RFC 5958), not to be used by KeyFactory.
	 * 
	 * @see #readEcPrivateKeyV2(byte[])
	 */
	public static final String ECv2 = "EC.v2";
	/**
	 * Key algorithm ED25519 (RFC 8422).
	 * 
	 * Used with {@link #getEdDsaProvider()}.
	 * 
	 * @since 2.4
	 */
	public static final String ED25519 = "ED25519";
	/**
	 * Key algorithm Ed25519 v2 (RFC 8410), not to be used by KeyFactory.
	 * 
	 * @see #readEdDsaPrivateKeyV2(byte[])
	 * 
	 * @since 3.0
	 */
	public static final String ED25519v2 = "ED25519.v2";
	/**
	 * Key algorithm ED448 (RFC 8422).
	 * 
	 * Used with {@link #getEdDsaProvider()}.
	 * 
	 * @since 2.4
	 */
	public static final String ED448 = "ED448";
	/**
	 * Key algorithm Ed448 v2 (RFC 8410), not to be used by KeyFactory.
	 * 
	 * @see #readEdDsaPrivateKeyV2(byte[])
	 * 
	 * @since 3.0
	 */
	public static final String ED448v2 = "ED448.v2";
	/**
	 * OID key algorithm ED25519 (RFC 8422).
	 * 
	 * Used with {@link #getEdDsaProvider()}.
	 * 
	 * @since 2.4
	 */
	public static final String OID_ED25519 = "OID.1.3.101.112";
	/**
	 * OID key algorithm ED448 (RFC 8422).
	 * 
	 * Used with {@link #getEdDsaProvider()}.
	 * 
	 * @since 2.4
	 */
	public static final String OID_ED448 = "OID.1.3.101.113";
	/**
	 * Key algorithm EdDSA (RFC 8422).
	 * 
	 * Used with {@link #getEdDsaProvider()}.
	 * 
	 * @since 2.4
	 */
	public static final String EDDSA = "EdDSA";
	/**
	 * ECPoint uncompressed.
	 * <a href="https://tools.ietf.org/html/rfc5480#section-2.2">RFC 5480, Section 2.2</a>
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
	 * ASN.1 OID for DH public key.
	 */
	private static final byte[] OID_DH_PUBLIC_KEY = { 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01,
			0x03, 0x01 };
	/**
	 * ASN.1 OID for DSA public key.
	 */
	private static final byte[] OID_DSA_PUBLIC_KEY = { 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x38, 0x04, 0x01 };
	/**
	 * ASN.1 OID for EC public key.
	 */
	private static final byte[] OID_EC_PUBLIC_KEY = { 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x02, 0x01 };
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
	 * ASN.1 entity definition for SEQUENCE.
	 */
	private static final EntityDefinition SEQUENCE = new EntityDefinition(TAG_SEQUENCE, MAX_DEFAULT_LENGTH, "SEQUENCE");
	/**
	 * ASN.1 entity definition for OID.
	 */
	private static final OidEntityDefinition OID = new OidEntityDefinition();
	/**
	 * ASN.1 entity definition for INTEGER.
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
	private static final EntityDefinition CONTEXT_SPECIFIC_PRIMITIVE_1 = new EntityDefinition(TAG_CONTEXT_1_SPECIFIC_PRIMITIVE,
			MAX_DEFAULT_LENGTH, "CONTEXT SPECIFIC PRIMITIVE 1");

	/**
	 * Alias algorithms for Ed25519.
	 * 
	 * @since 3.0
	 */
	private static final String[] ED25519_ALIASES = { ED25519, "1.3.101.112", OID_ED25519, EDDSA };

	/**
	 * Alias algorithms for Ed448.
	 * 
	 * @since 3.0
	 */
	private static final String[] ED448_ALIASES = { ED448, "1.3.101.113", OID_ED448, EDDSA };

	/**
	 * Table of algorithm aliases.
	 * 
	 * @since 3.0
	 */
	private static final String[][] ALGORITHM_ALIASES = { { "DH", "DiffieHellman" }, ED25519_ALIASES, ED448_ALIASES };

	private static final Logger LOGGER = LoggerFactory.getLogger(Asn1DerDecoder.class);

	/**
	 * Provider for EdDsa.
	 * 
	 * Either java 15 SunEC, or, for java version before, external java 7
	 * <a href="https://github.com/str4d/ed25519-java">net.i2p.crypto.eddsa</a>.
	 * 
	 * @since 2.4
	 */
	private static final Provider EDDSA_PROVIDER;
	private static final boolean ED25519_SUPPORT;
	private static final boolean ED448_SUPPORT;

	/**
	 * Package name for external java 7 EdDSA provider.
	 */
	private static final String NET_I2P_CRYPTO_EDDSA = "net.i2p.crypto.eddsa";

	static {
		boolean ed25519 = false;
		boolean ed448 = false;
		Provider provider = null;
		try {
			KeyFactory factory = KeyFactory.getInstance("EdDSA");
			provider = factory.getProvider();
			ed25519 = true;
			ed448 = true;
			LOGGER.trace("EdDSA from jvm {}", provider.getName());
		} catch (NoSuchAlgorithmException e) {
			Throwable cause = null;
			try {
				Class<?> clz = Class.forName(NET_I2P_CRYPTO_EDDSA + ".EdDSASecurityProvider");
				if (clz != null) {
					provider = (Provider) clz.getDeclaredConstructor().newInstance();
					Security.addProvider(provider);
					ed25519 = true;
					ed448 = false;
					LOGGER.trace("EdDSA from {}", NET_I2P_CRYPTO_EDDSA);
				}
			} catch (ClassNotFoundException e2) {
				cause = e2;
			} catch (InstantiationException e2) {
				cause = e2;
			} catch (IllegalAccessException e2) {
				cause = e2;
			} catch (IllegalArgumentException e2) {
				cause = e2;
			} catch (InvocationTargetException e2) {
				cause = e2;
			} catch (NoSuchMethodException e2) {
				cause = e2;
			} catch (SecurityException e2) {
				cause = e2;
			}
			if (provider == null) {
				LOGGER.trace("{} is not available!", NET_I2P_CRYPTO_EDDSA, cause);
			}
		}
		EDDSA_PROVIDER = provider;
		ED25519_SUPPORT = ed25519;
		ED448_SUPPORT = ed448;
	}

	/**
	 * Checks, whether the set contains the value, or not. The check is done
	 * using {@link String#equalsIgnoreCase(String)}.
	 * 
	 * @param set set of strings
	 * @param value value to match
	 * @return {@code true}, if value is contained in set, {@code false},
	 *         otherwise.
	 * @since 3.0
	 */
	private static boolean contains(String[] set, String value) {
		for (String item : set) {
			if (item.equalsIgnoreCase(value)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Gets the algorithm of the public key.
	 * 
	 * The v2 variants are not supported by the java 7 KeyFactory.
	 * 
	 * @param oid OID of public key.
	 * @param version version of format. {@code 0}, for v1, {@code 2} for v2.
	 * @return {@link #EC}, {@link #RSA}, {@link #DSA}, {@link #DH},
	 *         {@link #ED25519}, and {@link #ED448} for v1, {@link #ECv2},
	 *         {@link #ED25519v2}, and {@link #ED448v2} for v2, {@code null}, if
	 *         unknown.
	 * @since 3.0
	 */
	private static String getPublicKeyAlgorithm(final byte[] oid, int version) {
		String algorithm = null;
		if (Arrays.equals(oid, OID_EC_PUBLIC_KEY)) {
			algorithm = version == 0 ? EC : ECv2;
		} else if (Arrays.equals(oid, OID_RSA_PUBLIC_KEY)) {
			algorithm = version == 0 ? RSA : null;
		} else if (Arrays.equals(oid, OID_DSA_PUBLIC_KEY)) {
			algorithm = version == 0 ? DSA : null;
		} else if (Arrays.equals(oid, OID_DH_PUBLIC_KEY)) {
			algorithm = version == 0 ? DH : null;
		} else if (Arrays.equals(oid, OID_ED25519_PUBLIC_KEY)) {
			algorithm = version == 0 ? ED25519 : ED25519v2;
		} else if (Arrays.equals(oid, OID_ED448_PUBLIC_KEY)) {
			algorithm = version == 0 ? ED448 : ED448v2;
		}
		return algorithm;
	}

	/**
	 * Get EdDSA provider.
	 * 
	 * Either java 15 SunEC, or, for java version before, external java 7
	 * <a href="https://github.com/str4d/ed25519-java">net.i2p.crypto.eddsa</a>.
	 * 
	 * To disable external java 7 EdDSA provider, set
	 * "net_i2p_crypto_eddsa_disable" to true in environment or system
	 * properties.
	 * 
	 * @return EdDSA provider, or {@code null}, if not available or disabled.
	 * @since 2.4
	 */
	public static Provider getEdDsaProvider() {
		return EDDSA_PROVIDER;
	}

	/**
	 * Check, if key algorithm is supported.
	 * 
	 * @param algorithm key algorithm
	 * @return {@code true}, if supported, {@code false}, otherwise.
	 * @since 2.4
	 */
	public static boolean isSupported(String algorithm) {
		if (EC.equalsIgnoreCase(algorithm)) {
			return true;
		} else {
			String oid = getEdDsaStandardAlgorithmName(algorithm, null);
			if (OID_ED25519.equals(oid)) {
				return ED25519_SUPPORT;
			} else if (OID_ED448.equals(oid)) {
				return ED448_SUPPORT;
			} else if (EDDSA.equalsIgnoreCase(algorithm)) {
				return ED25519_SUPPORT || ED448_SUPPORT;
			}
		}
		return false;
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
	 * <a href="https://tools.ietf.org/html/rfc5480">RFC 5480</a>
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
	 * <a href="https://tools.ietf.org/html/rfc5480">RFC 5480</a>
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
	 * v1 (PKCS8), <a href="https://tools.ietf.org/html/rfc5208">RFC 5208</a>
	 * PrivateKeyInfo ::= SEQUENCE {
	 *  version                   Version,
	 *  privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
	 *  privateKey                PrivateKey,
	 *  attributes           [0]  IMPLICIT Attributes OPTIONAL }
	 * 
	 * v2 (PKCS12), 
	 * <a href="https://tools.ietf.org/html/rfc5958">RFC 5958 - (EC only!)</a>,
	 * <a href="https://tools.ietf.org/html/rfc8410">RFC 8410 - EdDSA</a>
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
	 * @return key algorithm name to be used by KeyFactory, or {@link #ECv2},
	 *         {@link #ED25519v2}, and {@link #ED448v2} for v2, which are not
	 *         supported by the java 7 KeyFactory, or {@code null}, if unknown.
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
		if (version < 0 && version > 1) {
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
							algorithm = ECv2;
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
	 * v1 (PKCS8), <a href="https://tools.ietf.org/html/rfc5208">RFC 5208</a>
	 * PrivateKeyInfo ::= SEQUENCE {
	 *  version                   Version,
	 *  privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
	 *  privateKey                PrivateKey,
	 *  attributes           [0]  IMPLICIT Attributes OPTIONAL }
	 * 
	 * v2 (PKCS12), 
	 * <a href="https://tools.ietf.org/html/rfc5958">RFC 5958 - (EC only!)</a>,
	 * <a href="https://tools.ietf.org/html/rfc8410">RFC 8410 - EdDSA</a>
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
			if (algorithm == ED25519v2 || algorithm == ED448v2) {
				keys = readEdDsaPrivateKeyV2(data);
			} else if (algorithm == ECv2) {
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
			} catch(IllegalArgumentException ex) {
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
				keys.privateKey = KeyFactory.getInstance(EC).generatePrivate(privateKeySpec);
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
	 * <a href="https://tools.ietf.org/html/rfc5480#section-2.2">RFC 5480, Section 2.2</a>
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
				return (ECPublicKey) KeyFactory.getInstance(EC).generatePublic(publicKeySpec);
			}
		}
		return null;
	}

	/**
	 * Read EdDSA private key (and public key) from PKCS12 / RFC 8410 v2 format.
	 * 
	 * See <a href="https://tools.ietf.org/html/rfc8410">RFC 8410 - EdDSA</a>.
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
	 * Check for equal key algorithm synonyms.
	 * 
	 * Currently on "DH" and "DiffieHellman" are supported synonyms.
	 * 
	 * @param keyAlgorithm1 key algorithm 1
	 * @param keyAlgorithm2 key algorithm 2
	 * @return {@code true}, if the key algorithms are equal or synonyms,
	 *         {@code false}, otherwise.
	 */
	public static boolean equalKeyAlgorithmSynonyms(String keyAlgorithm1, String keyAlgorithm2) {
		if (keyAlgorithm1.equals(keyAlgorithm2)) {
			return true;
		}
		for (String[] aliases : ALGORITHM_ALIASES) {
			if (contains(aliases, keyAlgorithm1) && contains(aliases, keyAlgorithm2)) {
				return true;
			}
		}
		return false;
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
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(EC);
		keyPairGenerator.initialize(new ECGenParameterSpec(oid));
		ECPublicKey apub = (ECPublicKey) keyPairGenerator.generateKeyPair().getPublic();
		return apub.getParams();
	}

	/**
	 * Get EdDSA standard algorithm name.
	 * 
	 * @param algorithm algorithm
	 * @param def default algorithm
	 * @return Either {@link #OID_ED25519}, {@link #OID_ED448}, {@link #EDDSA},
	 *         or the provided default algorithm
	 * @since 2.4
	 */
	public static String getEdDsaStandardAlgorithmName(String algorithm, String def) {
		if (algorithm.equalsIgnoreCase(EDDSA)) {
			return EDDSA;
		} else if (contains(ED25519_ALIASES, algorithm)) {
			return OID_ED25519;
		} else if (contains(ED448_ALIASES, algorithm)) {
			return OID_ED448;
		} else {
			return def;
		}
	}

	/**
	 * Get KeyFactory for algorithm.
	 * 
	 * Uses {@link #EDDSA_PROVIDER} for EdDSA keys.
	 * 
	 * @param algorithm key algorithm
	 * @return key factory
	 * @throws NoSuchAlgorithmException if key algorithm is not supported
	 * @since 2.4
	 */
	public static KeyFactory getKeyFactory(String algorithm) throws NoSuchAlgorithmException {
		String oid = null;
		if (EDDSA_PROVIDER != null) {
			oid = getEdDsaStandardAlgorithmName(algorithm, null);
		}
		if (oid != null) {
			return KeyFactory.getInstance(oid, EDDSA_PROVIDER);
		} else {
			return KeyFactory.getInstance(algorithm);
		}
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
		String oid = null;
		if (EDDSA_PROVIDER != null) {
			oid = getEdDsaStandardAlgorithmName(algorithm, null);
		}
		if (oid != null) {
			return KeyPairGenerator.getInstance(oid, EDDSA_PROVIDER);
		} else {
			return KeyPairGenerator.getInstance(algorithm);
		}
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
			// mark reader, if the entity must be returned, or the tag doesn't match
			reader.mark();
			// check tag
			int tag = reader.read(Byte.SIZE);
			if (tag != expectedTag) {
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
}
