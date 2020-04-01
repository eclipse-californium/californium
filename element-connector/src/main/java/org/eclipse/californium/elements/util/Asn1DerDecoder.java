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
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
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

/**
 * ASN.1 DER decoder for SEQUENCEs and OIDs.
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

		String algorithm = null;
		if (Arrays.equals(value, OID_EC_PUBLIC_KEY)) {
			algorithm = EC;
		} else if (Arrays.equals(value, OID_RSA_PUBLIC_KEY)) {
			algorithm = RSA;
		} else if (Arrays.equals(value, OID_DSA_PUBLIC_KEY)) {
			algorithm = DSA;
		} else if (Arrays.equals(value, OID_DH_PUBLIC_KEY)) {
			algorithm = DH;
		}
		return algorithm;
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
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(data);
			publicKey = KeyFactory.getInstance(algorithm).generatePublic(publicKeySpec);
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
	 * v1, <a href="https://tools.ietf.org/html/rfc5208">RFC 5208 - PKCS8</a>
	 * PrivateKeyInfo ::= SEQUENCE {
	 *  version                   Version,
	 *  privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
	 *  privateKey                PrivateKey,
	 *  attributes           [0]  IMPLICIT Attributes OPTIONAL }
	 * 
	 * v2, <a href=
	"https://tools.ietf.org/html/rfc5958">RFC 5958 - PKCS12 (EC only!)</a>
	 * 
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
	 * @return key algorithm name to be used by KeyFactory, "EC.v2" for RFC 5958
	 *         encoding, which is not supported directly by java 7 KeyFactory.
	 *         Or {@code null}, if the OID of the private key is unknown.
	 * @throws IllegalArgumentException if the private key algorithm could not
	 *             be read
	 */
	public static String readPrivateKeyAlgorithm(final byte[] data) {
		String algorithm = null;
		// outer sequence, PrivateKeyInfo
		DatagramReader reader = new DatagramReader(data, false);
		reader = SEQUENCE.createRangeReader(reader, false);
		// INTEGER version
		byte[] readValue = INTEGER.readValue(reader);
		int version = INTEGER.toInteger(readValue);
		if (version == 0) {
			// RFC 5208, v1
			// inner sequence, AlgorithmIdentifier
			reader = SEQUENCE.createRangeReader(reader, false);
			// oid, algorithm
			byte[] value = readOidValue(reader);
			if (Arrays.equals(value, OID_EC_PUBLIC_KEY)) {
				algorithm = EC;
			} else if (Arrays.equals(value, OID_RSA_PUBLIC_KEY)) {
				algorithm = RSA;
			} else if (Arrays.equals(value, OID_DSA_PUBLIC_KEY)) {
				algorithm = DSA;
			} else if (Arrays.equals(value, OID_DH_PUBLIC_KEY)) {
				algorithm = DH;
			}
		} else if (version == 1) {
			// RFC 5958
			// OCTET_STRING
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
			throw new IllegalArgumentException("Version 0x" + StringUtil.byteArray2Hex(data) + " not supported!");
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
	 * v1, <a href="https://tools.ietf.org/html/rfc5208">RFC 5208 - PKCS8</a>
	 * PrivateKeyInfo ::= SEQUENCE {
	 *  version                   Version,
	 *  privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
	 *  privateKey                PrivateKey,
	 *  attributes           [0]  IMPLICIT Attributes OPTIONAL }
	 * 
	 * v2, <a href="https://tools.ietf.org/html/rfc5958">RFC 5958 - PKCS12 (EC only!)</a>
	 * 
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
	 *         key for RFC 5958 encoding. Or {@code null}, if the OID of the
	 *         private key is unknown.
	 * @throws GeneralSecurityException if private key could not be read
	 */
	public static Keys readPrivateKey(final byte[] data) throws GeneralSecurityException {
		Keys keys = null;
		String algorithm = readPrivateKeyAlgorithm(data);
		if (algorithm != null) {
			if (algorithm.equals(ECv2)) {
				keys = readEcPrivateKeyV2(data);
			} else {
				EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(data);
				keys = new Keys();
				keys.privateKey = KeyFactory.getInstance(algorithm).generatePrivate(privateKeySpec);
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
		if (!keyAlgorithm1.equals(keyAlgorithm2)) {
			// currently just hard encoded check.
			if (keyAlgorithm1.equals("DH") && keyAlgorithm2.equals("DiffieHellman")) {
				return true;
			} else if (keyAlgorithm2.equals("DH") && keyAlgorithm1.equals("DiffieHellman")) {
				return true;
			}
			return false;
		}
		return true;
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
		 * The keys maybe {@link #add(Keys)} later.
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
			// mark reader, if the entity must be returned
			if (entity) {
				reader.mark();
			}
			// check tag
			int tag = reader.read(Byte.SIZE);
			if (tag != expectedTag) {
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
