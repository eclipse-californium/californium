/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.util.Arrays;

/**
 * ASN.1 DER decoder for SEQUENCEs and OIDs.
 */
public class Asn1DerDecoder {

	/**
	 * Maximum supported length for ASN.1 SEQUENCE.
	 */
	private static final int MAX_SEQUENCE_LENGTH = 0x10000;
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
	private static final EntityDefinition SEQUENCE = new EntityDefinition(TAG_SEQUENCE, MAX_SEQUENCE_LENGTH,
			"SEQUENCE");
	/**
	 * ASN.1 entity definition for OID.
	 */
	private static final EntityDefinition OID = new EntityDefinition(TAG_OID, MAX_OID_LENGTH, "OID");

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
	 * Read key algorithm from subjects public key.
	 * 
	 * Read key algorithm from subjects public key encoded in ASN.1 DER.
	 * 
	 * <pre>
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
	 * @return key algorithm name to be used by KeyFactory. Maybe {@code null},
	 *         if the OID of the subject public key is unknown.
	 * @throws IllegalArgumentException if provided bytes doesn't contain a
	 *             subject public key.
	 */
	public static String readSubjectPublicKeyAlgorithm(final byte[] data) {
		// outer sequence, SubjectPublicKeyInfo
		DatagramReader reader = new DatagramReader(data);
		byte[] value = readSequenceValue(reader);
		// inner sequence, AlgorithmIdentifier
		reader = new DatagramReader(value);
		value = readSequenceValue(reader);
		// oid, algorithm
		reader = new DatagramReader(value);
		value = readOidValue(reader);

		if (Arrays.equals(value, OID_EC_PUBLIC_KEY)) {
			return "EC";
		}
		if (Arrays.equals(value, OID_RSA_PUBLIC_KEY)) {
			return "RSA";
		}
		if (Arrays.equals(value, OID_DSA_PUBLIC_KEY)) {
			return "DSA";
		}
		if (Arrays.equals(value, OID_DH_PUBLIC_KEY)) {
			return "DH";
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
			return reader.readBytes(length);
		}
	}
}
