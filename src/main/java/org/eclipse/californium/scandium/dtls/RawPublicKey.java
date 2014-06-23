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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.scandium.util.ByteArrayUtils;
import org.eclipse.californium.scandium.util.DatagramReader;
import org.eclipse.californium.scandium.util.DatagramWriter;


/**
 * A raw public key only contains the SubjectPublicKeyInfo structure instead of
 * the entire certificate. This usage of raw public keys, instead of X.509-based
 * certificates, leads to a smaller code footprint. For details see <a
 * href="http://tools.ietf.org/html/draft-ietf-tls-oob-pubkey-03">TLS
 * Out-of-Band Public Key Validation</a> and <a
 * href="http://tools.ietf.org/html/rfc5480">RFC 5480</a>.
 */
public class RawPublicKey {

	// Logging ///////////////////////////////////////////////////////////

	private static final Logger LOGGER = Logger.getLogger(RawPublicKey.class.getCanonicalName());

	// Tags ///////////////////////////////////////////////////////////

	private final static int BIT_STRING_TAG = 0x03;

	private final static int NULL_TAG = 0x05;

	private final static int OBJECT_IDENTIFIER_TAG = 0x06;

	private final static int SEQUENCE_TAG = 0x30;

	// Constants //////////////////////////////////////////////////////

	private static final int OCTET_BITS = 8;

	// Members ////////////////////////////////////////////////////////

	private int[] algorithmOID;

	private int[] parametersOID;

	private byte[] subjectPublicKey;

	// Constructors ///////////////////////////////////////////////////

	public RawPublicKey() {
		this.subjectPublicKey = null;
		this.algorithmOID = null;
		this.parametersOID = null;
	}

	public RawPublicKey(byte[] subjectPublicKey, int[] algorithmOID, int[] parametersOID) {
		this.subjectPublicKey = subjectPublicKey;
		this.algorithmOID = algorithmOID;
		this.parametersOID = parametersOID;
	}

	// Serialization //////////////////////////////////////////////////

	public byte[] toByteArray() {

		DatagramWriter writer = new DatagramWriter();

		// AlgorithmIdentifier ::= SEQUENCE {
		// algorithm OBJECT IDENTIFIER,
		// parameters ANY DEFINED BY algorithm OPTIONAL
		// }
		byte[] algorithmBytes = writeTLV(OBJECT_IDENTIFIER_TAG, encodeOID(algorithmOID));
		byte[] parametersBytes;
		if (parametersOID != null) {
			parametersBytes = writeTLV(OBJECT_IDENTIFIER_TAG, encodeOID(parametersOID));
		} else {
			parametersBytes = writeTLV(NULL_TAG, new byte[0]);
		}
		byte[] algorithmIdentifierBytes = writeTLV(SEQUENCE_TAG, ByteArrayUtils.concatenate(algorithmBytes, parametersBytes));

		// SubjectPublicKeyInfo ::= SEQUENCE {
		// algorithm AlgorithmIdentifier,
		// subjectPublicKey BIT STRING
		// }
		byte[] subjectPublicKeyBytes = writeTLV(BIT_STRING_TAG, subjectPublicKey);
		byte[] subjectPublicKeyInfo = writeTLV(SEQUENCE_TAG, ByteArrayUtils.concatenate(algorithmIdentifierBytes, subjectPublicKeyBytes));

		writer.writeBytes(subjectPublicKeyInfo);

		return writer.toByteArray();
	}

	public static RawPublicKey fromByteArray(byte[] byteArray) {

		RawPublicKey rawPublicKey = new RawPublicKey();
		readTLV(byteArray, rawPublicKey);

		return rawPublicKey;
	}

	// Methods ////////////////////////////////////////////////////////

	/**
	 * Reads a part of the bytestream according to the specified DER tag and the
	 * length.
	 * 
	 * @param byteArray
	 *            the encoded TLV triplet.
	 * @param rawPublicKey
	 *            the {@link RawPublicKey} which needs to be initialized.
	 */
	private static void readTLV(byte[] byteArray, RawPublicKey rawPublicKey) {
		DatagramReader reader = new DatagramReader(byteArray);

		while (reader.bytesAvailable()) {
			int tag = reader.read(OCTET_BITS);
			int length = reader.read(OCTET_BITS);

			// decode the length of the value, if encoded into multiply bytes
			if (length > 127) {
				int additionalBytes = length & 0x7F;
				length = reader.read(additionalBytes * OCTET_BITS);
			}
			byte[] fragment = reader.readBytes(length);

			switch (tag) {
			case SEQUENCE_TAG:
				readTLV(fragment, rawPublicKey);
				break;

			case OBJECT_IDENTIFIER_TAG:
				int[] oid = decodeOID(fragment);
				rawPublicKey.setObjectIdentifier(oid);
				break;

			case BIT_STRING_TAG:
				// strip the first byte (unused counter)
				// http://msdn.microsoft.com/en-us/library/windows/desktop/bb540792(v=vs.85).aspx
				byte[] subjectPublicKey = new byte[fragment.length - 1];
				System.arraycopy(fragment, 1, subjectPublicKey, 0, fragment.length - 1);
				rawPublicKey.setBitString(subjectPublicKey);
				break;

			case NULL_TAG:
				// do nothing
				// http://msdn.microsoft.com/en-us/library/windows/desktop/bb540808(v=vs.85).aspx
				break;

			default:
				if (LOGGER.isLoggable(Level.WARNING)) {
				    LOGGER.warning("Unknown DER tag: " + tag);
				}
				break;
			}
		}
	}

	/**
	 * Writes a TLV triplet (tag-length-value).
	 * 
	 * @param tag
	 *            the tag.
	 * @param value
	 *            the value to be written.
	 * @return the corresponding byte array representation.
	 */
	private byte[] writeTLV(int tag, byte[] value) {
		DatagramWriter writer = new DatagramWriter();

		// write the tag
		writer.write(tag, OCTET_BITS);

		switch (tag) {
		case BIT_STRING_TAG:
			// add the unused field to the value, as described here:
			// http://msdn.microsoft.com/en-us/library/windows/desktop/bb540792(v=vs.85).aspx
			byte[] unusedByte = new byte[1];

			// in our cases, there are never unused bits in the last byte
			unusedByte[0] = 0x00;
			value = ByteArrayUtils.concatenate(unusedByte, value);
			break;

		default:
			break;
		}

		int length = value.length;
		if (length > 127) {
			/*
			 * If it is more than 127 bytes, bit 7 of the Length field is set to
			 * 1 and bits 6 through 0 specify the number of additional bytes
			 * used to identify the content length.
			 */
			int additionalBytes = 0;
			if (length >= 16777216) { // 2^24
				additionalBytes = 4;
			} else if (length >= 65536) { // 2^16
				additionalBytes = 3;
			} else if (length >= 256) { // 2^8
				additionalBytes = 2;
			} else {
				additionalBytes = 1;
			}
			int lengthField = 0x80;
			lengthField += additionalBytes;
			writer.write(lengthField, OCTET_BITS);
			writer.write(length, additionalBytes * OCTET_BITS);

		} else {
			/*
			 * If the SEQUENCE contains fewer than 128 bytes, the Length field
			 * of the TLV triplet requires only one byte to specify the content
			 * length.
			 */
			writer.write(length, OCTET_BITS);
		}
		writer.writeBytes(value);

		return writer.toByteArray();
	}

	/**
	 * Decodes a given byte stream into a OBJECT IDENTIFIER data type. See <a
	 * href=
	 * "http://msdn.microsoft.com/en-us/library/windows/desktop/bb540809(v=vs.85).aspx"
	 * >OBJECT IDENTIFIER</a> for details.
	 * 
	 * @param encoded
	 *            the encoded object identifier.
	 * @return the object identifier.
	 */
	public static int[] decodeOID(byte[] encoded) {
		List<Integer> list = new ArrayList<Integer>();

		int value = encoded[0];
		int first = value / 40;
		int second = value % 40;

		list.add(first);
		list.add(second);

		value = 0;
		List<Byte> values = new ArrayList<Byte>();
		for (int i = 1; i < encoded.length; i++) {
			byte b = encoded[i];
			values.add(b);

			// check if the highest bit of the byte is set to 1, then it's a
			// multiple byte encoding
			if ((b & 0x80) > 0) {
				// do nothing, encoding of this values not finished
			} else {
				// value encoded in on byte or last byte of multiple encoded
				// value
				Collections.reverse(values);
				int length = values.size();
				int v = 0;
				for (int j = length - 1; j >= 0; j--) {

					if (j > 0) {
						// remove the leftmost bit and "multiply" according to
						// order
						v += ((int) (values.get(j) & 0x7F)) << (7 * j);
					} else {
						// set the most left bit of the byte to zero indicating
						// this is the last byte
						// 0x7F = 0111 1111
						v += values.get(j);
					}

				}
				list.add(v);

				values.clear();
			}
		}
		int[] result = new int[list.size()];
		for (int i = 0; i < list.size(); i++) {
			result[i] = list.get(i);
		}

		return result;
	}

	/**
	 * Encodes an OBJECT IDENTIFIER data type into its byte representations. See
	 * <a href=
	 * "http://msdn.microsoft.com/en-us/library/windows/desktop/bb540809(v=vs.85).aspx"
	 * >OBJECT IDENTIFIER</a> for details.
	 * 
	 * @param oid
	 *            the object identifier.
	 * @return the encoded ibject identifier.
	 */
	public static byte[] encodeOID(int[] oid) {

		byte[] encoded = new byte[0];

		// first two nodes combined
		byte[] firstTwo = new byte[1];
		firstTwo[0] = (byte) (40 * oid[0] + oid[1]);
		encoded = ByteArrayUtils.concatenate(encoded, firstTwo);

		for (int i = 2; i < oid.length; i++) {
			int value = oid[i];

			int length;
			if (value >= 268435456) { // 2^28
				length = 5;
			} else if (value >= 2097152) { // 2^21
				length = 4;
			} else if (value >= 16384) { // 2^14
				length = 3;
			} else if (value >= 128) { // 2^7
				length = 2;
			} else {
				length = 1;
			}

			for (int j = length - 1; j >= 0; j--) {
				byte[] b = new byte[1];
				if (j > 0) {
					// Set the most left bit to 1 indicating that there follows
					// another byte
					// 0x80 = 1000 0000
					b[0] = (byte) (((value >> (7 * j)) & 0x7F) | 0x80);
				} else {
					// set the most left bit of the byte to zero indicating this
					// is the last byte
					// 0x7F = 0111 1111
					b[0] = (byte) (value & 0x7F);
				}
				encoded = ByteArrayUtils.concatenate(encoded, b);
			}
		}

		return encoded;
	}

	// Getters and Setters ////////////////////////////////////////////

	public void setObjectIdentifier(int[] oid) {
		if (algorithmOID != null) {
			parametersOID = oid;
		} else {
			algorithmOID = oid;
		}
	}

	public void setBitString(byte[] bitString) {
		subjectPublicKey = bitString;
	}

	public byte[] getSubjectPublicKey() {
		return subjectPublicKey;
	}

	public int[] getAlgorithmOID() {
		return algorithmOID;
	}

	public int[] getParametersOID() {
		return parametersOID;
	}

}
