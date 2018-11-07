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
 *    Achim Kraus (Bosch Software Innovations GmbH) - use faster toHexString()
 *                                                    implementation and add
 *                                                    toHex().
 *    Achim Kraus (Bosch Software Innovations GmbH) - cleanup not longer used methods
 ******************************************************************************/
package org.eclipse.californium.scandium.util;

public class ByteArrayUtils {

	/**
	 * Concatenates two byte arrays.
	 * 
	 * @param a
	 *            the first array.
	 * @param b
	 *            the second array.
	 * @return the concatenated array.
	 */
	public static byte[] concatenate(byte[] a, byte[] b) {
		int lengthA = a.length;
		int lengthB = b.length;

		byte[] concat = new byte[lengthA + lengthB];

		System.arraycopy(a, 0, concat, 0, lengthA);
		System.arraycopy(b, 0, concat, lengthA, lengthB);

		return concat;
	}

	/**
	 * Takes a byte array and returns it HEX representation.
	 * 
	 * Intended for logging.
	 * 
	 * @param byteArray the byte array.
	 * @return the HEX representation. Separated by spaces, e.g. "11 22 0A". if
	 *         {@code null} or a empty array is provided, the result is "--".
	 */
	public static String toHexString(byte[] byteArray) {

		if (byteArray != null && byteArray.length != 0) {
			char[] bytesHexadecimal = new char[byteArray.length * 3];
			for (int src = 0, dest = 0; src < byteArray.length; src++) {
				int value = byteArray[src] & 0xFF;
				bytesHexadecimal[dest++] = BIN_TO_HEX_ARRAY[value >>> 4];
				bytesHexadecimal[dest++] = BIN_TO_HEX_ARRAY[value & 0x0F];
				bytesHexadecimal[dest++] = ' ';
			}
			return new String(bytesHexadecimal, 0, bytesHexadecimal.length - 1);
		} else {
			return "--";
		}
	}

	/**
	 * Takes a byte array and returns it compact HEX representation.
	 * 
	 * @param byteArray the byte array.
	 * @return the HEX representation.
	 */
	public static String toHex(byte[] byteArray) {

		char[] bytesHexadecimal = new char[byteArray.length * 2];
		for (int src = 0, dest = 0; src < byteArray.length; src++) {
			int value = byteArray[src] & 0xFF;
			bytesHexadecimal[dest++] = BIN_TO_HEX_ARRAY[value >>> 4];
			bytesHexadecimal[dest++] = BIN_TO_HEX_ARRAY[value & 0x0F];
		}
		return new String(bytesHexadecimal);
	}

	/**
	 * Trims the leading zeros.
	 * 
	 * @param byeArray the byte array with possible leading zeros.
	 * @return the byte array with no leading zeros.
	 */
	public static byte[] trimZeroes(byte[] byeArray) {
		// count how many leading zeros
		int count = 0;
		while ((count < byeArray.length - 1) && (byeArray[count] == 0)) {
			count++;
		}
		if (count == 0) {
			// no leading zeros initially
			return byeArray;
		}
		byte[] trimmedByteArray = new byte[byeArray.length - count];
		System.arraycopy(byeArray, count, trimmedByteArray, 0, trimmedByteArray.length);
		return trimmedByteArray;
	}
	
	/**
	 * Lookup table for hexadecimal digits.
	 * 
	 * @see #toHexString(byte[])
	 */
	private final static char[] BIN_TO_HEX_ARRAY = "0123456789ABCDEF".toCharArray();
}
