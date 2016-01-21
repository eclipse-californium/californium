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
 ******************************************************************************/
package org.eclipse.californium.scandium.util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ByteArrayUtils {

	/**
	 * Adds a padding to the given array, such that a new array with the given
	 * length is generated.
	 * 
	 * @param array
	 *            the array to be padded.
	 * @param value
	 *            the padding value.
	 * @param newLength
	 *            the new length of the padded array.
	 * @return the array padded with the given value.
	 */
	public static byte[] padArray(byte[] array, byte value, int newLength) {
		int length = array.length;
		int paddingLength = newLength - length;

		if (paddingLength < 1) {
			return array;
		} else {
			byte[] padding = new byte[paddingLength];
			Arrays.fill(padding, value);

			return concatenate(array, padding);
		}

	}

	/**
	 * Truncates the given array to the request length.
	 * 
	 * @param array
	 *            the array to be truncated.
	 * @param newLength
	 *            the new length in bytes.
	 * @return the truncated array.
	 */
	public static byte[] truncate(byte[] array, int newLength) {
		if (array.length < newLength) {
			return array;
		} else {
			byte[] truncated = new byte[newLength];
			System.arraycopy(array, 0, truncated, 0, newLength);

			return truncated;
		}
	}

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
	 * Computes array-wise XOR.
	 * 
	 * @param a
	 *            the first array.
	 * @param b
	 *            the second array.
	 * @return the XOR-ed array.
	 */
	public static byte[] xorArrays(byte[] a, byte[] b) {
		byte[] xor = new byte[a.length];

		for (int i = 0; i < a.length; i++) {
			xor[i] = (byte) (a[i] ^ b[i]);
		}

		return xor;
	}

	/**
	 * Splits the given array into blocks of given size and adds padding to the
	 * last one, if necessary.
	 * 
	 * @param byteArray
	 *            the array.
	 * @param blocksize
	 *            the block size.
	 * @return a list of blocks of given size.
	 */
	public static List<byte[]> splitAndPad(byte[] byteArray, int blocksize) {
		List<byte[]> blocks = new ArrayList<byte[]>();
		int numBlocks = (int) Math.ceil(byteArray.length / (double) blocksize);

		for (int i = 0; i < numBlocks; i++) {

			byte[] block = new byte[blocksize];
			Arrays.fill(block, (byte) 0x00);
			if (i + 1 == numBlocks) {
				// the last block
				int remainingBytes = byteArray.length - (i * blocksize);
				System.arraycopy(byteArray, i * blocksize, block, 0, remainingBytes);
			} else {
				System.arraycopy(byteArray, i * blocksize, block, 0, blocksize);
			}
			blocks.add(block);
		}

		return blocks;
	}

	/**
	 * Takes a byte array and returns it HEX representation.
	 * 
	 * @param byteArray
	 *            the byte array.
	 * @return the HEX representation.
	 */
	public static String toHexString(byte[] byteArray) {

		if (byteArray != null && byteArray.length != 0) {

			StringBuilder builder = new StringBuilder(byteArray.length * 3);
			for (int i = 0; i < byteArray.length; i++) {
				builder.append(String.format("%02X", 0xFF & byteArray[i]));

				if (i < byteArray.length - 1) {
					builder.append(' ');
				}
			}
			return builder.toString();
		} else {
			return "--";
		}
	}

	/**
	 * Takes a HEX stream and returns the corresponding byte array.
	 * 
	 * @param hexStream
	 *            the HEX stream.
	 * @return the byte array.
	 */
	public static byte[] hexStreamToByteArray(String hexStream) {
		int length = hexStream.length();

		byte[] data = new byte[length / 2];
		for (int i = 0; i < length; i += 2) {
			data[i / 2] = (byte) ((Character.digit(hexStream.charAt(i), 16) << 4) + Character.digit(hexStream.charAt(i + 1), 16));
		}
		return data;
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
}
