/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add byteArray2HexString
 *                                                    and trunc
 ******************************************************************************/
package org.eclipse.californium.elements.util;

/**
 * String utils (as there are so many already out).
 */
public class StringUtil {

	/**
	 * Convert hexadecimal String into decoded character array. Intended to be
	 * used for passwords.
	 * 
	 * @param hex hexadecimal string. e.g. "4130010A"
	 * @return character array with decoded hexadecimal input parameter. e.g.
	 *         char[] { 'A', '0', 0x01, '\n' }.
	 * @throws IllegalArgumentException if the parameter length is odd or
	 *             contains non hexadecimal characters.
	 */
	public static char[] hex2CharArray(String hex) {
		if (hex == null) {
			return null;
		}
		int length = hex.length();
		if ((1 & length) != 0) {
			throw new IllegalArgumentException("'" + hex + "' has odd length!");
		}
		length /= 2;
		char[] result = new char[length];
		for (int indexDest = 0, indexSrc = 0; indexDest < length; ++indexDest) {
			int digit = Character.digit(hex.charAt(indexSrc), 16);
			if (digit < 0) {
				throw new IllegalArgumentException("'" + hex + "' digit " + indexSrc + " is not hexadecimal!");
			}
			result[indexDest] = (char) (digit << 4);
			++indexSrc;
			digit = Character.digit(hex.charAt(indexSrc), 16);
			if (digit < 0) {
				throw new IllegalArgumentException("'" + hex + "' digit " + indexSrc + " is not hexadecimal!");
			}
			result[indexDest] |= (char) digit;
			++indexSrc;
		}
		return result;
	}

	/**
	 * Byte array to hexadecimal string.
	 * 
	 * @param byteArray byte array to be converted to string
	 * @param max maximum bytes to be converted.
	 * @return hexadecimal string
	 */
	public static String byteArray2HexString(byte[] byteArray, int max) {

		if (byteArray != null && byteArray.length != 0) {
			if (max == 0 || max > byteArray.length) {
				max = byteArray.length;
			}
			StringBuilder builder = new StringBuilder(max * 3);
			for (int i = 0; i < max; i++) {
				builder.append(String.format("%02X", 0xFF & byteArray[i]));

				if (i < max - 1) {
					builder.append(' ');
				}
			}
			return builder.toString();
		} else {
			return "--";
		}
	}

	/**
	 * Truncate provided string.
	 * 
	 * @param text string to be truncated, if length is over the provided
	 *            maxLength
	 * @param maxLength maximum length of string. (0 doesn't truncate)
	 * @return truncated or original string
	 */
	public static String trunc(String text, int maxLength) {
		if (text != null && maxLength > 0 && maxLength < text.length()) {
			return text.substring(0, maxLength - 1);
		}
		return text;
	}

}
