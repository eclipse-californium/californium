/*******************************************************************************
 * Copyright (c) 2017, 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - add host name validator
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.regex.Pattern;

/**
 * String utility (as there are so many already out).
 */
public class StringUtil {

	/**
	 * Special character to signal, that no separator should be used when byte
	 * array are converted to hexadecimal strings.
	 * 
	 * @see #byteArray2HexString(byte[], char, int)
	 */
	public static final char NO_SEPARATOR = 0;

	/**
	 * Regex pattern for valid hostnames.
	 */
	private static final Pattern HOSTNAME_PATTERN = Pattern.compile(
			"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$");

	/**
	 * Workaround too support android API 16-18.
	 * 
	 * @see #lineSeparator()
	 */
	public static final String lineSeparator = System.getProperty("line.separator");

	/**
	 * Flag indicating, that InetSocketAddress supports "getHostString".
	 */
	public static final boolean SUPPORT_HOST_STRING;

	/**
	 * Lookup table for hexadecimal digits.
	 * 
	 * @see #toHexString(byte[])
	 */
	private final static char[] BIN_TO_HEX_ARRAY = "0123456789ABCDEF".toCharArray();

	static {
		boolean support = false;
		try {
			Method method = InetSocketAddress.class.getMethod("getHostString");
			support = method != null;
		} catch (NoSuchMethodException e) {
			// android before API 18
		}
		SUPPORT_HOST_STRING = support;
	}

	@NotForAndroid
	private static String toHostString(InetSocketAddress address) {
		return address.getHostString();
	}

	/**
	 * Return line separator.
	 * 
	 * @return line separator
	 * @see #lineSeparator
	 */
	public static String lineSeparator() {
		return lineSeparator;
	}

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
	 * Convert hexadecimal String into decoded byte array.
	 * 
	 * @param hex hexadecimal string. e.g. "4130010A"
	 * @return byte array with decoded hexadecimal input parameter.
	 * @throws IllegalArgumentException if the parameter length is odd or
	 *             contains non hexadecimal characters.
	 * @see #byteArray2Hex(byte[])
	 */
	public static byte[] hex2ByteArray(String hex) {
		if (hex == null) {
			return null;
		}
		int length = hex.length();
		if ((1 & length) != 0) {
			throw new IllegalArgumentException("'" + hex + "' has odd length!");
		}
		length /= 2;
		byte[] result = new byte[length];
		for (int indexDest = 0, indexSrc = 0; indexDest < length; ++indexDest) {
			int digit = Character.digit(hex.charAt(indexSrc), 16);
			if (digit < 0) {
				throw new IllegalArgumentException("'" + hex + "' digit " + indexSrc + " is not hexadecimal!");
			}
			result[indexDest] = (byte) (digit << 4);
			++indexSrc;
			digit = Character.digit(hex.charAt(indexSrc), 16);
			if (digit < 0) {
				throw new IllegalArgumentException("'" + hex + "' digit " + indexSrc + " is not hexadecimal!");
			}
			result[indexDest] |= (byte) digit;
			++indexSrc;
		}
		return result;
	}

	/**
	 * Byte array to hexadecimal string without separator.
	 * 
	 * @param byteArray byte array to be converted to string.
	 * @return hexadecimal string, e.g "0142A3". {@code null}, if the provided
	 *         byte array is {@code null}. {@code ""}, if provided byte array is
	 *         empty.
	 * @see #hex2ByteArray(String)
	 */
	public static String byteArray2Hex(byte[] byteArray) {
		if (byteArray == null) {
			return null;
		} else if (byteArray.length == 0) {
			return "";
		} else {
			return byteArray2HexString(byteArray, NO_SEPARATOR, 0);
		}
	}

	/**
	 * Byte array to hexadecimal display string.
	 * 
	 * All bytes are converted without separator.
	 * 
	 * @param byteArray byte array to be converted to string
	 * @return hexadecimal string, e.g "0145A4", "--", if byte array is
	 *         {@code null} or empty.
	 */
	public static String byteArray2HexString(byte[] byteArray) {
		return byteArray2HexString(byteArray, NO_SEPARATOR, 0);
	}

	/**
	 * Byte array to hexadecimal display string.
	 * 
	 * @param byteArray byte array to be converted to string
	 * @param sep separator. If {@link #NO_SEPARATOR}, then no separator is used
	 *            between the bytes.
	 * @param max maximum bytes to be converted. 0 to convert all bytes.
	 * @return hexadecimal string, e.g "01:45:A4", if ':' is used as separator.
	 *         "--", if byte array is {@code null} or empty.
	 */
	public static String byteArray2HexString(byte[] byteArray, char sep, int max) {

		if (byteArray != null && byteArray.length != 0) {
			if (max == 0 || max > byteArray.length) {
				max = byteArray.length;
			}
			StringBuilder builder = new StringBuilder(max * (sep == NO_SEPARATOR ? 2 : 3));
			for (int index = 0; index < max; index++) {
				int value = byteArray[index] & 0xFF;
				builder.append(BIN_TO_HEX_ARRAY[value >>> 4]);
				builder.append(BIN_TO_HEX_ARRAY[value & 0x0F]);
				if (sep != NO_SEPARATOR && index < max - 1) {
					builder.append(sep);
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
			return text.substring(0, maxLength);
		}
		return text;
	}

	/**
	 * Get address as string for logging.
	 * 
	 * @param address address to be converted to string
	 * @return the host address, or {@code null}, if address is {@code null}.
	 */
	public static String toString(InetAddress address) {
		if (address == null) {
			return null;
		}
		return address.getHostAddress();
	}

	/**
	 * Get socket address as string for logging.
	 * 
	 * @param address socket address to be converted to string
	 * @return the host string, if available, otherwise the host address, both
	 *         appended with ":" and the port. Or {@code null}, if address is
	 *         {@code null}.
	 */
	public static String toString(InetSocketAddress address) {
		if (address == null) {
			return null;
		}
		String host;
		if (SUPPORT_HOST_STRING) {
			host = toHostString(address);
		} else {
			host = toString(address.getAddress());
		}
		return host + ":" + address.getPort();
	}

	/**
	 * Checks if a given string is a valid host name as defined by
	 * <a href="http://tools.ietf.org/html/rfc1123">RFC 1123</a>.
	 * 
	 * @param name The name to check.
	 * @return {@code true} if the name is a valid host name.
	 */
	public static boolean isValidHostName(final String name) {
		if (name == null) {
			return false;
		} else {
			return HOSTNAME_PATTERN.matcher(name).matches();
		}
	}
}

