/*******************************************************************************
 * Copyright (c) 2017, 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add byteArray2HexString
 *                                                    and trunc
 *    Bosch Software Innovations GmbH - add host name validator
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
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
	 * Californium version. {@code null}, if not available.
	 * 
	 * @since 2.2
	 */
	public static final String CALIFORNIUM_VERSION;

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
		CALIFORNIUM_VERSION = StringUtil.class.getPackage().getImplementationVersion();
	}

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
	 * Character array to hexadecimal string.
	 * 
	 * @param charArray character array.
	 * @return hexadecimal string, or {@code null}, if provided character array
	 *         is {@code null}.
	 * @since 2.4
	 */
	public static String charArray2hex(char[] charArray) {
		if (charArray != null) {
			int length = charArray.length;
			StringBuilder builder = new StringBuilder(length * 2);
			for (int index = 0; index < length; index++) {
				int value = charArray[index] & 0xFF;
				builder.append(BIN_TO_HEX_ARRAY[value >>> 4]);
				builder.append(BIN_TO_HEX_ARRAY[value & 0x0F]);
			}
			return builder.toString();
		} else {
			return null;
		}
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
	 * Decode base 64 string into byte array.
	 * 
	 * Add padding, if missing.
	 * 
	 * @param base64 base64 string
	 * @return byte array.
	 * @since 2.3
	 */
	public static byte[] base64ToByteArray(String base64) {
		int pad = base64.length() % 4;
		if (pad > 0) {
			pad = 4 - pad;
			if (pad == 1) {
				base64 += "=";
			} else if (pad == 2) {
				base64 += "==";
			} else {
				throw new IllegalArgumentException("'" + base64 + "' invalid base64!");
			}
		}
		try {
			return Base64.decode(base64);
		} catch (IOException e) {
			return Bytes.EMPTY;
		}
	}

	/**
	 * Encode byte array into base64 string.
	 * 
	 * @param bytes byte array
	 * @return base64 string
	 * @since 2.3
	 */
	public static String byteArrayToBase64(byte[] bytes) {
		return Base64.encodeBytes(bytes);
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
			InetAddress addr = address.getAddress();
			if (addr != null) {
				host = toString(addr);
			} else {
				host = "<unresolved>";
			}
		}
		if (address.getAddress() instanceof Inet6Address) {
			return "[" + host + "]:" + address.getPort();
		} else {
			return host + ":" + address.getPort();
		}
	}

	/**
	 * Get socket address as string for logging.
	 * 
	 * @param address socket address to be converted to string
	 * @return the socket address as string, or {@code null}, if address is
	 *         {@code null}.
	 * @see #toString(InetSocketAddress)
	 * @since 2.6
	 */
	public static String toString(SocketAddress address) {
		if (address == null) {
			return null;
		}
		if (address instanceof InetSocketAddress) {
			return toString((InetSocketAddress) address);
		}
		return address.toString();
	}

	/**
	 * Get socket address as string for logging.
	 * 
	 * @param address socket address to be converted to string
	 * @return the host string, if available, separated by "/", appended by the
	 *         host address, ":" and the port. For "any addresses", "port #port"
	 *         is returned. And {@code null}, if address is {@code null}.
	 * @since 2.1
	 * @since 2.4 special return value for "any addresses"
	 */
	public static String toDisplayString(InetSocketAddress address) {
		if (address == null) {
			return null;
		}
		InetAddress addr = address.getAddress();
		if (addr != null && addr.isAnyLocalAddress()) {
			return "port " + address.getPort();
		}
		String name = SUPPORT_HOST_STRING ? toHostString(address) : "";
		String host = (addr != null) ? toString(addr) : "<unresolved>";
		if (name.equals(host)) {
			name = "";
		} else {
			name += "/";
		}
		if (address.getAddress() instanceof Inet6Address) {
			return name + "[" + host + "]:" + address.getPort();
		} else {
			return name + host + ":" + address.getPort();
		}
	}

	/**
	 * Returns a "lazy message supplier" for socket addresses.
	 * 
	 * Converts the provided socket address into a display string on calling
	 * {@link Object#toString()} on the returned object. Emulates the
	 * {@code MessageSupplier} idea of log4j.
	 * 
	 * @param address address to log.
	 * @return "lazy message supplier".
	 * @see #toDisplayString(InetSocketAddress)
	 * @since 3.0
	 */
	public static Object toLog(final SocketAddress address) {
		if (address == null) {
			return null;
		}
		return new Object() {

			public String toString() {
				if (address instanceof InetSocketAddress) {
					return toDisplayString((InetSocketAddress) address);
				} else {
					return address.toString();
				}
			}
		};
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

	/**
	 * Get URI hostname from address.
	 * 
	 * Apply workaround for JDK-8199396.
	 * 
	 * @param address address
	 * @return uri hostname
	 * @throws NullPointerException if address is {@code null}.
	 * @throws URISyntaxException if address could not be converted into
	 *             URI hostname.
	 * @since 2.1
	 */
	public static String getUriHostname(InetAddress address) throws URISyntaxException {
		if (address == null) {
			throw new NullPointerException("address must not be null!");
		}
		String host = address.getHostAddress();
		try {
			new URI(null, null, host, -1, null, null, null);
		} catch (URISyntaxException e) {
			try {
				// work-around for openjdk bug JDK-8199396.
				// some characters are not supported for the ipv6 scope.
				host = host.replaceAll("[-._~]", "");
				new URI(null, null, host, -1, null, null, null);
			} catch (URISyntaxException e2) {
				// throw first exception before work-around
				throw e;
			}
		}
		return host;
	}

	/**
	 * Normalize logging tag.
	 * 
	 * The normalized tag is either a empty string {@code ""}, or terminated by a
	 * space {@code ' '}.
	 * 
	 * @param tag tag to be normalized. {@code null} will be normalized to a
	 *            empty string {@code ""}.
	 * @return normalized tag. Either a empty string {@code ""}, or terminated by
	 *         a space {@code ' '}
	 */
	public static String normalizeLoggingTag(String tag) {
		if (tag == null) {
			tag = "";
		} else if (!tag.isEmpty() && !tag.endsWith(" ")) {
			tag += " ";
		}
		return tag;
	}

	/**
	 * Get configuration value.
	 * 
	 * Try first {@link System#getenv(String)}, if that returns {@code null} or
	 * an empty value, then return {@link System#getProperty(String)}.
	 * 
	 * @param name the name of the configuration value.
	 * @return the value, or {@code null}, if neither
	 *         {@link System#getenv(String)} nor
	 *         {@link System#getProperty(String)} returns a value.
	 * @since 2.2
	 */
	public static String getConfiguration(String name) {
		String value = System.getenv(name);
		if (value == null || value.isEmpty()) {
			value = System.getProperty(name);
		}
		return value;
	}

	/**
	 * Get long configuration value.
	 * 
	 * Try first {@link System#getenv(String)}, if that returns {@code null} or
	 * an empty value, then return {@link System#getProperty(String)} as long.
	 * 
	 * @param name the name of the configuration value.
	 * @return the long value, or {@code null}, if neither
	 *         {@link System#getenv(String)} nor
	 *         {@link System#getProperty(String)} returns a value.
	 * @see #getConfiguration(String)
	 * @since 2.3
	 */
	public static Long getConfigurationLong(String name) {
		String value = getConfiguration(name);
		if (value != null && !value.isEmpty()) {
			try {
				return Long.valueOf(value);
			} catch (NumberFormatException e) {
			}
		}
		return null;
	}

	/**
	 * Get boolean configuration value.
	 * 
	 * Try first {@link System#getenv(String)}, if that returns {@code null} or
	 * an empty value, then return {@link System#getProperty(String)} as
	 * Boolean.
	 * 
	 * Since 3.0, return type changed from {@code boolean} to {@code Boolean}.
	 * 
	 * @param name the name of the configuration value.
	 * @return the boolean value, or {@code null}, if neither
	 *         {@link System#getenv(String)} nor
	 *         {@link System#getProperty(String)} returns a value.
	 * @see #getConfiguration(String)
	 * @since 2.4
	 */
	public static Boolean getConfigurationBoolean(String name) {
		String value = getConfiguration(name);
		if (value != null && !value.isEmpty()) {
			return Boolean.valueOf(value);
		}
		return null;
	}
}
