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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.security.PublicKey;
import java.security.cert.Certificate;
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

	private static final Pattern IP_PATTERN = Pattern
			.compile("^(\\[[0-9a-fA-F:]+(%\\w+)?\\]|[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})$");

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
	 * @see #charArray2hex(char[])
	 * @see #byteArray2HexString(byte[], char, int)
	 */
	private final static char[] BIN_TO_HEX_ARRAY = "0123456789ABCDEF".toCharArray();

	/**
	 * Table with tabs for pretty printing.
	 * 
	 * @since 3.0
	 */
	private static final String[] TABS = new String[10];

	static {
		String tab = "";
		for (int i = 0; i < TABS.length; ++i) {
			TABS[i] = tab;
			tab += "\t";
		}
		boolean support = false;
		try {
			Method method = InetSocketAddress.class.getMethod("getHostString");
			support = method != null;
		} catch (NoSuchMethodException e) {
			// android before API 18
		}
		SUPPORT_HOST_STRING = support;
		String version = null;
		Package pack = StringUtil.class.getPackage();
		if (pack != null) {
			version = pack.getImplementationVersion();
			if ("0.0".equals(version)) {
				// that seems to be a dummy value used,
				// if the version is not available
				version = null;
			}
		}
		CALIFORNIUM_VERSION = version;
	}

	/**
	 * Get host string of inet socket address.
	 * 
	 * @param socketAddress inet socket address.
	 * @return host string
	 * @since 3.0 (changed scope to public)
	 */
	public static String toHostString(InetSocketAddress socketAddress) {
		if (SUPPORT_HOST_STRING) {
			return socketAddress.getHostString();
		} else {
			InetAddress address = socketAddress.getAddress();
			if (address != null) {
				String textAddress = address.toString();
				if (textAddress.startsWith("/")) {
					// unresolved, return literal IP
					return textAddress.substring(1);
				} else {
					// resolved, safe to call getHostName
					return address.getHostName();
				}
			} else {
				return socketAddress.getHostName();
			}
		}
	}

	/**
	 * Get indentation-prefix.
	 * 
	 * @param indentIndex indent
	 * @return indentation prefix.
	 * @since 3.0
	 */
	public static String indentation(int indentIndex) {
		if (indentIndex < 0) {
			return "";
		} else if (indentIndex >= TABS.length) {
			return TABS[TABS.length - 1];
		}
		return TABS[indentIndex];
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
	 * <b>Note:</b> Function will change with the next major release to throw an
	 * IllegalArgumentException instead of returning an empty array, if invalid
	 * characters are contained.
	 * 
	 * @param base64 base64 string
	 * @return byte array. empty, if provided string could not be decoded.
	 * @throws IllegalArgumentException if the length is invalid for base 64
	 * @see #base64ToByteArray(char[])
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
	 * Decode base 64 char array into byte array.
	 * 
	 * Alternative to {@link #base64ToByteArray(String)} for converting
	 * credentials. A char array could be cleared after usage, while a String
	 * may only get garbage collected. Add padding, if missing.
	 * 
	 * @param base64 base64 char array
	 * @return byte array.
	 * @throws IllegalArgumentException if the length is invalid for base 64 or
	 *             character is out of the supported character set of base 64.
	 * @since 3.3
	 */
	public static byte[] base64ToByteArray(char[] base64) {
		int pad = base64.length % 4;
		if (pad > 0) {
			pad = 4 - pad;
			if (pad != 1 && pad != 2) {
				throw new IllegalArgumentException("'" + new String(base64) + "' invalid base64!");
			}
		}
		int index = 0;
		byte[] data64 = new byte[base64.length + pad];
		for (; index < base64.length; ++index) {
			char b = base64[index];
			if (b > 127) {
				throw new IllegalArgumentException("'" + new String(base64) + "' has invalid base64 char '" + b + "'!");
			}
			data64[index] = (byte) b;
		}
		while (pad > 0) {
			--pad;
			data64[index++] = (byte) '=';
		}
		try {
			return Base64.decode(data64);
		} catch (IOException e) {
			throw new IllegalArgumentException(e.getMessage());
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
	 * Encode byte array into base64 char array.
	 * 
	 * @param bytes byte array
	 * @return base64 char array
	 * @since 3.3
	 */
	public static char[] byteArrayToBase64CharArray(byte[] bytes) {
		byte[] base64 = Base64.encodeBytesToBytes(bytes);
		char[] result = new char[base64.length];
		for (int index = 0; index < base64.length; ++index) {
			result[index] = (char) base64[index];
		}
		Bytes.clear(base64);
		return result;
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
	 * Remove tail from builder's.
	 * 
	 * If provided tail doesn't match, the provided builder is unchanged.
	 * 
	 * @param builder builder to remove tail
	 * @param tail tail to remove.
	 * @return {@code true}, if the provided tail has been removed,
	 *         {@code false}, if the build is left unchanged.
	 * @throws NullPointerException if one of the provided arguments is
	 *             {@code null}.
	 * @since 3.7
	 */
	public static boolean truncateTail(StringBuilder builder, String tail) {
		if (builder == null) {
			throw new NullPointerException("Builder must not be null!");
		}
		if (tail == null) {
			throw new NullPointerException("Tail must not be null!");
		}
		boolean truncated = false;
		int tailLength = tail.length();
		if (tailLength > 0) {
			int end = builder.length() - tailLength;
			if (end > 0) {
				truncated = true;
				for (int index = 0; index < tailLength; ++index) {
					if (builder.charAt(index + end) != tail.charAt(index)) {
						truncated = false;
						break;
					}
				}
				if (truncated) {
					builder.setLength(end);
				}
			}
		}
		return truncated;
	}

	/**
	 * Remove tail from text.
	 * 
	 * If provided tail doesn't match the tail of the text, the text is returned
	 * unchanged.
	 * 
	 * @param text text to remove tail
	 * @param tail tail to remove
	 * @return text with tail removed, if matching. Otherwise the provided text.
	 * @throws NullPointerException if one of the provided arguments is
	 *             {@code null}.
	 * @since 3.7
	 */
	public static String truncateTail(String text, String tail) {
		if (text == null) {
			throw new NullPointerException("Text must not be null!");
		}
		if (tail == null) {
			throw new NullPointerException("Tail must not be null!");
		}
		if (tail.length() > 0 && text.endsWith(tail)) {
			return text.substring(0, text.length() - tail.length());
		}
		return text;
	}

	/**
	 * Remove header from builder's.
	 * 
	 * If provided header doesn't match, the provided builder is unchanged.
	 * 
	 * @param builder builder to remove tail
	 * @param header header to remove.
	 * @return {@code true}, if the provided header has been removed,
	 *         {@code false}, if the build is left unchanged.
	 * @throws NullPointerException if one of the provided arguments is
	 *             {@code null}.
	 * @since 3.9
	 */
	public static boolean truncateHeader(StringBuilder builder, String header) {
		if (builder == null) {
			throw new NullPointerException("Builder must not be null!");
		}
		if (header == null) {
			throw new NullPointerException("Tail must not be null!");
		}
		boolean truncated = false;
		int headerLength = header.length();
		if (headerLength > 0 && headerLength <= builder.length()) {
			truncated = true;
			for (int index = 0; index < headerLength; ++index) {
				if (builder.charAt(index) != header.charAt(index)) {
					truncated = false;
					break;
				}
			}
			if (truncated) {
				builder.replace(0, headerLength, "");
			}
		}
		return truncated;
	}

	/**
	 * Remove header from text.
	 * 
	 * If provided header doesn't match the header of the text, the text is
	 * returned unchanged.
	 * 
	 * @param text text to remove tail
	 * @param header header to remove
	 * @return text with header removed, if matching. Otherwise the provided
	 *         text.
	 * @throws NullPointerException if one of the provided arguments is
	 *             {@code null}.
	 * @since 3.9
	 */
	public static String truncateHeader(String text, String header) {
		if (text == null) {
			throw new NullPointerException("Text must not be null!");
		}
		if (header == null) {
			throw new NullPointerException("Tail must not be null!");
		}
		if (header.length() > 0 && text.startsWith(header)) {
			return text.substring(header.length());
		}
		return text;
	}

	/**
	 * Convert UTF-8 data into display string.
	 * 
	 * If none-printable data is contained, the data is converted to a
	 * hexa-decimal string. If the UTF-8 string exceeds the limit, it's
	 * truncated and the length is appended. If a hexa-decimal string is
	 * returned and the data length exceeds the limit, the data is truncated and
	 * the length is appended.
	 * 
	 * @param data data to convert
	 * @param limit limit of result. Either limits the UTF-8 string, or the data
	 *            for the hexa-decimal string.
	 * @return display string
	 * @since 3.0
	 */
	public static String toDisplayString(byte[] data, int limit) {
		if (data == null) {
			return "<no data>";
		} else if (data.length == 0) {
			return "<empty data>";
		}
		if (data.length < limit) {
			limit = data.length;
		}
		boolean text = true;
		for (byte b : data) {
			if (' ' > b) {
				switch (b) {
				case '\t':
				case '\n':
				case '\r':
					continue;
				}
				text = false;
				break;
			}
		}
		if (text) {
			CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder();
			decoder.onMalformedInput(CodingErrorAction.REPORT);
			decoder.onUnmappableCharacter(CodingErrorAction.REPORT);
			ByteBuffer in = ByteBuffer.wrap(data);
			CharBuffer out = CharBuffer.allocate(limit);
			CoderResult result = decoder.decode(in, out, true);
			decoder.flush(out);
			((Buffer) out).flip();
			if (CoderResult.OVERFLOW == result) {
				return "\"" + out + "\".. " + data.length + " bytes";
			} else if (!result.isError()) {
				return "\"" + out + "\"";
			}
		}
		String hex = byteArray2HexString(data, ' ', limit);
		if (data.length > limit) {
			hex += ".." + data.length + " bytes";
		}
		return hex;
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
	 * <a href="https://tools.ietf.org/html/rfc1123" target="_blank">RFC
	 * 1123</a>.
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
	 * Checks if a given string is a literal IP address.
	 * 
	 * @param address address to check.
	 * @return {@code true} if the address is a literal IP address.
	 * @since 3.0
	 */
	public static boolean isLiteralIpAddress(final String address) {
		if (address == null) {
			return false;
		} else {
			return IP_PATTERN.matcher(address).matches();
		}
	}

	/**
	 * Get URI hostname from address.
	 * 
	 * Apply workaround for JDK-8199396.
	 * 
	 * Note: since 3.0, a "%" in a IPv6 address is replaced by the encoded form
	 * with "%25".
	 * 
	 * @param address address
	 * @return uri hostname
	 * @throws NullPointerException if address is {@code null}.
	 * @throws URISyntaxException if address could not be converted into URI
	 *             hostname.
	 * @since 2.1
	 */
	public static String getUriHostname(InetAddress address) throws URISyntaxException {
		if (address == null) {
			throw new NullPointerException("address must not be null!");
		}
		String host = address.getHostAddress();
		if (address instanceof Inet6Address) {
			Inet6Address address6 = (Inet6Address) address;
			if (address6.getScopedInterface() != null || address6.getScopeId() > 0) {
				int pos = host.indexOf('%');
				if (pos > 0 && pos + 1 < host.length()) {
					String separator = "%25";
					String scope = host.substring(pos + 1);
					String hostAddress = host.substring(0, pos);
					host = hostAddress + separator + scope;
					try {
						new URI(null, null, host, -1, null, null, null);
					} catch (URISyntaxException e) {
						// work-around for openjdk bug JDK-8199396.
						// some characters are not supported for the ipv6 scope.
						scope = scope.replaceAll("[-._~]", "");
						if (scope.isEmpty()) {
							host = hostAddress;
						} else {
							host = hostAddress + separator + scope;
							try {
								new URI(null, null, host, -1, null, null, null);
							} catch (URISyntaxException e2) {
								throw e;
							}
						}
					}
				}
			}
		}
		return host;
	}

	/**
	 * Normalize logging tag.
	 * 
	 * The normalized tag is either a empty string {@code ""}, or terminated by
	 * a space {@code ' '}.
	 * 
	 * @param tag tag to be normalized. {@code null} will be normalized to a
	 *            empty string {@code ""}.
	 * @return normalized tag. Either a empty string {@code ""}, or terminated
	 *         by a space {@code ' '}
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
	 * Get display text for Certificate.
	 * 
	 * @param cert certificate
	 * @return display text
	 * @since 3.0
	 */
	public static String toDisplayString(Certificate cert) {
		int indentIndex = 0;
		String[] lines = cert.toString().split("\n");
		StringBuilder text = new StringBuilder();
		for (String line : lines) {
			line = line.trim();
			if (!line.isEmpty()) {
				int indent = indentDelta(line);
				if (indent < 0 && line.length() == 1) {
					indentIndex += indent;
					indent = 0;
				}
				text.append(indentation(indentIndex)).append(line).append("\n");
				indentIndex += indent;
			} else {
				text.append("\n");
			}
		}
		return text.toString();
	}

	/**
	 * Get indent delta for provided lines.
	 * 
	 * Counts {@code '['} (+1) and {@code ']'} (-1).
	 * 
	 * @param line line
	 * @return indent change.
	 * @since 3.0
	 */
	private static int indentDelta(String line) {
		int index = 0;
		for (int i = line.length(); i > 0;) {
			--i;
			char c = line.charAt(i);
			if (c == '[') {
				++index;
			} else if (c == ']') {
				--index;
			}
		}
		if (index != 0 && line.matches("\\d+:\\s+.*")) {
			// escape hex-dumps
			return 0;
		}
		return index;
	}

	/**
	 * Get display text for public key.
	 * 
	 * @param publicKey public key
	 * @return display text
	 * @since 3.0
	 */
	public static String toDisplayString(PublicKey publicKey) {
		return publicKey.toString().replaceAll("\n\\s+", "\n");
	}

	/**
	 * Checks, whether the set contains the value, or not.
	 * 
	 * The check is done using {@link String#equalsIgnoreCase(String)}.
	 * 
	 * @param set set of strings
	 * @param value value to match
	 * @return {@code true}, if value is contained in set, {@code false},
	 *         otherwise.
	 * @since 3.3
	 */
	public static boolean containsIgnoreCase(String[] set, String value) {
		for (String item : set) {
			if (item.equalsIgnoreCase(value)) {
				return true;
			}
		}
		return false;
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
			String property = System.getProperty(name);
			if (property != null) {
				value = property;
			}
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

	/**
	 * Read file.
	 * 
	 * @param file file to read
	 * @param defaultText default text
	 * @return text contained in file, or defaultText, if file could not be
	 *         read.
	 * @since 3.0
	 */
	public static String readFile(File file, String defaultText) {
		String content = defaultText;
		if (file.canRead()) {
			try (FileReader reader = new FileReader(file)) {
				BufferedReader lineReader = new BufferedReader(reader);
				content = lineReader.readLine();
				lineReader.close();
			} catch (FileNotFoundException e) {
			} catch (IOException e) {
			}
		}
		return content;
	}
}
