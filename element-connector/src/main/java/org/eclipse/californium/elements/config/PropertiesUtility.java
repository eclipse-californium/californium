/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.config;

import org.eclipse.californium.elements.util.StringUtil;

/**
 * Encoding for java properties file.
 * 
 * @since 3.0
 */
public class PropertiesUtility {

	private static final String QUOTED = "=:#!\\";
	private static final String SUBSTITUDED = "\t\n\r\f";
	private static final String SUBSTITUDES = "tnrf";

	/**
	 * A table of hex digits.
	 * 
	 * @see #appendUnicode(char, StringBuilder)
	 */
	private static final char[] HEX_DIGIT = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E',
			'F' };

	/**
	 * Normalize string value for properties files.
	 * 
	 * @param value string value
	 * @param escapeSpace {@code true}, to escape spaces' {@code ' '} by
	 *            {@code "\\ "}, {@code false}, to keep them.
	 * @return normalized string
	 */
	public static String normalize(String value, boolean escapeSpace) {

		int length = value.length();
		StringBuilder builder = new StringBuilder(length);

		for (int index = 0; index < length; index++) {
			char aChar = value.charAt(index);
			if ((aChar == ' ' && escapeSpace) || QUOTED.indexOf(aChar) >= 0) {
				builder.append('\\');
				builder.append(aChar);
				continue;
			}
			int substituteIndex = SUBSTITUDED.indexOf(aChar);
			if (substituteIndex >= 0) {
				builder.append('\\');
				builder.append(SUBSTITUDES.charAt(substituteIndex));
				continue;
			}
			if ((aChar < 32) || (aChar >= 128)) {
				appendUnicode(aChar, builder);
			} else {
				builder.append(aChar);
			}
		}

		return builder.toString();
	}

	/**
	 * Normalize comments for properties files.
	 * 
	 * Append "# " and split lines on whitespace, if they exceed 64 bytes.
	 * 
	 * @param comments normalized comments.
	 * @return normalized comment
	 */
	public static String normalizeComments(String comments) {
		if (comments == null) {
			return "#";
		}
		int length = comments.length();
		boolean eol = false;
		StringBuilder builder = new StringBuilder(length + 1);
		builder.append('#');
		builder.append(' ');
		int lineLength = 0;
		for (int index = 0; index < length; index++) {
			char aChar = comments.charAt(index);
			if (aChar == '\r' && index + 1 < length) {
				char nextChar = comments.charAt(index + 1);
				if (nextChar == '\n') {
					++index;
					aChar = nextChar;
				}
			}
			if (aChar == '\n' || aChar == '\r' || (lineLength > 64 && Character.isWhitespace(aChar))) {
				lineLength = 0;
				builder.append(StringUtil.lineSeparator());
				eol = true;
			} else {
				if (eol) {
					if (aChar != '#' && aChar != '!') {
						builder.append('#');
						builder.append(' ');
					}
					eol = false;
				}
				if ((aChar < 32) || (aChar >= 128)) {
					lineLength += 6;
					appendUnicode(aChar, builder);
				} else {
					++lineLength;
					builder.append(aChar);
				}
			}
		}

		return builder.toString();
	}

	/**
	 * Append character encoded using a hexadecimal unicode.
	 * 
	 * Format: {@code \\uhhhh}
	 * 
	 * @param c character to encode
	 * @param builder builder to append the character encoded as unicode.
	 */
	public static void appendUnicode(char c, StringBuilder builder) {
		builder.append('\\').append('u');
		builder.append(HEX_DIGIT[(c >> 12) & 0xf]);
		builder.append(HEX_DIGIT[(c >> 8) & 0xf]);
		builder.append(HEX_DIGIT[(c >> 4) & 0xf]);
		builder.append(HEX_DIGIT[c & 0xf]);
	}

}
