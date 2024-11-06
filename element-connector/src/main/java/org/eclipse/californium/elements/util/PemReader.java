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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reader for PEM files.
 * 
 * @since 2.0
 */
public class PemReader {

	/**
	 * The logger.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(PemReader.class);

	/**
	 * Pattern for begin tag.
	 */
	private static final Pattern BEGIN_PATTERN = Pattern.compile("^\\-+BEGIN\\s+([\\w\\s]+)\\-+$");

	/**
	 * Pattern for end tag.
	 */
	private static final Pattern END_PATTERN = Pattern.compile("^\\-+END\\s+([\\w\\s]+)\\-+$");

	/**
	 * Buffered reader.
	 */
	private BufferedReader reader;
	/**
	 * Current tag.
	 * 
	 * Set by {@link #readNextBegin()}.
	 */
	private String tag;

	private int lines;

	/**
	 * Create PEM reader from {@link InputStream}.
	 * 
	 * @param in input stream
	 */
	public PemReader(InputStream in) {
		reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
	}

	/**
	 * Create PEM reader from {@link Reader}.
	 * 
	 * @param in reader
	 * @since 3.12
	 */
	public PemReader(Reader in) {
		reader = new BufferedReader(in);
	}

	/**
	 * Create PEM reader from {@link BufferedReader}.
	 * 
	 * @param in buffered reader
	 * @since 4.0
	 */
	public PemReader(BufferedReader in) {
		reader = in;
	}

	/**
	 * Close reader.
	 */
	public void close() {
		try {
			reader.close();
		} catch (IOException e) {
		}
	}

	/**
	 * Read to next begin pattern.
	 * 
	 * @return begin tag
	 * @throws IOException if an i/o error occurred
	 */
	public String readNextBegin() throws IOException {
		String line;
		tag = null;
		while ((line = reader.readLine()) != null) {
			++lines;
			Matcher matcher = BEGIN_PATTERN.matcher(line);
			if (matcher.matches()) {
				tag = matcher.group(1);
				LOGGER.debug("Found Begin of {}", tag);
				break;
			}
		}
		return tag;
	}

	/**
	 * Read to end pattern.
	 * 
	 * @return bytes of read section. {@code null}, if end pattern not found.
	 * @throws IOException if an i/o error occurred
	 */
	public byte[] readToEnd() throws IOException {
		String line;
		StringBuilder buffer = new StringBuilder();

		while ((line = reader.readLine()) != null) {
			++lines;
			Matcher matcher = END_PATTERN.matcher(line);
			if (matcher.matches()) {
				String end = matcher.group(1);
				if (end.equals(tag)) {
					byte[] decode = StringUtil.base64ToByteArray(buffer.toString());
					LOGGER.debug("Found End of {}", tag);
					return decode;
				} else {
					LOGGER.warn("Found End of {}, but expected {}!", end, tag);
					break;
				}
			}
			buffer.append(line);
		}
		tag = null;
		return null;
	}

	/**
	 * Get number of lines since last call of this function.
	 * 
	 * @return number of lines
	 * @since 4.0
	 */
	public int lines() {
		int lines = this.lines;
		this.lines = 0;
		return lines;
	}
}
