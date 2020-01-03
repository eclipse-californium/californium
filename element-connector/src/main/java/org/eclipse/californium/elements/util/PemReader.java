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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PemReader {
	public static final Logger LOGGER = LoggerFactory.getLogger(PemReader.class);

	private static final Pattern BEGIN_PATTERN = Pattern.compile("^\\-+BEGIN\\s+([\\w\\s]+)\\-+$");

	private static final Pattern END_PATTERN = Pattern.compile("^\\-+END\\s+([\\w\\s]+)\\-+$");

	private BufferedReader reader;
	private String tag;

	public PemReader(InputStream in) {
		reader = new BufferedReader(new InputStreamReader(in));
	}

	public void close() {
		try {
			reader.close();
		} catch (IOException e) {
		}
	}

	public String readNextBegin() throws IOException {
		String line;
		tag = null;
		while ((line = reader.readLine()) != null) {
			Matcher matcher = BEGIN_PATTERN.matcher(line);
			if (matcher.matches()) {
				tag = matcher.group(1);
				LOGGER.debug("Found Begin of {}", tag);
				break;
			}
		}
		return tag;
	}

	public byte[] readToEnd() throws IOException {
		String line;
		StringBuilder buffer = new StringBuilder();

		while ((line = reader.readLine()) != null) {
			Matcher matcher = END_PATTERN.matcher(line);
			if (matcher.matches()) {
				String end = matcher.group(1);
				if (end.equals(tag)) {
					byte[] decode = Base64.decode(buffer.toString());
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
}
