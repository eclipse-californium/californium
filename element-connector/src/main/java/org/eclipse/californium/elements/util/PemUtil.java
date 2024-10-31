/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.elements.util;

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Base64.Encoder;

/**
 * PEM utility.
 * 
 * @since 4.0
 */
public class PemUtil {

	/**
	 * Write data in base 64.
	 * 
	 * @param tag tag to use in PEM
	 * @param data data to write
	 * @param writer writer to write data to
	 * @throws IOException if an i/o error occurred
	 */
	public static void write(String tag, byte[] data, Writer writer) throws IOException {
		writer.write("-----BEGIN ");
		writer.write(tag);
		writer.write("-----");
		writer.write(StringUtil.lineSeparator());
		Encoder mimeEncoder = Base64.getMimeEncoder(64, StringUtil.lineSeparator().getBytes(StandardCharsets.UTF_8));
		writer.write(mimeEncoder.encodeToString(data));
		writer.write(StringUtil.lineSeparator());
		writer.write("-----END ");
		writer.write(tag);
		writer.write("-----");
		writer.write(StringUtil.lineSeparator());
	}
}
