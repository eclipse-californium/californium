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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - logging improvements
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;

/**
 * An identifier for the compression algorithms defined by the IANA to be used
 * with DTLS.
 * <p>
 * Instances of this enumeration do not implement any compression functionality.
 * They merely serve as an object representation of the identifiers defined
 * in <a href="http://tools.ietf.org/html/rfc3749">Transport Layer Security
 * Protocol Compression Methods</a>.
 * <p>
 * Note that only the {@link #NULL} compression method is supported at the
 * moment.
 */
public enum CompressionMethod {
	NULL(0x00),
	DEFLATE(0x01);

	// DTLS-specific constants ////////////////////////////////////////

	public static final int COMPRESSION_METHOD_BITS = 8;

	// Logging ////////////////////////////////////////////////////////

	private static final Logger LOGGER = Logger.getLogger(CompressionMethod.class.getCanonicalName());

	// Members ////////////////////////////////////////////////////////

	private int code;
	
	// Constructor ////////////////////////////////////////////////////

	private CompressionMethod(int code) {
		this.code = code;
	}
	
	// Methods ////////////////////////////////////////////////////////

	public int getCode() {
		return code;
	}

	public static CompressionMethod getMethodByCode(int code) {
		switch (code) {
		case 0x00:
			return CompressionMethod.NULL;
		case 0x01:
			return CompressionMethod.DEFLATE;

		default:
			LOGGER.log(Level.FINER, "Unknown compression method code: {0}", code);
			return null;
		}
	}

	// Serialization //////////////////////////////////////////////////

	/**
	 * Takes a list of compression methods and creates the representing byte
	 * stream.
	 * 
	 * @param compressionMethods
	 *            the list of the compression methods
	 * @return the corresponding byte array
	 */
	public static byte[] listToByteArray(List<CompressionMethod> compressionMethods) {

		DatagramWriter writer = new DatagramWriter();
		for (CompressionMethod compressionMethod : compressionMethods) {
			writer.write(compressionMethod.getCode(), COMPRESSION_METHOD_BITS);
		}

		return writer.toByteArray();
	}

	/**
	 * Takes a byte array and creates the representing list of compression
	 * methods.
	 * 
	 * @param byteArray
	 *            the encoded compression methods as byte array
	 * @param numElements
	 *            the number of compression methods represented in the byte
	 *            array
	 * @return corresponding list of compression methods
	 */
	public static List<CompressionMethod> listFromByteArray(byte[] byteArray, int numElements) {
		List<CompressionMethod> compressionMethods = new ArrayList<CompressionMethod>();
		DatagramReader reader = new DatagramReader(byteArray);

		for (int i = 0; i < numElements; i++) {
			int code = reader.read(COMPRESSION_METHOD_BITS);
			CompressionMethod method = CompressionMethod.getMethodByCode(code);
			if (method != null) {
				compressionMethods.add(method);
			}
		}
		return compressionMethods;
	}
}
