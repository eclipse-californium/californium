/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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
package org.eclipse.californium.scandium.dtls;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.californium.scandium.util.DatagramReader;
import org.eclipse.californium.scandium.util.DatagramWriter;


/**
 * The algorithm used to compress data prior to encryption.
 */
public enum CompressionMethod {
	NULL(0x00);
	
	// DTLS-specific constants ////////////////////////////////////////

	private static final int COMPRESSION_METHOD_BITS = 8;
	
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

		default:
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
			compressionMethods.add(CompressionMethod.getMethodByCode(code));
		}
		return compressionMethods;
	}

}
