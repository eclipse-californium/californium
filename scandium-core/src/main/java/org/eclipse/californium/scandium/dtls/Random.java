/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Date;

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.cipher.RandomManager;

/**
 * A 32-byte value provided by the client and the server in the
 * {@link ClientHello} respectively in the {@link ServerHello} used later in the
 * protocol to compute the premaster secret. See <a
 * href="https://tools.ietf.org/html/rfc5246#appendix-A.4.1" target="_blank">RFC 5246</a> for the
 * message format.
 */
public class Random extends Bytes {

	public Random() {
		this(createBytes());
	}

	/**
	 * Sets the random bytes explicitly.
	 * 
	 * @param randomBytes the bytes to use
	 * @throws NullPointerException if the given array is {@code null}
	 * @throws IllegalArgumentException if the given array's length is not 32
	 */
	public Random(byte[] randomBytes) {
		super(randomBytes);
		if (randomBytes.length != 32) {
			throw new IllegalArgumentException("Random bytes array's length must be 32");
		}
	}

	public String toString(int indent) {
		StringBuilder sb = new StringBuilder();
		byte[] randomBytes = getBytes();
		// get the UNIX timestamp from the first 4 bytes
		byte b0 = randomBytes[0];
		byte b1 = randomBytes[1];
		byte b2 = randomBytes[2];
		byte b3 = randomBytes[3];
		
		long gmtUnixTime = ((0xFF & b0) << 24) | ((0xFF & b1) << 16) | ((0xFF & b2) << 8) | (0xFF & b3);

		Date date = new Date(gmtUnixTime * 1000L);

		String indentation = StringUtil.indentation(indent);

		sb.append(indentation).append("GMT Unix Time: ").append(date).append(StringUtil.lineSeparator());

		// output the remaining 28 random bytes
		byte[] rand = Arrays.copyOfRange(randomBytes, 4, 32);
		sb.append(indentation).append("Random Bytes: ").append(StringUtil.byteArray2Hex(rand)).append(StringUtil.lineSeparator());

		return sb.toString();
	}

	@Override
	public String toString() {
		return toString(0);
	}

	/**
	 * Create byte array of 32 bytes initialized with random bytes and time
	 * stamp in the first 4 bytes.
	 * 
	 * @return byte array initialized with random bytes
	 * @see SecureRandom#nextBytes(byte[])
	 */
	public static byte[] createBytes() {

		byte[] randomBytes = Bytes.createBytes(RandomManager.currentSecureRandom(), 32);

		// overwrite the first 4 bytes with the UNIX time
		int gmtUnixTime = (int) (System.currentTimeMillis() / 1000);
		randomBytes[0] = (byte) (gmtUnixTime >> 24);
		randomBytes[1] = (byte) (gmtUnixTime >> 16);
		randomBytes[2] = (byte) (gmtUnixTime >> 8);
		randomBytes[3] = (byte) gmtUnixTime;
		return randomBytes;
	}
}
