/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - refactor existing PRF code from Handshaker
 *                                      into separate class
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.elements.util.StandardCharsets;
import org.eclipse.californium.scandium.util.ByteArrayUtils;

/**
 * The Pseudo Random Function as defined in TLS 1.2.
 * 
 * @see <a href="http://tools.ietf.org/html/rfc5246#section-5">RFC 5246</a>
 */
public final class PseudoRandomFunction {

	/**
	 * Test, if mac and hash is supported.
	 * 
	 * @param macName name of mac
	 * @param hashName name of hash
	 * @return {@code true}, if supported
	 */
	public final static boolean isSupported(String macName, String hashName) {
		try {
			Mac.getInstance(macName);
		} catch (NoSuchAlgorithmException e) {
			return false;
		}
		try {
			MessageDigest.getInstance(hashName);
		} catch (NoSuchAlgorithmException e) {
			return false;
		}
		return true;
	}

	private PseudoRandomFunction() {
	}

	public enum Label {

		// The master secret is always 48 bytes long, see
		// http://tools.ietf.org/html/rfc5246#section-8.1
		MASTER_SECRET_LABEL("master secret", 48),
		// The most key material required is 128 bytes, see
		// http://tools.ietf.org/html/rfc5246#section-6.3
		// (some cipher suites, not mentioned in rfc5246 requires more!)
		KEY_EXPANSION_LABEL("key expansion", 128),
		// The verify data is always 12 bytes long, see
		// http://tools.ietf.org/html/rfc5246#section-7.4.9
		CLIENT_FINISHED_LABEL("client finished", 12),
		// The verify data is always 12 bytes long, see
		// http://tools.ietf.org/html/rfc5246#section-7.4.9
		SERVER_FINISHED_LABEL("server finished", 12);

		private String value;
		private int length;

		private Label(String value, int length) {
			this.value = value;
			this.length = length;
		}

		public String value() {
			return value;
		}

		public byte[] getBytes() {
			return value.getBytes(StandardCharsets.UTF_8);
		}

		public int length() {
			return length;
		}
	}

	static byte[] doPRF(String algorithmMac, byte[] secret, byte[] label, byte[] seed, int length) {
		try {
			Mac hmac = Mac.getInstance(algorithmMac);
			hmac.init(new SecretKeySpec(secret, "MAC"));
			return doExpansion(hmac, ByteArrayUtils.concatenate(label, seed), length);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(String.format("MAC algorithm %s is not available on JVM", algorithmMac), e);
		} catch (InvalidKeyException e) {
			// according to http://www.ietf.org/rfc/rfc2104 (HMAC) section 3
			// keys can be of arbitrary length
			throw new IllegalArgumentException("Cannot run Pseudo Random Function with invalid key", e);
		}
		
	}

	/**
	 * Does the pseudo random function as defined in
	 * <a href="http://tools.ietf.org/html/rfc5246#section-5">RFC 5246</a>.
	 * 
	 * @param algorithmMac MAC algorithm name. e.g. "HmacSHA256"
	 * @param secret the secret to use for the secure hash function
	 * @param label the label to use for creating the original data. Uses the
	 *            length from the label.
	 * @param seed the seed to use for creating the original data
	 * @return the expanded data
	 */
	public static final byte[] doPRF(String algorithmMac, byte[] secret, Label label, byte[] seed) {
		return doPRF(algorithmMac, secret, label.getBytes(), seed, label.length());
	}

	/**
	 * Does the pseudo random function as defined in <a
	 * href="http://tools.ietf.org/html/rfc5246#section-5">RFC 5246</a>.
	 * 
	 * @param algorithmMac MAC algorithm name. e.g. "HmacSHA256"
	 * @param secret the secret to use for the secure hash function
	 * @param label the label to use for creating the original data
	 * @param seed the seed to use for creating the original data
	 * @param length the length of data to create
	 * @return the expanded data
	 */
	public static final byte[] doPRF(String algorithmMac, byte[] secret, Label label, byte[] seed, int length) {
		return doPRF(algorithmMac, secret, label.getBytes(), seed, length);
	}

	/**
	 * Performs the secret expansion as described in <a
	 * href="http://tools.ietf.org/html/rfc5246#section-5">RFC 5246</a>.
	 * 
	 * @param hmac the cryptographic hash function to use for expansion.
	 * @param data the data to expand.
	 * @param length the number of bytes to expand the data to.
	 * @return the expanded data.
	 */
	static final byte[] doExpansion(Mac hmac, byte[] data, int length) {
		/*
		 * RFC 5246, chapter 5, page 15
		 * 
		 * P_hash(secret, seed) = 
		 *    HMAC_hash(secret, A(1) + seed) +
		 *    HMAC_hash(secret, A(2) + seed) + 
		 *    HMAC_hash(secret, A(3) + seed) + ...
		 * where + indicates concatenation.
		 *  
		 * A() is defined as: 
		 *    A(0) = seed, 
		 *    A(i) = HMAC_hash(secret, A(i-1))
		 */

		int offset = 0;
		final int macLength = hmac.getMacLength();
		final byte[] aAndSeed = new byte[macLength + data.length];
		final byte[] expansion = new byte[length];
		try {
			// copy appended seed to buffer end
			System.arraycopy(data, 0, aAndSeed, macLength, data.length);
			// calculate A(n) from A(0)
			hmac.update(data);
			while (true) {
				// write result to "A(n) + seed"
				hmac.doFinal(aAndSeed, 0);
				// calculate HMAC_hash from "A(n) + seed"
				hmac.update(aAndSeed);
				final int nextOffset = offset + macLength;
				if (nextOffset > length) {
					// too large for expansion!
					// write HMAC_hash result temporary to "A(n) + seed"
					hmac.doFinal(aAndSeed, 0);
					// write head of result from temporary "A(n) + seed" to expansion
					System.arraycopy(aAndSeed, 0, expansion, offset, length - offset);
					break;
				} else {
					// write HMAC_hash result to expansion
					hmac.doFinal(expansion, offset);
					if (nextOffset == length) {
						break;
					}
				}
				offset = nextOffset;
				// calculate A(n+1) from "A(n) + seed" head ("A(n)")
				hmac.update(aAndSeed, 0, macLength);
			}
		} catch (ShortBufferException e) {
			e.printStackTrace();
		}
		return expansion;
	}
}
