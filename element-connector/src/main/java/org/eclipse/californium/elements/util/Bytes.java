/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial API and implementation
 *******************************************************************************/
package org.eclipse.californium.elements.util;

import java.util.Arrays;
import java.util.Random;

/**
 * Byte array as key.
 */
public class Bytes {

	/**
	 * Empty byte array.
	 */
	public static final byte[] EMPTY = new byte[0];
	/**
	 * bytes.
	 */
	private final byte[] bytes;
	/**
	 * Pre-calculated hash.
	 * 
	 * @see #hashCode()
	 */
	private final int hash;

	private final boolean useClassInEquals;

	/**
	 * Bytes as String.
	 * 
	 * Cache result of {@link #getAsString()}.
	 * 
	 * @since 2.4
	 */
	private String asString;

	/**
	 * Create bytes array.
	 * 
	 * @param bytes bytes (not copied!)
	 * @throws NullPointerException if bytes is {@code null}
	 * @throws IllegalArgumentException if bytes length is larger than 255
	 */
	public Bytes(byte[] bytes) {
		this(bytes, 255, false);
	}

	/**
	 * Create bytes array.
	 * 
	 * @param bytes bytes
	 * @param maxLength maximum length of bytes
	 * @param copy {@code true} to copy bytes, {@code false} to use the provided
	 *            bytes
	 * @throws NullPointerException if bytes is {@code null}
	 * @throws IllegalArgumentException if bytes length is larger than maxLength
	 */
	public Bytes(byte[] bytes, int maxLength, boolean copy) {
		this(bytes, maxLength, copy, false);
	}

	/**
	 * Create bytes array.
	 * 
	 * @param bytes bytes
	 * @param maxLength maximum length of bytes
	 * @param copy {@code true} to copy bytes, {@code false} to use the provided
	 *            bytes
	 * @param useClassInEquals {@code true} to check the class, {@code false},
	 *            if equals checks only for {@link Bytes}
	 * @throws NullPointerException if bytes is {@code null}
	 * @throws IllegalArgumentException if bytes length is larger than maxLength
	 * @since 3.0
	 */
	public Bytes(byte[] bytes, int maxLength, boolean copy, boolean useClassInEquals) {
		if (bytes == null) {
			throw new NullPointerException("bytes must not be null");
		} else if (bytes.length > maxLength) {
			throw new IllegalArgumentException("bytes length must be between 0 and " + maxLength + " inclusive");
		}
		this.useClassInEquals = useClassInEquals;
		this.bytes = copy ? Arrays.copyOf(bytes, bytes.length) : bytes;
		this.hash = Arrays.hashCode(bytes);
	}

	@Override
	public String toString() {
		return new StringBuilder("BYTES=").append(getAsString()).toString();
	}

	@Override
	public final int hashCode() {
		return hash;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Note: since 3.0 the sub-class may be ignored. This depends on the
	 * provided value of the {@code useClassInEquals} parameter in
	 * {@link Bytes#Bytes(byte[], int, boolean, boolean)} for {@code this}, or
	 * the {@code other} object. The default behavior is changed to ignore the
	 * sub-class.
	 */
	@Override
	public final boolean equals(Object obj) {
		if (this == obj) {
			return true;
		} else if (obj == null) {
			return false;
		}
		if (obj instanceof Bytes) {
			Bytes other = (Bytes) obj;
			if ((useClassInEquals || other.useClassInEquals) && getClass() != obj.getClass()) {
				return false;
			}
			if (hash != other.hash) {
				return false;
			}
			return Arrays.equals(bytes, other.bytes);
		}
		return false;
	}

	/**
	 * Get bytes array.
	 * 
	 * @return bytes array. Not Copied!
	 */
	public final byte[] getBytes() {
		return bytes;
	}

	/**
	 * Get bytes as (hexadecimal) string.
	 * 
	 * @return bytes as (hexadecimal) string
	 */
	public final String getAsString() {
		if (asString == null) {
			asString = StringUtil.byteArray2Hex(bytes);
		}
		return asString;
	}

	/**
	 * Check, if connection id is empty.
	 * 
	 * @return {@code true}, if connection id is empty, {@code false}, otherwise
	 */
	public final boolean isEmpty() {
		return bytes.length == 0;
	}

	/**
	 * Return number of bytes.
	 * 
	 * @return number of bytes. 0 to 255.
	 */
	public final int length() {
		return bytes.length;
	}

	/**
	 * Create byte array initialized with random bytes.
	 * 
	 * @param generator random generator
	 * @param size number of bytes
	 * @return byte array initialized with random bytes
	 * @see Random#nextBytes(byte[])
	 */
	public static byte[] createBytes(Random generator, int size) {
		byte[] byteArray = new byte[size];
		try {
			generator.nextBytes(byteArray);
		} catch (IllegalArgumentException ex) {
			if (ex.getMessage().contains("Number of bits per request limited ")) {
				// Bouncy Castle limits the SecureRandom to 32k
				if (size > 4096) {
					byte[] part = new byte[4096];
					int offset = 0;
					while (offset < size) {
						generator.nextBytes(part);
						int fill = Math.min(size - offset, part.length);
						System.arraycopy(part, 0, byteArray, offset, fill);
						offset += fill;
					}
				}
			}
		}
		return byteArray;
	}

	/**
	 * Concatenates two Bytes.
	 * 
	 * @param a the first Bytes.
	 * @param b the second Bytes.
	 * @return the concatenated array.
	 * @see #concatenate(byte[], byte[])
	 */
	public static byte[] concatenate(Bytes a, Bytes b) {
		return concatenate(a.getBytes(), b.getBytes());
	}

	/**
	 * Concatenates two byte arrays.
	 * 
	 * @param a the first array.
	 * @param b the second array.
	 * @return the concatenated array.
	 * @see #concatenate(Bytes, Bytes)
	 */
	public static byte[] concatenate(byte[] a, byte[] b) {
		int lengthA = a.length;
		int lengthB = b.length;

		byte[] concat = new byte[lengthA + lengthB];

		System.arraycopy(a, 0, concat, 0, lengthA);
		System.arraycopy(b, 0, concat, lengthA, lengthB);

		return concat;
	}

	/**
	 * Clear provided byte array.
	 * 
	 * Fill it with 0s.
	 * 
	 * @param data byte array to be cleared.
	 */
	public static void clear(byte[] data) {
		Arrays.fill(data, (byte) 0);
	}

	/**
	 * Checks, whether some bytes are "equal to" each other.
	 * 
	 * @param a first bytes to check
	 * @param b second bytes to check
	 * @return {@code true}, if the bytes are equal, {@code false}, otherwise.
	 * @since 3.0
	 */
	public static boolean equals(Bytes a, Bytes b) {
		if (a == b) {
			return true;
		} else if (a == null || b == null) {
			return false;
		}
		return a.equals(b);
	}
}
