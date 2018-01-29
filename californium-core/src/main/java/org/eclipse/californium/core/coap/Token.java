/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial API and implementation
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove double [] from toString
 *******************************************************************************/
package org.eclipse.californium.core.coap;

import java.util.Arrays;

import org.eclipse.californium.core.Utils;

/**
 * Implementation of CoAP token.
 */
public class Token {

	/**
	 * Empty token.
	 */
	public static final Token EMPTY = new Token(new byte[0]);

	/**
	 * token data.
	 */
	private final byte[] token;
	/**
	 * Pre-calculated hash.
	 * 
	 * @see #hashCode()
	 */
	private final int hash;

	/**
	 * Create token from bytes.
	 * 
	 * @param token token bytes to be copied
	 */
	public Token(byte[] token) {
		this(token, true);
	}

	/**
	 * Create token from bytes.
	 * 
	 * @param token token bytes
	 * @param copy {@code true}, to copy the bytes, {@code false}, to use the
	 *            bytes without copy
	 * @throws NullPointerException if token is {@code null}
	 * @throws IllegalArgumentException if tokens length is larger than 8 (as
	 *             specified in CoAP)
	 */
	private Token(byte[] token, boolean copy) {
		if (token == null) {
			throw new NullPointerException("token bytes must not be null");
		} else if (token.length > 8) {
			throw new IllegalArgumentException("Token length must be between 0 and 8 inclusive");
		}
		if (copy && token.length > 0) {
			this.token = Arrays.copyOf(token, token.length);
		} else {
			this.token = token;
		}
		this.hash = Arrays.hashCode(this.token);
	}

	@Override
	public String toString() {
		return new StringBuilder("Token=").append(Utils.toHexString(token)).toString();
	}

	@Override
	public int hashCode() {
		return hash;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Token other = (Token) obj;
		return Arrays.equals(token, other.token);
	}

	/**
	 * Get token bytes.
	 * 
	 * @return token bytes. Not Copied!
	 */
	public byte[] getBytes() {
		return token;
	}

	/**
	 * Get token bytes as (hexadecimal) string.
	 * 
	 * @return token bytes as (hexadecimal) string
	 */
	public String getAsString() {
		return Utils.toHexString(token);
	}

	/**
	 * Check, if token is empty.
	 * 
	 * @return {@code true}, if token is empty, {@code false}, otherwise
	 */
	public boolean isEmpty() {
		return token.length == 0;
	}

	/**
	 * Return number of token bytes.
	 * 
	 * @return number of token bytes. 0 to 8.
	 */
	public int length() {
		return token.length;
	}

	/**
	 * Create token from provider token.
	 * 
	 * Doesn't copy the provided token.
	 * 
	 * @param token token, not copied!
	 * @return created Token
	 */
	public static Token fromProvider(byte[] token) {
		return new Token(token, false);
	}
}
