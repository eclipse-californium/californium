/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove double [] from toString
 *    Achim Kraus (Bosch Software Innovations GmbH) - use introduced Bytes
 *******************************************************************************/
package org.eclipse.californium.core.coap;

import org.eclipse.californium.elements.util.Bytes;

/**
 * Implementation of CoAP token.
 */
public class Token extends Bytes {

	/**
	 * Empty token.
	 */
	public static final Token EMPTY = new Token(Bytes.EMPTY);

	/**
	 * Create token from bytes.
	 * 
	 * @param token token bytes to be copied
	 * @throws NullPointerException if token is {@code null}
	 * @throws IllegalArgumentException if tokens length is larger than 8 (as
	 *             specified in CoAP)
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
		super(token, 8, copy);
	}

	@Override
	public String toString() {
		return new StringBuilder("Token=").append(getAsString()).toString();
	}

	/**
	 * Create token from provider token.
	 * <p>
	 * Doesn't copy the provided token.
	 * 
	 * @param token token, not copied!
	 * @return created Token
	 * @throws NullPointerException if token is {@code null}
	 * @throws IllegalArgumentException if tokens length is larger than 8 (as
	 *             specified in CoAP)
	 */
	public static Token fromProvider(byte[] token) {
		if (token == null) {
			throw new NullPointerException("token must not be null");
		}
		if (token.length == 0) {
			return EMPTY;
		} else {
			return new Token(token, false);
		}
	}

	/**
	 * Creates token.
	 * <p>
	 * May return {@link #EMPTY}, if provided array is empty.
	 * 
	 * @param token token as byte array. May be {@code null}.
	 * @return create token, or {@code null}, if {@code null} is provided
	 * @throws IllegalArgumentException if tokens length is larger than 8 (as
	 *             specified in CoAP)
	 * @since 4.0
	 */
	public static Token create(byte[] token) {
		if (token == null) {
			return null;
		} else if (token.length == 0) {
			return EMPTY;
		} else {
			return new Token(token);
		}
	}
}
