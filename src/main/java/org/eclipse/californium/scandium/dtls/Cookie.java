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


/**
 * Represents a stateless cookie which is used in the {@link HelloVerifyRequest}
 * in the DTLS handshake to prevent denial-of-service attacks. See <a
 * href="http://tools.ietf.org/html/rfc6347#section-4.3.2">RFC 6347</a> for
 * further details.
 */
public class Cookie {

	/** The cookie as byte array. */
	private byte[] cookie;

	/**
	 * Used by client, when sending a {@link ClientHello} for the first time
	 * (empty cookie).
	 */
	public Cookie() {
		this.cookie = new byte[] {};
	}

	/**
	 * Called when sending a {@link HelloVerifyRequest} (server) or
	 * {@link ClientHello} (client) for the second time.
	 * 
	 * @param cookie
	 *            the Cookie.
	 */
	public Cookie(byte[] cookie) {
		this.cookie = cookie;
	}

	/**
	 * 
	 * @return the number of bytes of the cookie.
	 */
	public int length() {
		return cookie.length;
	}

	public byte[] getCookie() {
		return cookie;
	}

	public void setCookie(byte[] cookie) {
		this.cookie = cookie;
	}
}
