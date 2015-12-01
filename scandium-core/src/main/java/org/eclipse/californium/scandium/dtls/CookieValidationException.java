/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - Initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.util.Arrays;

/**
 * Thrown to indicate that a peer failed to prove its ability to receive messages
 * sent to the IP address used as the source IP in a <em>CLIENT_HELLO</em> handshake
 * message.
 * <p>
 * The <a href="http://tools.ietf.org/html/rfc6347#section-4.2.1">DTLS 1.2 specification</a>
 * defines a cookie exchange mechanism in order to prevent denial-of-service attacks using
 * forged IP addresses.
 */
public class CookieValidationException extends DtlsException {

	private static final long serialVersionUID = 1L;

	private final byte[] expectedCookie;
	private final byte[] receivedCookie;

	/**
	 * Constructs a new cookie validation exception for the cookie that failed validation.
	 * 
	 * @param expectedCookie the cookie sent to the client for validation
	 * @param receivedCookie the cookie received back from the client
	 * @param peer the IP address and port the cookie was used to verify control of
	 */
	public CookieValidationException(byte[] expectedCookie, byte[] receivedCookie, InetSocketAddress peer) {
		super("Cookie validation failed for peer", peer);
		this.expectedCookie = Arrays.copyOf(expectedCookie, expectedCookie.length);
		this.receivedCookie = Arrays.copyOf(receivedCookie, receivedCookie.length);
	}

	/**
	 * Gets the cookie value that has been sent to the client.
	 * 
	 * @return the cookie
	 */
	public final byte[] getExpectedCookie() {
		return expectedCookie;
	}

	/**
	 * Gets the cookie value that has been sent back by the client.
	 * 
	 * @return the cookie
	 */
	public final byte[] getReceivedCookie() {
		return receivedCookie;
	}
}
