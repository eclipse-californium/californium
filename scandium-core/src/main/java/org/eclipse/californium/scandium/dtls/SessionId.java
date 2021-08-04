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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add equals() & hashCode()
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add toString()
 *    Achim Kraus (Bosch Software Innovations GmbH) - use toHex() for compact
 *                                                    hex representation. 
 *    Achim Kraus (Bosch Software Innovations GmbH) - reuse id as string
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.scandium.dtls.cipher.RandomManager;

/**
 * A session identifier is a value generated by a server that identifies a
 * particular session.
 */
public final class SessionId extends Bytes {

	private static final SessionId EMPTY_SESSION_ID = new SessionId(Bytes.EMPTY);

	public SessionId() {
		this(Bytes.createBytes(RandomManager.currentSecureRandom(), 32));
	}

	/**
	 * Creates a session identifier based on given bytes.
	 * 
	 * @param sessionId the bytes constituting the identifier
	 * @throws NullPointerException if the byte array is {@code null}
	 * @throws IllegalArgumentException if the byte array is larger than 255
	 *             bytes
	 */
	public SessionId(byte[] sessionId) {
		super(sessionId);
	}

	/**
	 * Creates a new instance with an empty byte array as the ID.
	 * 
	 * @return a new (empty) session ID object
	 */
	public static SessionId emptySessionId() {
		return EMPTY_SESSION_ID;
	}

	/**
	 * Creates a string representation of this session ID.
	 * 
	 * @return the hexadecimal string representation of the <code>id</code> property value
	 */
	@Override
	public String toString() {
		return getAsString();
	}
}
