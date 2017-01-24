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
 *    Bosch Software Innovations GmbH - add support for correlation context to provide
 *                                      additional information to application layer for
 *                                      matching messages using TLS
 ******************************************************************************/
package org.eclipse.californium.elements;

import org.eclipse.californium.elements.util.StringUtil;

/**
 * A correlation context that explicitly supports TLS specific properties.
 * Currently the context is not aware of renegotiation (API to acquire
 * information is missing). According oracle, the renegotiate issues seems not
 * be fixed, if your java is not to deprecated.
 * 
 * @see <a
 *      href="http://www.oracle.com/technetwork/java/javase/overview/tlsreadme2-176330.html">
 *      Fix renegotiate</a>
 */
public class TlsCorrelationContext extends TcpCorrelationContext {

	public static final String KEY_CIPHER = "CIPHER";

	/**
	 * Creates a new correlation context from TLS session parameters.
	 * 
	 * @param connectionId the connectionn's ID.
	 * @param sessionId the session's ID.
	 * @param cipher the cipher suite of the session's current read/write state.
	 * @throws NullPointerException if any of the params is <code>null</code>.
	 */
	public TlsCorrelationContext(String connectionId, String sessionId, String cipher) {
		super(connectionId);
		if (sessionId == null) {
			throw new NullPointerException("Session ID must not be null");
		} else if (cipher == null) {
			throw new NullPointerException("Cipher must not be null");
		} else {
			put(KEY_SESSION_ID, sessionId);
			put(KEY_CIPHER, cipher);
		}
	}

	public String getSessionId() {
		return get(KEY_SESSION_ID);
	}

	public String getCipher() {
		return get(KEY_CIPHER);
	}

	@Override
	public String toString() {
		return String.format("TLS(%s,%s,%s)", getConnectionId(), StringUtil.trunc(getSessionId(), 15), getCipher());
	}

}
