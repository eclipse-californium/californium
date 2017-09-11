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
 *                                      matching messages (fix GitHub issue #1)
 *    Achim Kraus (Bosch Software Innovations GmbH) - rename DtlsCorrelationContext 
 *                                      into DtlsEndpointContext.
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.net.InetSocketAddress;
import java.security.Principal;

/**
 * A endpoint context that explicitly supports DTLS specific properties.
 */
public class DtlsEndpointContext extends MapBasedEndpointContext {

	public static final String KEY_SESSION_ID = "DTLS_SESSION_ID";
	public static final String KEY_EPOCH = "DTLS_EPOCH";
	public static final String KEY_CIPHER = "DTLS_CIPHER";

	/**
	 * Creates a new endpoint context from DTLS session parameters.
	 * 
	 * @param sessionId the session's ID.
	 * @param epoch the session's current read/write epoch.
	 * @param cipher the cipher suite of the session's current read/write state.
	 * @throws NullPointerException if any of the params is <code>null</code>.
	 */
	public DtlsEndpointContext(InetSocketAddress peerAddress, Principal peerIdentity, String sessionId, String epoch, String cipher) {
		super(peerAddress, peerIdentity);
		if (sessionId == null) {
			throw new NullPointerException("Session ID must not be null");
		} else if (epoch == null) {
			throw new NullPointerException("Epoch must not be null");
		} else if (cipher == null) {
			throw new NullPointerException("Cipher must not be null");
		} else {
			put(KEY_SESSION_ID, sessionId);
			put(KEY_EPOCH, epoch);
			put(KEY_CIPHER, cipher);
		}
	}

	public String getSessionId() {
		return get(KEY_SESSION_ID);
	}

	public String getEpoch() {
		return get(KEY_EPOCH);
	}

	public String getCipher() {
		return get(KEY_CIPHER);
	}
}