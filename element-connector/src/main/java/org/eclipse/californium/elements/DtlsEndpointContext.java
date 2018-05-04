/*******************************************************************************
 * Copyright (c) 2016, 2018 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - extend endpoint context with
 *                                                    inet socket address and principal
 *    Bosch Software Innovations GmbH - extend context with virtual host name
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.net.InetSocketAddress;
import java.security.Principal;

import org.eclipse.californium.elements.util.StringUtil;

/**
 * A endpoint context that explicitly supports DTLS specific properties.
 */
public class DtlsEndpointContext extends MapBasedEndpointContext {

	static final String KEY_SESSION_ID = "DTLS_SESSION_ID";
	static final String KEY_EPOCH = "DTLS_EPOCH";
	static final String KEY_CIPHER = "DTLS_CIPHER";

	/**
	 * Creates a new endpoint context from DTLS session parameters.
	 * 
	 * @param peerAddress peer address of endpoint context
	 * @param peerIdentity peer identity of endpoint context
	 * @param sessionId the session's ID.
	 * @param epoch the session's current read/write epoch.
	 * @param cipher the cipher suite of the session's current read/write state.
	 * @throws NullPointerException if any of the parameters other than peerIdentity
	 *             are {@code null}.
	 */
	public DtlsEndpointContext(InetSocketAddress peerAddress, Principal peerIdentity,
			String sessionId, String epoch, String cipher) {

		super(peerAddress, peerIdentity,
				KEY_SESSION_ID, sessionId,
				KEY_CIPHER, cipher,
				KEY_EPOCH, epoch);
	}

	/**
	 * Gets the ID of the DTLS session that this context has been created from.
	 * 
	 * @return The session ID.
	 */
	public String getSessionId() {
		return get(KEY_SESSION_ID);
	}

	/**
	 * Gets the epoch of the DTLS session that this context has been created from.
	 * 
	 * @return The session ID.
	 */
	public String getEpoch() {
		return get(KEY_EPOCH);
	}

	/**
	 * Gets the cipher suite of the DTLS session that this context has been created from.
	 * 
	 * @return The session ID.
	 */
	public String getCipher() {
		return get(KEY_CIPHER);
	}

	@Override
	public String toString() {
		return String.format("DTLS(%s, ID:%s)", getPeerAddressAsString(),
				StringUtil.trunc(getSessionId(), ID_TRUNC_LENGTH));
	}
}
