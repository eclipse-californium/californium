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
 *    Bosch Software Innovations GmbH - add support for endpoint context to provide
 *                                      additional information to application layer for
 *                                      matching messages using TLS
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.net.InetSocketAddress;
import java.security.Principal;

import org.eclipse.californium.elements.util.StringUtil;

/**
 * A endpoint context that explicitly supports TLS specific properties.
 * Currently the context is not aware of renegotiation (API to acquire
 * information is missing). According oracle, the renegotiate issues seems to be
 * fixed, if your java is not to deprecated.
 * 
 * @see <a href=
 *      "http://www.oracle.com/technetwork/java/javase/overview/tlsreadme2-176330.html">
 *      Fix renegotiate</a>
 */
public class TlsEndpointContext extends TcpEndpointContext {

	public static final String KEY_SESSION_ID = "TLS_SESSION_ID";

	public static final String KEY_CIPHER = "TLS_CIPHER";

	/**
	 * Creates a new correlation context from TLS session parameters.
	 * 
	 * @param peerAddress peer address of endpoint context
	 * @param peerIdentity peer identity of endpoint context
	 * @param connectionId the connectionn's ID.
	 * @param sessionId the session's ID.
	 * @param timestamp the timestamp in milliseconds of the last connect. 
	 * @param cipher the cipher suite of the session's current read/write state.
	 * @throws NullPointerException if any of the params is {@code null}.
	 * @since 3.0 (added timestamp)
	 */
	public TlsEndpointContext(InetSocketAddress peerAddress, Principal peerIdentity, String connectionId,
			String sessionId, String cipher, long timestamp) {
		super(peerAddress, peerIdentity, new Attributes().add(KEY_CONNECTION_ID, connectionId)
				.add(KEY_CONNECTION_TIMESTAMP, timestamp).add(KEY_SESSION_ID, sessionId).add(KEY_CIPHER, cipher));
	}

	public String getSessionId() {
		return getString(KEY_SESSION_ID);
	}

	public String getCipher() {
		return getString(KEY_CIPHER);
	}

	@Override
	public String toString() {
		return String.format("TLS(%s,%s,%s,%s)", getPeerAddressAsString(),
				StringUtil.trunc(getConnectionId(), ID_TRUNC_LENGTH), StringUtil.trunc(getSessionId(), ID_TRUNC_LENGTH),
				getCipher());
	}

}
