/*******************************************************************************
 * Copyright (c) 2016, 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - add support for correlation context to provide
 *                                      additional information to application layer for
 *                                      matching messages (fix GitHub issue #1)
 *    Achim Kraus (Bosch Software Innovations GmbH) - extend endpoint context with
 *                                                    inet socket address and principal
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.net.InetSocketAddress;
import java.security.Principal;

import org.eclipse.californium.elements.util.StringUtil;

/**
 * An endpoint context that explicitly supports DTLS specific properties.
 */
public class DtlsEndpointContext extends MapBasedEndpointContext {

	/**
	 * The name of the attribute that contains the DTLS session ID.
	 */
	public static final String KEY_SESSION_ID = "DTLS_SESSION_ID";
	/**
	 * The name of the attribute that contains the <em>epoch</em> of the
	 * DTLS session.
	 */
	public static final String KEY_EPOCH = "DTLS_EPOCH";
	/**
	 * The name of the attribute that contains the cipher suite used with
	 * the DTLS session.
	 */
	public static final String KEY_CIPHER = "DTLS_CIPHER";
	/**
	 * The name of the attribute that contains the timestamp of the last
	 * handshake of the DTLS session.
	 */
	public static final String KEY_HANDSHAKE_TIMESTAMP = "DTLS_HANDSHAKE_TIMESTAMP";
	/**
	 * The name of the attribute that contains a handshake mode. Values see
	 * {@link #HANDSHAKE_MODE_FORCE_FULL}, {@link #HANDSHAKE_MODE_FORCE}, and
	 * {@link #HANDSHAKE_MODE_NONE}. Only considered, if endpoint is not
	 * configured as "server only". If not provided, a handshake will be
	 * started, if required and the connector is not configured to act as server
	 * only. None critical attribute, not considered for matching.
	 */
	public static final String KEY_HANDSHAKE_MODE = KEY_PREFIX_NONE_CRITICAL + "DTLS_HANDSHAKE_MODE";

	/**
	 * Force full handshake before send this message. Doesn't start a handshake,
	 * if the connector is configured to act as server only.
	 */
	public static final String HANDSHAKE_MODE_FORCE_FULL = "full";
	/**
	 * Force handshake before send this message. Doesn't start a handshake, if
	 * the connector is configured to act as server only.
	 */
	public static final String HANDSHAKE_MODE_FORCE = "force";
	/**
	 * Don't start a handshake, even, if no session is available.
	 */
	public static final String HANDSHAKE_MODE_NONE = "none";

	/**
	 * The name of the attribute that contains a auto session resumption timeout
	 * in milliseconds. {@code ""}, disable auto session resumption. None
	 * critical attribute, not considered for matching.
	 */
	public static final String KEY_RESUMPTION_TIMEOUT = KEY_PREFIX_NONE_CRITICAL + "DTLS_RESUMPTION_TIMEOUT";

	/**
	 * Creates a context for DTLS session parameters.
	 * 
	 * @param peerAddress peer address of endpoint context
	 * @param peerIdentity peer identity of endpoint context
	 * @param sessionId the session's ID.
	 * @param epoch the session's current read/write epoch.
	 * @param cipher the cipher suite of the session's current read/write state.
	 * @param timestamp the timestamp in milliseconds of the last handshake. See
	 *            {@link System#currentTimeMillis()}.
	 * @throws NullPointerException if any of the parameters other than
	 *             peerIdentity are {@code null}.
	 */
	public DtlsEndpointContext(InetSocketAddress peerAddress, Principal peerIdentity,
			String sessionId, String epoch, String cipher, String timestamp) {

		this(peerAddress, null, peerIdentity, sessionId, epoch, cipher, timestamp);
	}

	/**
	 * Creates a context for DTLS session parameters.
	 * 
	 * @param peerAddress peer address of endpoint context
	 * @param virtualHost the name of the virtual host at the peer
	 * @param peerIdentity peer identity of endpoint context
	 * @param sessionId the session's ID.
	 * @param epoch the session's current read/write epoch.
	 * @param cipher the cipher suite of the session's current read/write state.
	 * @param timestamp the timestamp in milliseconds of the last handshake. See
	 *            {@link System#currentTimeMillis()}.
	 * @throws NullPointerException if any of the parameters other than
	 *             peerIdentity are {@code null}.
	 */
	public DtlsEndpointContext(InetSocketAddress peerAddress, String virtualHost, Principal peerIdentity,
			String sessionId, String epoch, String cipher, String timestamp) {

		super(peerAddress, virtualHost, peerIdentity, KEY_SESSION_ID, sessionId, KEY_CIPHER, cipher, KEY_EPOCH, epoch,
				KEY_HANDSHAKE_TIMESTAMP, timestamp);
	}

	/**
	 * Gets the identifier of the DTLS session.
	 * 
	 * @return The identifier.
	 */
	public final String getSessionId() {
		return get(KEY_SESSION_ID);
	}

	/**
	 * Gets the current epoch of the DTLS session.
	 * 
	 * @return The epoch number.
	 */
	public final String getEpoch() {
		return get(KEY_EPOCH);
	}

	/**
	 * Gets the name of the cipher suite in use for the DTLS session.
	 * 
	 * @return The name.
	 */
	public final String getCipher() {
		return get(KEY_CIPHER);
	}

	/**
	 * Gets the timestamp in milliseconds of the last handshake.
	 * 
	 * @return The timestamp in milliseconds of the last handshake.
	 * 
	 * @see System#currentTimeMillis()
	 */
	public final String getHandshakeTimestamp() {
		return get(KEY_HANDSHAKE_TIMESTAMP);
	}

	@Override
	public String toString() {
		return String.format("DTLS(%s,ID:%s)", getPeerAddressAsString(),
				StringUtil.trunc(getSessionId(), ID_TRUNC_LENGTH));
	}
}
