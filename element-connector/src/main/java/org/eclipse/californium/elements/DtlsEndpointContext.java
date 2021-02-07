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

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * An endpoint context that explicitly supports DTLS specific properties.
 */
public class DtlsEndpointContext extends MapBasedEndpointContext {

	/**
	 * The name of the attribute that contains the DTLS session ID as {@link Bytes}.
	 */
	public static final String KEY_SESSION_ID = "DTLS_SESSION_ID";
	/**
	 * The name of the attribute that contains the <em>epoch</em> of the DTLS
	 * session as {@link Number}.
	 */
	public static final String KEY_EPOCH = "DTLS_EPOCH";
	/**
	 * The name of the attribute that contains the cipher suite used with the
	 * DTLS session as {@link String}.
	 */
	public static final String KEY_CIPHER = "DTLS_CIPHER";
	/**
	 * The name of the attribute that contains the timestamp of the last
	 * handshake of the DTLS session as {@link Number}.
	 * 
	 * In milliseconds since midnight, January 1, 1970 UTC.
	 */
	public static final String KEY_HANDSHAKE_TIMESTAMP = "DTLS_HANDSHAKE_TIMESTAMP";
	/**
	 * The name of the attribute that contains the DTLS Connection ID of the
	 * other peer as {@link Bytes}, if used.
	 * 
	 * @since 2.5
	 */
	public static final String KEY_READ_CONNECTION_ID = "DTLS_READ_CONNECTION_ID";
	/**
	 * The name of the attribute that contains the DTLS Connection ID of the
	 * other peer as {@link Bytes}, if used.
	 * 
	 * @since 2.5
	 */
	public static final String KEY_WRITE_CONNECTION_ID = "DTLS_WRITE_CONNECTION_ID";
	/**
	 * The name of the attribute that indicates, that the record is received via
	 * a DTLS_CID router.
	 * 
	 * @since 2.5
	 */
	public static final String KEY_VIA_ROUTER = KEY_PREFIX_NONE_CRITICAL + "DTLS_VIA_ROUTER";
	/**
	 * The name of the attribute that contains a handshake mode. Values see
	 * {@link #HANDSHAKE_MODE_FORCE_FULL}, {@link #HANDSHAKE_MODE_FORCE},
	 * {@link #HANDSHAKE_MODE_PROBE}, and {@link #HANDSHAKE_MODE_NONE}. Only
	 * considered, if endpoint is not configured as "server only". If not
	 * provided, a handshake will be started, if required and the connector is
	 * not configured to act as server only. None critical attribute, not
	 * considered for matching.
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
	 * Force handshake probe before send this message. Doesn't start a
	 * handshake, if the connector is configured to act as server only.
	 */
	public static final String HANDSHAKE_MODE_PROBE = "probe";
	/**
	 * Start a handshake, if no session is available.
	 */
	public static final String HANDSHAKE_MODE_AUTO = "auto";
	/**
	 * Don't start a handshake, even, if no session is available.
	 */
	public static final String HANDSHAKE_MODE_NONE = "none";

	/**
	 * The name of the attribute that contains a auto session resumption timeout
	 * in milliseconds as number.
	 * 
	 * {@code -1}, disable auto session resumption. None critical attribute, not
	 * considered for matching.
	 */
	public static final String KEY_RESUMPTION_TIMEOUT = KEY_PREFIX_NONE_CRITICAL + "DTLS_RESUMPTION_TIMEOUT";

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
	 *             peerIdentity or virtualHost are {@code null}.
	 */
	public DtlsEndpointContext(InetSocketAddress peerAddress, String virtualHost, Principal peerIdentity,
			Bytes sessionId, int epoch, String cipher, long timestamp) {

		super(peerAddress, virtualHost, peerIdentity, new Attributes().add(KEY_SESSION_ID, sessionId)
				.add(KEY_CIPHER, cipher).add(KEY_EPOCH, epoch).add(KEY_HANDSHAKE_TIMESTAMP, timestamp));
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
	 * @param writeCid dtls connection id for outgoing records.
	 * @param readCid dtls connection id for incoming records.
	 * @param via via router tag.
	 * @throws NullPointerException if any of the parameters other than
	 *             peerIdentity or virtualHost are {@code null}.
	 * @since 2.5
	 */
	public DtlsEndpointContext(InetSocketAddress peerAddress, String virtualHost, Principal peerIdentity,
			Bytes sessionId, int epoch, String cipher, long timestamp, Bytes writeCid, Bytes readCid,
			String via) {
		super(peerAddress, virtualHost, peerIdentity,
				new Attributes().add(KEY_SESSION_ID, sessionId).add(KEY_CIPHER, cipher).add(KEY_EPOCH, epoch)
						.add(KEY_HANDSHAKE_TIMESTAMP, timestamp).add(KEY_WRITE_CONNECTION_ID, writeCid)
						.add(KEY_READ_CONNECTION_ID, readCid).add(KEY_VIA_ROUTER, via));
	}

	/**
	 * Creates a context for DTLS session parameters.
	 * 
	 * @param peerAddress peer address of endpoint context
	 * @param virtualHost the name of the virtual host at the peer
	 * @param peerIdentity peer identity of endpoint context
	 * @param attributes attributes for dtls context.
	 * @since 3.0
	 */
	public DtlsEndpointContext(InetSocketAddress peerAddress, String virtualHost, Principal peerIdentity,
			Attributes attributes) {
		super(peerAddress, virtualHost, peerIdentity, attributes);
	}

	/**
	 * Gets the identifier of the DTLS session.
	 * 
	 * @return The identifier.
	 */
	public final Bytes getSessionId() {
		return getBytes(KEY_SESSION_ID);
	}

	/**
	 * Gets the current epoch of the DTLS session.
	 * 
	 * @return The epoch number.
	 */
	public final Number getEpoch() {
		return getNumber(KEY_EPOCH);
	}

	/**
	 * Gets the name of the cipher suite in use for the DTLS session.
	 * 
	 * @return The name.
	 */
	public final String getCipher() {
		return getString(KEY_CIPHER);
	}

	/**
	 * Gets the timestamp in milliseconds of the last handshake.
	 * 
	 * @return The timestamp in milliseconds of the last handshake.
	 * 
	 * @see System#currentTimeMillis()
	 */
	public final Number getHandshakeTimestamp() {
		return getNumber(KEY_HANDSHAKE_TIMESTAMP);
	}

	@Override
	public String toString() {
		return String.format("DTLS(%s,ID:%s)", getPeerAddressAsString(),
				StringUtil.trunc(getSessionId().getAsString(), ID_TRUNC_LENGTH));
	}
}
