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
	 * The name of the attribute that contains the DTLS session ID as
	 * {@link Bytes}.
	 */
	public static final Definition<Bytes> KEY_SESSION_ID = new Definition<>("DTLS_SESSION_ID", Bytes.class,
			ATTRIBUTE_DEFINITIONS);
	/**
	 * The name of the attribute that contains the <em>epoch</em> of the DTLS
	 * session as {@link Number}.
	 */
	public static final Definition<Integer> KEY_EPOCH = new Definition<>("DTLS_EPOCH", Integer.class,
			ATTRIBUTE_DEFINITIONS);
	/**
	 * The name of the attribute that contains the cipher suite used with the
	 * DTLS session as {@link String}.
	 */
	public static final Definition<String> KEY_CIPHER = new Definition<>("DTLS_CIPHER", String.class,
			ATTRIBUTE_DEFINITIONS);
	/**
	 * The name of the attribute that contains the timestamp of the last
	 * handshake of the DTLS session as {@link Number}.
	 * 
	 * In milliseconds since midnight, January 1, 1970 UTC.
	 */
	public static final Definition<Long> KEY_HANDSHAKE_TIMESTAMP = new Definition<>("DTLS_HANDSHAKE_TIMESTAMP",
			Long.class, ATTRIBUTE_DEFINITIONS);
	/**
	 * The name of the attribute that contains the dtls packet sequence number
	 * during the DTLS session as {@link Number}.
	 */
	public static final Definition<Long> DTLS_READ_SEQUENCE_NUMBER = new Definition<>(
			KEY_PREFIX_NONE_CRITICAL + "DTLS_READ_SEQUENCE_NUMBER", Long.class, ATTRIBUTE_DEFINITIONS);
	/**
	 * The name of the attribute that contains the DTLS Connection ID for
	 * incoming records from the other peer as {@link Bytes}, if used.
	 * 
	 * @since 2.5
	 */
	public static final Definition<Bytes> KEY_READ_CONNECTION_ID = new Definition<>("DTLS_READ_CONNECTION_ID",
			Bytes.class, ATTRIBUTE_DEFINITIONS);
	/**
	 * The name of the attribute that contains the DTLS Connection ID for
	 * outgoing records sent to the other peer as {@link Bytes}, if used.
	 * 
	 * @since 2.5
	 */
	public static final Definition<Bytes> KEY_WRITE_CONNECTION_ID = new Definition<>("DTLS_WRITE_CONNECTION_ID",
			Bytes.class, ATTRIBUTE_DEFINITIONS);
	/**
	 * The name of the attribute that indicates, that the record is received via
	 * a DTLS_CID router.
	 * 
	 * @since 2.5
	 */
	public static final Definition<String> KEY_VIA_ROUTER = new Definition<>(
			KEY_PREFIX_NONE_CRITICAL + "DTLS_VIA_ROUTER", String.class, ATTRIBUTE_DEFINITIONS);
	/**
	 * The name of the attribute that contains a handshake mode. Values see
	 * {@link #HANDSHAKE_MODE_FORCE_FULL}, {@link #HANDSHAKE_MODE_FORCE},
	 * {@link #HANDSHAKE_MODE_PROBE}, and {@link #HANDSHAKE_MODE_NONE}. Only
	 * considered, if endpoint is not configured as "server only". If not
	 * provided, a handshake will be started, if required and the connector is
	 * not configured to act as server only. None critical attribute, not
	 * considered for matching.
	 */
	public static final Definition<String> KEY_HANDSHAKE_MODE = new Definition<>(
			KEY_PREFIX_NONE_CRITICAL + "DTLS_HANDSHAKE_MODE", String.class, ATTRIBUTE_DEFINITIONS);
	/**
	 * The name of the attribute that contains a auto handshake timeout in
	 * milliseconds as {@link Number}.
	 * 
	 * {@code -1}, disable auto handshake timeout. None critical attribute, not
	 * considered for matching.
	 * 
	 * @since 3.0 (renamed, was KEY_RESUMPTION_TIMEOUT)
	 */
	public static final Definition<Integer> KEY_AUTO_HANDSHAKE_TIMEOUT = new Definition<>(
			KEY_PREFIX_NONE_CRITICAL + "DTLS_AUTO_HANDSHAKE_TIMEOUT", Integer.class, ATTRIBUTE_DEFINITIONS);
	/**
	 * The name of the attribute that contains the message size limit.
	 * 
	 * @since 3.0
	 */
	public static final Definition<Integer> KEY_MESSAGE_SIZE_LIMIT = new Definition<>(
			KEY_PREFIX_NONE_CRITICAL + "DTLS_MESSAGE_SIZE_LIMIT", Integer.class, ATTRIBUTE_DEFINITIONS);
	/**
	 * The name of the attribute that contains a marker for the extended master secret 
	 * (see <a href="https://tools.ietf.org/html/rfc7627" target="_blank">RFC 7627</a>).
	 * 
	 * @since 3.0
	 */
	public static final Definition<Boolean> KEY_EXTENDED_MASTER_SECRET = new Definition<>(
			KEY_PREFIX_NONE_CRITICAL + "DTLS_EXTENDED_MASTER_SECRET", Boolean.class, ATTRIBUTE_DEFINITIONS);
	/**
	 * The name of the attribute that contains a marker for newest received
	 * records.
	 * 
	 * @since 3.0
	 */
	public static final Definition<Boolean> KEY_NEWEST_RECORD = new Definition<>(
			KEY_PREFIX_NONE_CRITICAL + "DTLS_NEWEST_RECORD", Boolean.class, ATTRIBUTE_DEFINITIONS);
	/**
	 * The name of the attribute that contains a marker for newest received
	 * records.
	 * 
	 * @since 3.0
	 */
	public static final Definition<InetSocketAddress> KEY_PREVIOUS_ADDRESS = new Definition<>(
			KEY_PREFIX_NONE_CRITICAL + "DTLS_PREVIOUS_ADDRESS", InetSocketAddress.class, ATTRIBUTE_DEFINITIONS);
	/**
	 * The name of the attribute that contains a marker for the secure renegotiationt 
	 * (see <a href="https://tools.ietf.org/html/rfc5746" target="_blank">RFC 5746</a>).
	 * 
	 * Californium doesn't support renegotiation at all, but RFC5746 requests to
	 * update to a minimal version of RFC 5746.
	 * 
	 * @since 3.8
	 */
	public static final Definition<Boolean> KEY_SECURE_RENEGOTIATION = new Definition<>(
			"DTLS_SECURE_RENEGOTIATION", Boolean.class, ATTRIBUTE_DEFINITIONS);
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
	 * Attribute to set HANDSHAKE_MODE to {@link #HANDSHAKE_MODE_NONE}.
	 * 
	 * @since 3.0
	 */
	public static final Attributes ATTRIBUTE_HANDSHAKE_MODE_NONE = new Attributes()
			.add(KEY_HANDSHAKE_MODE, HANDSHAKE_MODE_NONE).lock();
	/**
	 * Attribute to set HANDSHAKE_MODE to {@link #HANDSHAKE_MODE_AUTO}.
	 * 
	 * @since 3.0
	 */
	public static final Attributes ATTRIBUTE_HANDSHAKE_MODE_AUTO = new Attributes()
			.add(KEY_HANDSHAKE_MODE, HANDSHAKE_MODE_AUTO).lock();
	/**
	 * Attribute to set HANDSHAKE_MODE to {@link #HANDSHAKE_MODE_PROBE}.
	 * 
	 * @since 3.0
	 */
	public static final Attributes ATTRIBUTE_HANDSHAKE_MODE_PROBE = new Attributes()
			.add(KEY_HANDSHAKE_MODE, HANDSHAKE_MODE_PROBE).lock();
	/**
	 * Attribute to set HANDSHAKE_MODE to {@link #HANDSHAKE_MODE_FORCE}.
	 * 
	 * @since 3.0
	 */
	public static final Attributes ATTRIBUTE_HANDSHAKE_MODE_FORCE = new Attributes()
			.add(KEY_HANDSHAKE_MODE, HANDSHAKE_MODE_FORCE).lock();
	/**
	 * Attribute to set HANDSHAKE_MODE to {@link #HANDSHAKE_MODE_FORCE_FULL}.
	 * 
	 * @since 3.0
	 */
	public static final Attributes ATTRIBUE_HANDSHAKE_MODE_FORCE_FULL = new Attributes()
			.add(KEY_HANDSHAKE_MODE, HANDSHAKE_MODE_FORCE_FULL).lock();

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
			Bytes sessionId, int epoch, String cipher, long timestamp, Bytes writeCid, Bytes readCid, String via) {
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
		return get(KEY_SESSION_ID);
	}

	/**
	 * Gets the current epoch of the DTLS session.
	 * 
	 * @return The epoch number.
	 */
	public final Number getEpoch() {
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
	public final Number getHandshakeTimestamp() {
		return get(KEY_HANDSHAKE_TIMESTAMP);
	}

	@Override
	public String toString() {
		return String.format("DTLS(%s,ID:%s)", getPeerAddressAsString(),
				StringUtil.trunc(getSessionId().getAsString(), ID_TRUNC_LENGTH));
	}
}
