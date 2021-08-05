/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial support for correlation context to provide
 *                                      additional information to application layer for
 *                                      matching messages using TCP.
 *    Achim Kraus (Bosch Software Innovations GmbH) - extend endpoint context with
 *                                                    inet socket address and principal
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.net.InetSocketAddress;
import java.security.Principal;

import org.eclipse.californium.elements.util.StringUtil;

/**
 * A endpoint context that explicitly supports TCP specific properties.
 */
public class TcpEndpointContext extends MapBasedEndpointContext {

	/**
	 * Key for TCP connection ID as {@link String}.
	 */
	public static final Definition<String> KEY_CONNECTION_ID = new Definition<>("CONNECTION_ID", String.class,
			ATTRIBUTE_DEFINITIONS);
	/**
	 * Key for TCP connection timestamp as {@link String}.
	 * 
	 * In milliseconds since midnight, January 1, 1970 UTC.
	 * 
	 * @since 3.0
	 */
	public static final Definition<Long> KEY_CONNECTION_TIMESTAMP = new Definition<>("CONNECTION_TIMESTAMP", Long.class,
			ATTRIBUTE_DEFINITIONS);

	/**
	 * Creates a new endpoint context from TCP connection ID.
	 * 
	 * @param peerAddress peer address of endpoint context
	 * @param connectionId the connectionn's ID.
	 * @param timestamp the timestamp in milliseconds of the last connect.
	 * @throws NullPointerException if connectionId or peer address is
	 *             {@code null}.
	 */
	public TcpEndpointContext(InetSocketAddress peerAddress, String connectionId, long timestamp) {
		this(peerAddress, null,
				new Attributes().add(KEY_CONNECTION_ID, connectionId).add(KEY_CONNECTION_TIMESTAMP, timestamp));
	}

	/**
	 * Creates a new endpoint context.
	 * 
	 * Intended to be used by subclasses, which provides a principal and
	 * additional attributes. The {@link #KEY_CONNECTION_ID} attribute MUST be
	 * included in the attributes.
	 * 
	 * @param peerAddress peer address of endpoint context
	 * @param peerIdentity peer identity of endpoint context
	 * @param attributes map of attributes, must contain
	 *            {@link #KEY_CONNECTION_ID}.
	 * @throws NullPointerException if peer address is {@code null}.
	 * @throws IllegalArgumentException attributes not contain
	 *             {@link #KEY_CONNECTION_ID}
	 * @since 3.0 (changed to use Attributes)
	 */
	protected TcpEndpointContext(InetSocketAddress peerAddress, Principal peerIdentity, Attributes attributes) {
		super(peerAddress, peerIdentity, attributes);
		if (null == getConnectionId()) {
			throw new IllegalArgumentException("Missing " + KEY_CONNECTION_ID + " attribute!");
		}
	}

	/**
	 * Get TCP connection id.
	 * 
	 * @return TCP connection id
	 */
	public String getConnectionId() {
		return get(KEY_CONNECTION_ID);
	}

	/**
	 * Gets the timestamp in milliseconds of the last connect.
	 * 
	 * @return The timestamp in milliseconds of the last connect.
	 * 
	 * @see System#currentTimeMillis()
	 * @since 3.0
	 */
	public final Number getConnectionTimestamp() {
		return get(KEY_CONNECTION_TIMESTAMP);
	}

	@Override
	public String toString() {
		return String.format("TCP(%s,ID:%s)", getPeerAddressAsString(),
				StringUtil.trunc(getConnectionId(), ID_TRUNC_LENGTH));
	}

}
