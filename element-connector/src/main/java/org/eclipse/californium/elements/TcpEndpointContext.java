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
	 * Key for TCP connection ID.
	 * 
	 */
	public static final String KEY_CONNECTION_ID = "CONNECTION_ID";

	/**
	 * Creates a new endpoint context from TCP connection ID.
	 * 
	 * @param peerAddress peer address of endpoint context
	 * @param connectionId the connectionn's ID.
	 * @throws NullPointerException if connectionId or peer address is
	 *             <code>null</code>.
	 */
	public TcpEndpointContext(InetSocketAddress peerAddress, String connectionId) {
		this(peerAddress, null, KEY_CONNECTION_ID, connectionId);
	}

	/**
	 * Creates a new endpoint context.
	 * 
	 * Intended to be used by subclasses, which provides a principal and
	 * additional attributes. The {@link #KEY_CONNECTION_ID} attribute MUST be
	 * included in the attributes list.
	 * 
	 * @param peerAddress peer address of endpoint context
	 * @param peerIdentity peer identity of endpoint context
	 * @param attributes list of attributes (name-value pairs, e.g. key_1,
	 *            value_1, key_2, value_2 ...), the pair
	 *            {@link #KEY_CONNECTION_ID}, "id" must be contained in the
	 *            attributes.
	 */
	protected TcpEndpointContext(InetSocketAddress peerAddress, Principal peerIdentity, String... attributes) {
		super(peerAddress, peerIdentity, attributes);
		if (null == getConnectionId()) {
			throw new IllegalArgumentException("Missing attribute ");
		}
	}

	public String getConnectionId() {
		return get(KEY_CONNECTION_ID);
	}

	@Override
	public String toString() {
		return String.format("TCP(%s,ID:%s)", getPeerAddressAsString(),
				StringUtil.trunc(getConnectionId(), ID_TRUNC_LENGTH));
	}

}
