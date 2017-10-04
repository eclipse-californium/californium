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
 *    Bosch Software Innovations GmbH - initial support for correlation context to provide
 *                                      additional information to application layer for
 *                                      matching messages using TCP.
 *    Achim Kraus (Bosch Software Innovations GmbH) - extend endpoint context with
 *                                                    inet socket address and principal
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.net.InetSocketAddress;
import java.security.Principal;

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
		this(peerAddress, null, connectionId);
	}

	/**
	 * Creates a new endpoint context from TCP connection ID.
	 * 
	 * @param peerAddress peer address of endpoint context
	 * @param peerIdentity peer identity of endpoint context
	 * @param connectionId the connectionn's ID.
	 * @throws NullPointerException if connectionId or peer address is
	 *             <code>null</code>.
	 */
	public TcpEndpointContext(InetSocketAddress peerAddress, Principal peerIdentity, String connectionId) {
		super(peerAddress, peerIdentity, KEY_CONNECTION_ID, connectionId);
	}

	public String getConnectionId() {
		return get(KEY_CONNECTION_ID);
	}

	@Override
	public String toString() {
		return String.format("TCP(%s:%d,ID:%s)", getPeerAddress().getHostString(), getPeerAddress().getPort(),
				getConnectionId());
	}

}
