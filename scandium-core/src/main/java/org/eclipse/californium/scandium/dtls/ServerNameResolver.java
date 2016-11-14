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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;

import org.eclipse.californium.scandium.util.ServerNames;

/**
 * Resolves IP addresses to server names.
 * <p>
 * The {@code ClientHandshaker} uses this resolver to determine whether the <em>CLIENT_HELLO</em>
 * message sent to a peer should include a <a href="https://tools.ietf.org/html/rfc6066#section-3">
 * <em>Server Name Indication</em> extension</a> and if so, which server names it should indicate to
 * the peer.
 *
 */
public interface ServerNameResolver {

	/**
	 * Gets the server names to indicate to a given peer during a handshake.
	 * <p>
	 * A DTLS client uses this method to determine the server names to include in
	 * the <a href="https://tools.ietf.org/html/rfc6066#section-3"><em>Server Name
	 * Indication</em> extension</a> in its <em>CLIENT_HELLO</em> message during a
	 * DTLS handshake with the peer.
	 * 
	 * @param peerAddress The IP address of the peer to perform the handshake with.
	 * @return The server names to include in the extension or <code>null</code> if
	 *         no names are registered for the peer.
	 * @throws NullPointerException if address is {@code null}.
	 */
	ServerNames getServerNames(InetSocketAddress peerAddress);
}
