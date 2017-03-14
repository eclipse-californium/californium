/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 * Julien Vermillard - Sierra Wireless
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.pskstore;

import java.net.InetSocketAddress;

import org.eclipse.californium.scandium.util.ServerNames;

/**
 * A storage for pre-shared-key identity.
 */
public interface PskStore {

	/**
	 * Gets the shared key for a given identity.
	 * <p>
	 * The key is used for mutual authentication during a DTLS handshake.
	 * 
	 * @param identity The identity to look up the key for.
	 * @return The key or <code>null</code> if the given identity is unknown.
	 * @throws NullPointerException if identity is {@code null}.
	 */
	byte[] getKey(String identity);

	/**
	 * Gets the shared key for a given identity.
	 * <p>
	 * The key is used for mutual authentication during a DTLS handshake.
	 * 
	 * @param serverNames The names of servers the client provided as part of
	 *            the <em>Server Name Indication</em> hello extension during the
	 *            DTLS handshake. The key returned for the given identity is
	 *            being looked up in the context of these server names.
	 * @param identity The identity to look up the key for.
	 * @return The key or <code>null</code> if the given identity is unknown.
	 * @throws NullPointerException if any of the parameters is {@code null}.
	 */
	byte[] getKey(ServerNames serverNames, String identity);

	/**
	 * Gets the Identity to use for a PSK based handshake with a given peer.
	 * <p>
	 * A DTLS client uses this method to determine the identity to include in
	 * its <em>CLIENT_KEY_EXCHANGE</em> message during a PSK based DTLS
	 * handshake with the peer.
	 * 
	 * @param inetAddress The IP address of the peer to perform the handshake
	 *            with.
	 * @return The identity to use or <code>null</code> if no peer with the
	 *         given address is registered.
	 * @throws NullPointerException if address is {@code null}.
	 */
	String getIdentity(InetSocketAddress inetAddress);
}
