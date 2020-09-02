/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 *                                      abstract API 
 *******************************************************************************/

package org.eclipse.californium.scandium.dtls.pskstore;

import java.net.InetSocketAddress;

import javax.crypto.SecretKey;

import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * String based pre-shared-key store.
 * <p>
 * May be used for backwards compatibility.
 * 
 * @deprecated use {@link AdvancedPskStore} instead, or {@link BridgePskStore}
 *             until migrated.
 */
@Deprecated
public abstract class StringPskStore implements PskStore {

	@Override
	public SecretKey getKey(final PskPublicInformation identity) {
		if (identity.isCompliantEncoding()) {
			return getKey(identity.getPublicInfoAsString());
		}
		return null;
	}

	@Override
	public SecretKey getKey(final ServerNames serverNames, final PskPublicInformation identity) {
		if (identity.isCompliantEncoding()) {
			return getKey(serverNames, identity.getPublicInfoAsString());
		}
		return null;
	}

	@Override
	public PskPublicInformation getIdentity(final InetSocketAddress inetAddress) {
		return new PskPublicInformation(getIdentityAsString(inetAddress));
	}

	@Override
	public PskPublicInformation getIdentity(InetSocketAddress peerAddress, ServerNames virtualHost) {
		return new PskPublicInformation(getIdentityAsString(peerAddress, virtualHost));
	}

	/**
	 * Gets the pre-shared key for a given identity.
	 * <p>
	 * A DTLS server can use this method to look up the pre-shared key for an
	 * identity provided by the client as part of a PSK key exchange.
	 * </p>
	 * <p>
	 * The returned key is {@link SecretUtil#destroy}ed after usage.
	 * </p>
	 * 
	 * @param identity The identity to look up the key for.
	 * @return The key or <code>null</code> if the given identity is unknown.
	 * @throws NullPointerException if identity is {@code null}.
	 */
	public abstract SecretKey getKey(String identity);

	/**
	 * Gets the pre-shared key for a given identity in the scope of a server name.
	 * <p>
	 * A DTLS server can use this method to look up the pre-shared key for an
	 * identity provided by the client as part of a PSK key exchange.
	 * </p>
	 * <p>
	 * The key is looked up in the context of the <em>virtual host</em> that the
	 * client has provided in the <em>Server Name Indication</em> extension
	 * contained in its <em>CLIENT_HELLO</em> message.
	 * </p>
	 * The returned key is {@link SecretUtil#destroy}ed after usage.
	 * 
	 * @param serverName The name of the host that the client wants to connect
	 *            to as provided in the <em>Server Name Indication</em> HELLO
	 *            extension during the DTLS handshake. The key returned for the
	 *            given identity is being looked up in the context of this host
	 *            name.
	 * @param identity The identity to look up the key for.
	 * @return The key or <code>null</code> if no matching identity has been
	 *         registered for any of the server name types.
	 * @throws NullPointerException if any of the parameters is {@code null}.
	 */
	public abstract SecretKey getKey(ServerNames serverName, String identity);

	/**
	 * Gets the <em>identity</em> to use for a PSK based handshake with a given
	 * peer.
	 * <p>
	 * A DTLS client uses this method to determine the identity to include in
	 * its <em>CLIENT_KEY_EXCHANGE</em> message during a PSK based DTLS
	 * handshake with the peer.
	 * </p>
	 * 
	 * @param inetAddress The IP address of the peer to perform the handshake
	 *            with.
	 * @return The identity to use or <code>null</code> if no peer with the
	 *         given address is registered.
	 * @throws NullPointerException if address is {@code null}.
	 */
	public abstract String getIdentityAsString(InetSocketAddress inetAddress);

	/**
	 * Gets the <em>identity</em> to use for a PSK based handshake with a given
	 * peer.
	 * <p>
	 * A DTLS client uses this method to determine the identity to include in
	 * its <em>CLIENT_KEY_EXCHANGE</em> message during a PSK based DTLS
	 * handshake with the peer.
	 * 
	 * @param peerAddress The IP address and port of the peer to perform the
	 *            handshake with.
	 * @param virtualHost The virtual host at the peer to connect to. If
	 *            {@code null}, the identity will be looked up in the
	 *            <em>global</em> scope, yielding the same result as
	 *            {@link #getIdentity(InetSocketAddress)}.
	 * @return The identity to use or <code>null</code> if no peer with the
	 *         given address and virtual host is registered.
	 * @throws NullPointerException if address or host are {@code null}.
	 */
	public abstract String getIdentityAsString(InetSocketAddress peerAddress, ServerNames virtualHost);

}
