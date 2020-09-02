/*******************************************************************************
 * Copyright (c) 2015, 2018 Institute for Pervasive Computing, ETH Zurich and others.
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
 * Julien Vermillard - Sierra Wireless
 * Bosch Software Innovations GmbH - add SNI support
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.pskstore;

import java.net.InetSocketAddress;

import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;

import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * A service for resolving pre-shared key identities. {@link SecretKey} maybe
 * generated from byte arrays by {@link SecretUtil#create(byte[], String)}.
 * 
 * @deprecated use {@link AdvancedPskStore} instead, or {@link BridgePskStore}
 *             until migrated.
 */
@Deprecated
public interface PskStore {

	/**
	 * Gets the pre-shared key for a given identity.
	 * <p>
	 * A DTLS server can use this method to look up the pre-shared key for an
	 * identity provided by the client as part of a PSK key exchange.
	 * </p>
	 * <p>
	 * The implementation is intended to normalize the identity by a matching
	 * entry, if that entry is not UTF-8 compliant encoded.
	 * </p>
	 * The returned key is {@link SecretUtil#destroy}ed after usage.
	 * 
	 * @param identity The identity to look up the key for.
	 * @return The key or {@code null} if the given identity is unknown.
	 * @throws NullPointerException if identity is {@code null}.
	 * @see PskPublicInformation#normalize(String)
	 */
	SecretKey getKey(PskPublicInformation identity);

	/**
	 * Gets the pre-shared key for a given identity in the scope of a server
	 * name.
	 * <p>
	 * A DTLS server can use this method to look up the pre-shared key for an
	 * identity provided by the client as part of a PSK key exchange.
	 * </p>
	 * <p>
	 * The key is looked up in the context of the <em>virtual host</em> that the
	 * client has provided in the <em>Server Name Indication</em> extension
	 * contained in its <em>CLIENT_HELLO</em> message.
	 * </p>
	 * <p>
	 * The implementation is intended to normalize the identity by a matching
	 * entry, if that entry is not UTF-8 compliant encoded.
	 * </p>
	 * The returned key is intended to be be a copy. If the used
	 * {@link SecretKey} implements {@link Destroyable}, it will be cleaned up
	 * by {@link SecretUtil#destroy}ed after its usage.
	 * 
	 * @param serverName The name of the host that the client wants to connect
	 *            to as provided in the <em>Server Name Indication</em> HELLO
	 *            extension during the DTLS handshake. The key returned for the
	 *            given identity is being looked up in the context of this host
	 *            name.
	 * @param identity The identity to look up the key for.
	 * @return The key or {@code null} if no matching identity has been
	 *         registered for any of the server name types.
	 * @throws NullPointerException if any of the parameters is {@code null}.
	 * @see PskPublicInformation#normalize(String)
	 */
	SecretKey getKey(ServerNames serverName, PskPublicInformation identity);

	/**
	 * Gets the <em>identity</em> to use for a PSK based handshake with a given
	 * peer.
	 * <p>
	 * A DTLS client uses this method to determine the identity to include in
	 * its <em>CLIENT_KEY_EXCHANGE</em> message during a PSK based DTLS
	 * handshake with the peer.
	 * 
	 * @param inetAddress The IP address of the peer to perform the handshake
	 *            with.
	 * @return The identity to use or {@code null} if no peer with the given
	 *         address is registered.
	 * @throws NullPointerException if address is {@code null}.
	 */
	PskPublicInformation getIdentity(InetSocketAddress inetAddress);

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
	 * @return The identity to use or {@code null} if no peer with the given
	 *         address and virtual host is registered.
	 * @throws NullPointerException if address or host are {@code null}.
	 */
	PskPublicInformation getIdentity(InetSocketAddress peerAddress, ServerNames virtualHost);
}
