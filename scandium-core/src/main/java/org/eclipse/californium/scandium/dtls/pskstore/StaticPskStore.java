/*******************************************************************************
 * Copyright (c) 2015, 2018 Institute for Pervasive Computing, ETH Zurich and others.
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
 * Bosch Software Innovations GmbH - add SNI support
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.pskstore;

import java.net.InetSocketAddress;
import java.util.Arrays;

import org.eclipse.californium.scandium.util.ServerNames;

/**
 * A simple in-memory pre-shared-key store.
 * <p>
 * This implementation always returns the same identity/Key for all peers
 * and is mainly intended for testing and evaluation purposes.
 * <p>
 * NB Keeping keys in in-memory is not a good idea for production. Instead, keys
 * should be kept in an encrypted store.
 */
public class StaticPskStore implements PskStore {

	private final byte[] key;
	private final String fixedIdentity;

	/**
	 * Creates a new store for an identity and key.
	 * 
	 * @param identity The (single) identity to always use.
	 * @param key The (single) key for the identity.
	 */
	public StaticPskStore(final String identity, final byte[] key) {
		this.fixedIdentity = identity;
		this.key = Arrays.copyOf(key, key.length);
	}

	@Override
	public String getIdentity(final InetSocketAddress inetAddress) {
		return fixedIdentity;
	}

	@Override
	public String getIdentity(InetSocketAddress peerAddress, ServerNames virtualHost) {
		return getIdentity(peerAddress);
	}

	@Override
	public byte[] getKey(final String identity) {
		return key;
	}

	@Override
	public byte[] getKey(final ServerNames serverNames, final String identity) {
		return getKey(identity);
	}
}
