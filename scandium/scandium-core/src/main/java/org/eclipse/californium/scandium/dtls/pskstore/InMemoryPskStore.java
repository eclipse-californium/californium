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
 * Kai Hudalla (Bosch Software Innovations GmbH) - fix formatting
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.pskstore;

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An in-memory pre-shared-key storage. 
 * If you don't need to initiate connection,
 * you could just add identity/key with {@link #setKey(String, byte[])}.
 * If you need to initiate connection, 
 * you should add known peers with {@link #addKnownPeer(InetSocketAddress, String, byte[])}.
 * 
 * To be used only for testing and evaluation. 
 * You are supposed to store your key in a secure way: 
 * keeping them in-memory is not a good idea.
 */
public class InMemoryPskStore implements PskStore {

	private Map<String, byte[]> keys = new ConcurrentHashMap<>();

	private Map<InetSocketAddress, String> knownPeers = new ConcurrentHashMap<>();

	@Override
	public byte[] getKey(String identity) {
		byte[] key = keys.get(identity);
		if (key == null) {
			return null;
		} else {
			// defensive copy
			return Arrays.copyOf(key, key.length);
		}
	}

	/**
	 * Set a key value for a given identity.
	 * 
	 * @param identity
	 *            the identity associated with the key
	 * @param key
	 *            the key used to authenticate the identity
	 */
	public void setKey(String identity, byte[] key) {
		keys.put(identity, key);
	}

	/**
	 * Add a known peer. Used when we need to initiate a connection.
	 * 
	 * @param peerAddress
	 *            address of known peer we need to connect to
	 * @param identity
	 *            identity used for this peer
	 * @param key
	 *            the key used for this the peer
	 */
	public void addKnownPeer(InetSocketAddress peerAddress, String identity, byte[] key) {
		knownPeers.put(peerAddress, identity);
		keys.put(identity, key);
	}

	@Override
	public String getIdentity(InetSocketAddress inetAddress) {
		return knownPeers.get(inetAddress);
	}
}