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

import org.eclipse.californium.scandium.dtls.ServerNameResolver;
import org.eclipse.californium.scandium.util.ServerName;
import org.eclipse.californium.scandium.util.ServerNames;

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
public class InMemoryPskStore implements PskStore, ServerNameResolver {

	private final Map<ServerName, Map<String, byte[]>> scopedKeys = new ConcurrentHashMap<>();
	private final Map<String, byte[]> keys = new ConcurrentHashMap<>();
	private final Map<InetSocketAddress, String> identitiesByAddress = new ConcurrentHashMap<>();
	private final Map<InetSocketAddress, ServerNames> serverNamesByAddress = new ConcurrentHashMap<>();

	@Override
	public byte[] getKey(final String identity) {

		if (identity == null) {
			throw new NullPointerException("identity must not be null");
		} else {
			return getKeyFromMap(identity, keys);
		}
	}

	private static byte[] getKeyFromMap(final String identity, final Map<String, byte[]> keyMap) {

		byte[] result = null;
		if (keyMap != null) {
			byte[] key = keyMap.get(identity);
			if (key != null) {
				// defensive copy
				result = Arrays.copyOf(key, key.length);
			}
		}
		return result;
	}

	@Override
	public byte[] getKey(final ServerNames serverNames, final String identity) {

		if (serverNames == null) {
			throw new NullPointerException("server names must not be null");
		} else if (identity == null) {
			throw new NullPointerException("identity must not be null");
		} else {
			synchronized (scopedKeys) {
				for (ServerName serverName : serverNames) {
					byte[] key = getKeyFromMap(identity, scopedKeys.get(serverName));
					if (key != null) {
						return key;
					}
				}
				return null;
			}
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
	public void setKey(final String identity, final byte[] key) {

		keys.put(identity, Arrays.copyOf(key, key.length));
	}

	/**
	 * Sets a key for an identity scoped to a server name.
	 * 
	 * @param identity The identity to set the key for.
	 * @param key The key to set for the identity.
	 * @param serverName The server name to associate the identity and key with.
	 */
	public void setKey(final String identity, final byte[] key, final ServerName serverName) {

		if (identity == null) {
			throw new NullPointerException("identity must not be null");
		} else if (key == null) {
			throw new NullPointerException("key must not be null");
		} else if (serverName == null) {
			throw new NullPointerException("serverName must not be null");
		} else {
			synchronized (scopedKeys) {
				Map<String, byte[]> keysForServerName = scopedKeys.get(serverName);
				if (keysForServerName == null) {
					keysForServerName = new ConcurrentHashMap<>();
					scopedKeys.put(serverName, keysForServerName);
				}
				keysForServerName.put(identity, Arrays.copyOf(key, key.length));
			}
		}
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
	public void addKnownPeer(final InetSocketAddress peerAddress, final String identity, final byte[] key) {

		identitiesByAddress.put(peerAddress, identity);
		setKey(identity, key);
	}

	/**
	 * Adds server names for a given peer.
	 * <p>
	 * This method replaces any existing mapping for the peer address.
	 * 
	 * @param peerAddress The IP address of the peer.
	 * @param serverNames The server names to include in the SNI extension.
	 */
	public void addServerNames(final InetSocketAddress peerAddress, final ServerNames serverNames) {

		if (peerAddress != null && serverNames != null) {
			this.serverNamesByAddress.put(peerAddress, serverNames);
		}
	}

	@Override
	public String getIdentity(final InetSocketAddress inetAddress) {

		if (inetAddress == null) {
			throw new NullPointerException("address must not be null");
		} else {
			return identitiesByAddress.get(inetAddress);
		}
	}

	@Override
	public ServerNames getServerNames(final InetSocketAddress peerAddress) {

		if (peerAddress == null) {
			return null;
		} else {
			return serverNamesByAddress.get(peerAddress);
		}
	}
}