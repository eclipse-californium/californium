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
 * Kai Hudalla (Bosch Software Innovations GmbH) - fix formatting
 * Bosch Software Innovations GmbH - do not implement ServerNameResolver anymore
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.pskstore;

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.util.ServerName;
import org.eclipse.californium.scandium.util.ServerName.NameType;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * An in-memory pre-shared key storage.
 * <p>
 * If you don't need to initiate handshake/connection, you could just add
 * identity/key with {@link #setKey(String, byte[])} or
 * {@link #setKey(PskPublicInformation, byte[])}. If you need to initiate
 * connection, you should add known peers with
 * {@link #addKnownPeer(InetSocketAddress, String, byte[])} or
 * {@link #addKnownPeer(InetSocketAddress, PskPublicInformation, byte[])}.
 * </p>
 * <p>
 * If non-compliant encoded identities are used, please provide
 * {@link PskPublicInformation#PskPublicInformation(String, byte[])} identities
 * with the non-compliant encoded bytes and the intended string.
 * </p>
 * <p>
 * To be used only for testing and evaluation. 
 * You are supposed to store your key in a secure way:
 * keeping them in-memory is not a good idea.
 * </p>
 */
public class InMemoryPskStore implements PskStore {

	private static final ServerName GLOBAL_SCOPE = ServerName.from(NameType.UNDEFINED, Bytes.EMPTY);

	private static class Psk {

		private final PskPublicInformation identity;
		private final byte[] key;

		private Psk(PskPublicInformation identity, byte[] key) {
			this.identity = identity;
			this.key = Arrays.copyOf(key, key.length);
		}

		private byte[] getKey() {
			return Arrays.copyOf(key, key.length);
		}
	}

	private final Map<ServerName, Map<PskPublicInformation, Psk>> scopedKeys = new ConcurrentHashMap<>();
	private final Map<InetSocketAddress, Map<ServerName, PskPublicInformation>> scopedIdentities = new ConcurrentHashMap<>();

	@Override
	public byte[] getKey(final PskPublicInformation identity) {

		if (identity == null) {
			throw new NullPointerException("identity must not be null");
		} else {
			synchronized (scopedKeys) {
				return getKeyFromMapAndNormalizeIdentity(identity, scopedKeys.get(GLOBAL_SCOPE));
			}
		}
	}

	@Override
	public byte[] getKey(final ServerNames serverNames, final PskPublicInformation identity) {

		if (serverNames == null) {
			return getKey(identity);
		} else if (identity == null) {
			throw new NullPointerException("identity must not be null");
		} else {
			synchronized (scopedKeys) {
				for (ServerName serverName : serverNames) {
					return getKeyFromMapAndNormalizeIdentity(identity, scopedKeys.get(serverName));
				}
				return null;
			}
		}
	}

	private static byte[] getKeyFromMapAndNormalizeIdentity(final PskPublicInformation identity,
			final Map<PskPublicInformation, Psk> keyMap) {

		if (keyMap != null) {
			Psk psk = keyMap.get(identity);
			if (psk != null) {
				if (!psk.identity.isCompliantEncoding()) {
					identity.normalize(psk.identity.getPublicInfoAsString());
				}
				return psk.getKey();
			}
		}
		return null;
	}

	/**
	 * Sets a key value for a given identity.
	 * <p>
	 * If the key already exists, it will be replaced.
	 * </p>
	 * 
	 * @param identity the identity associated with the key
	 * @param key the key used to authenticate the identity
	 * @see #setKey(PskPublicInformation, byte[])
	 */
	public void setKey(final String identity, final byte[] key) {

		setKey(new PskPublicInformation(identity), key, GLOBAL_SCOPE);
	}

	/**
	 * Sets a key value for a given identity.
	 * <p>
	 * If the key already exists, it will be replaced.
	 * </p>
	 * 
	 * @param identity the identity associated with the key
	 * @param key the key used to authenticate the identity
	 * @see #setKey(String, byte[])
	 */
	public void setKey(final PskPublicInformation identity, final byte[] key) {

		setKey(identity, key, GLOBAL_SCOPE);
	}

	/**
	 * Sets a key for an identity scoped to a virtual host.
	 * <p>
	 * If the key already exists, it will be replaced.
	 * </p>
	 * 
	 * @param identity The identity to set the key for.
	 * @param key The key to set for the identity.
	 * @param virtualHost The virtual host to associate the identity and key
	 *            with.
	 * @see #setKey(PskPublicInformation, byte[], String)
	 */
	public void setKey(final String identity, final byte[] key, final String virtualHost) {
		setKey(new PskPublicInformation(identity), key, ServerName.fromHostName(virtualHost));
	}

	/**
	 * Sets a key for an identity scoped to a virtual host.
	 * <p>
	 * If the key already exists, it will be replaced.
	 * </p>
	 * 
	 * @param identity The identity to set the key for.
	 * @param key The key to set for the identity.
	 * @param virtualHost The virtual host to associate the identity and key
	 *            with.
	 * @see #setKey(String, byte[], String)
	 */
	public void setKey(final PskPublicInformation identity, final byte[] key, final String virtualHost) {
		setKey(identity, key, ServerName.fromHostName(virtualHost));
	}

	/**
	 * Sets a key for an identity scoped to a virtual host.
	 * <p>
	 * If the key already exists, it will be replaced.
	 * </p>
	 * 
	 * @param identity The identity to set the key for.
	 * @param key The key to set for the identity.
	 * @param virtualHost The virtual host to associate the identity and key
	 *            with.
	 * @see #setKey(PskPublicInformation, byte[], ServerName)
	 */
	public void setKey(final String identity, final byte[] key, final ServerName virtualHost) {
		setKey(new PskPublicInformation(identity), key, virtualHost);
	}

	/**
	 * Sets a key for an identity scoped to a virtual host.
	 * <p>
	 * If the key already exists, it will be replaced.
	 * </p>
	 * 
	 * @param identity The identity to set the key for.
	 * @param key The key to set for the identity.
	 * @param virtualHost The virtual host to associate the identity and key
	 *            with.
	 * @see #setKey(String, byte[], ServerName)
	 */
	public void setKey(final PskPublicInformation identity, final byte[] key, final ServerName virtualHost) {

		if (identity == null) {
			throw new NullPointerException("identity must not be null");
		} else if (key == null) {
			throw new NullPointerException("key must not be null");
		} else if (virtualHost == null) {
			throw new NullPointerException("serverName must not be null");
		} else {
			synchronized (scopedKeys) {
				Map<PskPublicInformation, Psk> keysForServerName = scopedKeys.get(virtualHost);
				if (keysForServerName == null) {
					keysForServerName = new ConcurrentHashMap<>();
					scopedKeys.put(virtualHost, keysForServerName);
				}
				keysForServerName.put(identity, new Psk(identity, key));
			}
		}
	}

	/**
	 * Adds a shared key for a peer.
	 * <p>
	 * If the key already exists, it will be replaced.
	 * </p>
	 * 
	 * @param peerAddress the IP address and port to use the key for
	 * @param identity the PSK identity
	 * @param key the shared key
	 * @throws NullPointerException if any of the parameters are {@code null}.
	 * @see #addKnownPeer(InetSocketAddress, PskPublicInformation, byte[])
	 */
	public void addKnownPeer(final InetSocketAddress peerAddress, final String identity, final byte[] key) {
		addKnownPeer(peerAddress, GLOBAL_SCOPE, new PskPublicInformation(identity), key);
	}

	/**
	 * Adds a shared key for a peer.
	 * <p>
	 * If the key already exists, it will be replaced.
	 * </p>
	 * 
	 * @param peerAddress the IP address and port to use the key for
	 * @param identity the PSK identity
	 * @param key the shared key
	 * @throws NullPointerException if any of the parameters are {@code null}.
	 * @see #addKnownPeer(InetSocketAddress, String, byte[])
	 */
	public void addKnownPeer(final InetSocketAddress peerAddress, final PskPublicInformation identity,
			final byte[] key) {

		addKnownPeer(peerAddress, GLOBAL_SCOPE, identity, key);
	}

	/**
	 * Adds a shared key for a virtual host on a peer.
	 * <p>
	 * If the key already exists, it will be replaced. serverNames
	 * </p>
	 * 
	 * @param peerAddress the IP address and port to use the key for
	 * @param virtualHost the virtual host to use the key for
	 * @param identity the PSK identity
	 * @param key the shared key
	 * @throws NullPointerException if any of the parameters are {@code null}.
	 * @see #addKnownPeer(InetSocketAddress, String, PskPublicInformation,
	 *      byte[])
	 */
	public void addKnownPeer(final InetSocketAddress peerAddress, final String virtualHost, final String identity,
			final byte[] key) {
		addKnownPeer(peerAddress, ServerName.fromHostName(virtualHost), new PskPublicInformation(identity), key);
	}

	/**
	 * Adds a shared key for a virtual host on a peer.
	 * <p>
	 * If the key already exists, it will be replaced. serverNames
	 * </p>
	 * 
	 * @param peerAddress the IP address and port to use the key for
	 * @param virtualHost the virtual host to use the key for
	 * @param identity the PSK identity
	 * @param key the shared key
	 * @throws NullPointerException if any of the parameters are {@code null}.
	 * @see #addKnownPeer(InetSocketAddress, String, String, byte[])
	 */
	public void addKnownPeer(final InetSocketAddress peerAddress, final String virtualHost,
			final PskPublicInformation identity, final byte[] key) {

		addKnownPeer(peerAddress, ServerName.fromHostName(virtualHost), identity, key);
	}

	private void addKnownPeer(final InetSocketAddress peerAddress, final ServerName virtualHost,
			final PskPublicInformation identity, final byte[] key) {

		if (peerAddress == null) {
			throw new NullPointerException("peer address must not be null");
		} else if (virtualHost == null) {
			throw new NullPointerException("virtual host must not be null");
		} else if (identity == null) {
			throw new NullPointerException("identity must not be null");
		} else if (key == null) {
			throw new NullPointerException("key must not be null");
		} else {
			synchronized (scopedKeys) {
				Map<ServerName, PskPublicInformation> identities = scopedIdentities.get(peerAddress);
				if (identities == null) {
					identities = new ConcurrentHashMap<>();
					scopedIdentities.put(peerAddress, identities);
				}
				identities.put(virtualHost, identity);
				setKey(identity, key, virtualHost);
			}
		}
	}

	@Override
	public PskPublicInformation getIdentity(final InetSocketAddress peerAddress) {

		if (peerAddress == null) {
			throw new NullPointerException("address must not be null");
		} else {
			synchronized (scopedKeys) {
				return getIdentityFromMap(GLOBAL_SCOPE, scopedIdentities.get(peerAddress));
			}
		}
	}

	@Override
	public PskPublicInformation getIdentity(final InetSocketAddress peerAddress, final ServerNames virtualHost) {

		if (virtualHost == null) {
			return getIdentity(peerAddress);
		} else if (peerAddress == null) {
			throw new NullPointerException("address must not be null");
		} else {
			synchronized (scopedKeys) {
				for (ServerName serverName : virtualHost) {
					PskPublicInformation identity = getIdentityFromMap(serverName, scopedIdentities.get(peerAddress));
					if (identity != null) {
						return identity;
					}
				}
				return null;
			}
		}
	}

	private static PskPublicInformation getIdentityFromMap(final ServerName virtualHost,
			final Map<ServerName, PskPublicInformation> identities) {

		if (identities != null) {
			return identities.get(virtualHost);
		} else {
			return null;
		}
	}
}
