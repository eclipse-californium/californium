/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.pskstore;

import java.net.InetSocketAddress;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerName;
import org.eclipse.californium.scandium.util.ServerName.NameType;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * {@link AdvancedPskStore} implementation supporting multiple peers.
 * 
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
 * To be used only for testing and evaluation. You are supposed to store your
 * key in a secure way: keeping them in-memory is not a good idea.
 * </p>
 * 
 * @since 2.5
 */
public class AdvancedMultiPskStore implements AdvancedPskStore, Destroyable {

	private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

	@Override
	public boolean hasEcdhePskSupported() {
		return true;
	}

	@Override
	public PskSecretResult requestPskSecretResult(ConnectionId cid, ServerNames serverNames,
			PskPublicInformation identity, String hmacAlgorithm, SecretKey otherSecret, byte[] seed,
			boolean useExtendedMasterSecret) {

		PskCredentials credentials = getCredentials(serverNames, identity);
		if (credentials != null) {
			return new PskSecretResult(cid, credentials.getIdentity(), credentials.getKey());
		} else {
			return new PskSecretResult(cid, identity, null);
		}
	}

	/**
	 * Get credentials for server name and identity.
	 * 
	 * @param serverNames server name
	 * @param identity identity
	 * @return credentials, or {@code null}, if not available.
	 * @since 3.7
	 */
	private PskCredentials getCredentials(ServerNames serverNames, PskPublicInformation identity) {

		PskCredentials credentials = null;

		if (identity == null) {
			throw new NullPointerException("identity must not be null");
		} else {
			lock.readLock().lock();
			try {
				if (serverNames == null) {
					credentials = getPskCredentials(identity, scopedKeys.get(GLOBAL_SCOPE));
				} else {
					for (ServerName serverName : serverNames) {
						credentials = getPskCredentials(identity, scopedKeys.get(serverName));
						if (credentials != null) {
							break;
						}
					}
				}
			} finally {
				lock.readLock().unlock();
			}
		}
		return credentials;
	}

	@Override
	public PskPublicInformation getIdentity(InetSocketAddress peerAddress, ServerNames virtualHost) {
		if (peerAddress == null) {
			throw new NullPointerException("address must not be null");
		} else {
			lock.readLock().lock();
			try {
				if (virtualHost == null) {
					return getIdentityFromMap(GLOBAL_SCOPE, scopedIdentities.get(peerAddress));
				} else {
					for (ServerName serverName : virtualHost) {
						PskPublicInformation identity = getIdentityFromMap(serverName,
								scopedIdentities.get(peerAddress));
						if (identity != null) {
							return identity;
						}
					}
				}
			} finally {
				lock.readLock().unlock();
			}
		}
		return null;
	}

	@Override
	public void setResultHandler(HandshakeResultHandler resultHandler) {
		// empty implementation
	}

	@Override
	public void destroy() throws DestroyFailedException {
		lock.writeLock().lock();
		try {
			destroyed = true;
			scopedIdentities.clear();
			for (Map<PskPublicInformation, PskCredentials> keys : scopedKeys.values()) {
				for (PskCredentials credentials : keys.values()) {
					credentials.destroy();
				}
			}
			scopedKeys.clear();
		} finally {
			lock.writeLock().unlock();
		}
	}

	@Override
	public boolean isDestroyed() {
		return destroyed;
	}

	private static final ServerName GLOBAL_SCOPE = ServerName.from(NameType.UNDEFINED, Bytes.EMPTY);

	private static class PskCredentials implements Destroyable {

		private final PskPublicInformation identity;
		private final SecretKey key;

		private PskCredentials(PskPublicInformation identity, byte[] key) {
			this.identity = identity;
			this.key = SecretUtil.create(key, PskSecretResult.ALGORITHM_PSK);
		}

		public PskPublicInformation getIdentity() {
			return identity;
		}

		public SecretKey getKey() {
			return SecretUtil.create(key);
		}

		@Override
		public void destroy() throws DestroyFailedException {
			SecretUtil.destroy(key);
		}

		@Override
		public boolean isDestroyed() {
			return SecretUtil.isDestroyed(key);
		}
	}

	private final Map<ServerName, Map<PskPublicInformation, PskCredentials>> scopedKeys = new ConcurrentHashMap<>();
	private final Map<InetSocketAddress, Map<ServerName, PskPublicInformation>> scopedIdentities = new ConcurrentHashMap<>();
	private volatile boolean destroyed;

	private static PskCredentials getPskCredentials(final PskPublicInformation identity,
			final Map<PskPublicInformation, PskCredentials> keyMap) {

		if (keyMap != null) {
			return keyMap.get(identity);
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
	 * @see #setKey(PskPublicInformation, byte[], ServerName)
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
	 * @see #setKey(PskPublicInformation, byte[], ServerName)
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
	 * @see #setKey(PskPublicInformation, byte[], ServerName)
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
	 * @see #setKey(PskPublicInformation, byte[], ServerName)
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
			lock.writeLock().lock();
			try {
				Map<PskPublicInformation, PskCredentials> keysForServerName = scopedKeys.get(virtualHost);
				if (keysForServerName == null) {
					keysForServerName = new ConcurrentHashMap<>();
					scopedKeys.put(virtualHost, keysForServerName);
				}
				keysForServerName.put(identity, new PskCredentials(identity, key));
			} finally {
				lock.writeLock().unlock();
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
			lock.writeLock().lock();
			try {
				Map<ServerName, PskPublicInformation> identities = scopedIdentities.get(peerAddress);
				if (identities == null) {
					identities = new ConcurrentHashMap<>();
					scopedIdentities.put(peerAddress, identities);
				}
				identities.put(virtualHost, identity);
				setKey(identity, key, virtualHost);
			} finally {
				lock.writeLock().unlock();
			}
		}
	}

	/**
	 * Removes a key value for a given identity.
	 * 
	 * @param identity The identity to remove the key for.
	 * @see #removeKey(PskPublicInformation, ServerName)
	 */
	public void removeKey(final String identity) {
		removeKey(new PskPublicInformation(identity), GLOBAL_SCOPE);
	}

	/**
	 * Removes a key value for a given identity.
	 * 
	 * @param identity The identity to remove the key for.
	 * @see #removeKey(PskPublicInformation, ServerName)
	 */
	public void removeKey(final PskPublicInformation identity) {
		removeKey(identity, GLOBAL_SCOPE);
	}

	/**
	 * Removes a key for an identity scoped to a virtual host.
	 * 
	 * @param identity The identity to remove the key for.
	 * @param virtualHost The virtual host to associate the identity and key
	 *            with.
	 * @see #removeKey(PskPublicInformation, ServerName)
	 */
	public void removeKey(final String identity, final String virtualHost) {
		removeKey(new PskPublicInformation(identity), ServerName.fromHostName(virtualHost));
	}

	/**
	 * Removes a key for an identity scoped to a virtual host.
	 * 
	 * @param identity The identity to remove the key for.
	 * @param virtualHost The virtual host to associate the identity and key
	 *            with.
	 * @see #removeKey(PskPublicInformation, ServerName)
	 */
	public void removeKey(final PskPublicInformation identity, final String virtualHost) {
		removeKey(identity, ServerName.fromHostName(virtualHost));
	}

	/**
	 * Removes a key for an identity scoped to a virtual host.
	 * 
	 * @param identity The identity to remove the key for.
	 * @param virtualHost The virtual host to associate the identity with.
	 * @see #removeKey(PskPublicInformation, ServerName)
	 */
	public void removeKey(final String identity, final ServerName virtualHost) {
		removeKey(new PskPublicInformation(identity), virtualHost);
	}

	/**
	 * Removes a key for an identity scoped to a virtual host.
	 * 
	 * @param identity The identity to remove the key for.
	 * @param virtualHost The virtual host to associate the identity with.
	 */
	public void removeKey(final PskPublicInformation identity, final ServerName virtualHost) {

		if (identity == null) {
			throw new NullPointerException("identity must not be null");
		} else if (virtualHost == null) {
			throw new NullPointerException("serverName must not be null");
		} else {
			lock.writeLock().lock();
			try {
				Map<PskPublicInformation, PskCredentials> keysForServerName = scopedKeys.get(virtualHost);
				if (keysForServerName != null) {
					keysForServerName.remove(identity);
				}
			} finally {
				lock.writeLock().unlock();
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
