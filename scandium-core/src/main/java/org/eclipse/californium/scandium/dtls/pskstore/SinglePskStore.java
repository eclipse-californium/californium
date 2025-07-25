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

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * {@link PskStore} implementation for clients to connect a single other
 * peer.
 * 
 * @since 4.0 (Renamed AdvancedSinglePskStore into SinglePskStore)
 */
public class SinglePskStore implements PskStore, Destroyable {

	/**
	 * PSK identity.
	 */
	private final PskPublicInformation identity;
	/**
	 * PSK secret key.
	 */
	private final SecretKey secret;

	/**
	 * Create simple store with initial credentials.
	 * 
	 * @param identity PSK identity
	 * @param key PSK secret key
	 */
	public SinglePskStore(String identity, byte[] key) {
		this(new PskPublicInformation(identity), key);
	}

	/**
	 * Create simple store with initial credentials.
	 * 
	 * @param identity PSK identity
	 * @param key PSK secret key
	 */
	public SinglePskStore(PskPublicInformation identity, byte[] key) {
		this.identity = identity;
		this.secret = SecretUtil.create(key, "PSK");
	}

	/**
	 * Create simple store with initial credentials.
	 * 
	 * @param identity PSK identity
	 * @param key PSK secret key
	 */
	public SinglePskStore(String identity,SecretKey key) {
		this(new PskPublicInformation(identity), key);
	}

	/**
	 * Create simple store with initial credentials.
	 * 
	 * @param identity PSK identity
	 * @param key PSK secret key
	 */
	public SinglePskStore(PskPublicInformation identity, SecretKey key) {
		this.identity = identity;
		this.secret = SecretUtil.create(key);
	}

	@Override
	public boolean hasEcdhePskSupported() {
		return true;
	}

	@Override
	public PskSecretResult requestPskSecretResult(ConnectionId cid, ServerNames serverName,
			PskPublicInformation identity, String hmacAlgorithm, SecretKey otherSecret, byte[] seed, boolean useExtendedMasterSecret) {
		SecretKey secret = null;
		if (this.identity.equals(identity)) {
			secret = this.secret;
		}
		return new PskSecretResult(cid, this.identity, secret, false, false);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Ignores arguments, though only a single destination peers is supported.
	 */
	@Override
	public PskPublicInformation getIdentity(InetSocketAddress peerAddress, ServerNames virtualHost) {
		return identity;
	}

	@Override
	public void setResultHandler(HandshakeResultHandler resultHandler) {
		// empty implementation
	}

	@Override
	public void destroy() throws DestroyFailedException {
		SecretUtil.destroy(secret);
	}

	@Override
	public boolean isDestroyed() {
		return SecretUtil.isDestroyed(secret);
	}
}
