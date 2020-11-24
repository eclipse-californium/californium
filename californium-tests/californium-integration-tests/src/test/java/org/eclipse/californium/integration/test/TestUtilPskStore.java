/*******************************************************************************
 * Copyright (c) 2017, 2018 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation.
 ******************************************************************************/

package org.eclipse.californium.integration.test;

import java.net.InetSocketAddress;

import javax.crypto.SecretKey;

import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedPskStore;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * Simple {@link PskStore} implementation with exchangeable credentials and
 * catch all function.
 */
public class TestUtilPskStore implements AdvancedPskStore {
	/**
	 * Returns secret for all identities.
	 * 
	 * @since 2.5
	 */
	private boolean catchAll;
	/**
	 * PSK identity.
	 */
	private PskPublicInformation identity;
	/**
	 * PSK secret key.
	 */
	private SecretKey secret;

	/**
	 * Create simple store.
	 */
	public TestUtilPskStore() {
	}

	/**
	 * Exchange credentials.
	 * 
	 * @param identity PSK identity
	 * @param key      PSK secret key
	 */
	public synchronized void set(String identity, byte[] key) {
		this.identity = new PskPublicInformation(identity);
		SecretUtil.destroy(this.secret);
		this.secret = SecretUtil.create(key, "PSK");
	}

	/**
	 * Set catch all identities.
	 * 
	 * Returns always the secret regardless of the identity.
	 * 
	 * @param all {@code true}, enable catch all, {@code false}, disable it
	 * @since 2.5
	 */
	public synchronized void setCatchAll(boolean all) {
		this.catchAll = all;
	}

	@Override
	public boolean hasEcdhePskSupported() {
		return true;
	}

	@Override
	public PskSecretResult requestPskSecretResult(ConnectionId cid, ServerNames serverName,
			PskPublicInformation identity, String hmacAlgorithm, SecretKey otherSecret, byte[] seed, boolean useExtendedMasterSecret) {
		SecretKey secret = null;
		PskPublicInformation pskIdentity = identity;
		synchronized (this) {
			if (this.identity != null && this.identity.equals(identity)) {
				pskIdentity = this.identity;
				secret = SecretUtil.create(this.secret);
			} else if (this.catchAll) {
				secret = SecretUtil.create(this.secret);
			}
		}
		return new PskSecretResult(cid, pskIdentity, secret);
	}

	@Override
	public synchronized PskPublicInformation getIdentity(InetSocketAddress peerAddress, ServerNames virtualHost) {
		return identity;
	}

	@Override
	public void setResultHandler(HandshakeResultHandler resultHandler) {
	}
}
