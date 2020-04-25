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

import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.dtls.PskSecretResultHandler;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalCryptoMap;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalCryptoMap.Factory;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalMac;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * Simple in-memory example implementation of {@link AdvancedPskStore}.
 * 
 * Delegates calls to {@link PskStore}.
 */
public class AdvancedInMemoryPskStore implements AdvancedPskStore {

	protected static final ThreadLocalCryptoMap<ThreadLocalMac> MAC = new ThreadLocalCryptoMap<>(
			new Factory<ThreadLocalMac>() {

				@Override
				public ThreadLocalMac getInstance(String algorithm) {
					return new ThreadLocalMac(algorithm);
				}
			});

	protected final PskStore pskStore;
	protected final boolean master;

	/**
	 * Create an advanced pskstore from {@link PskStore}.
	 * 
	 * @param pskStore psk store
	 * @throws NullPointerException if store is {@code null}
	 */
	public AdvancedInMemoryPskStore(PskStore pskStore) {
		if (pskStore == null) {
			throw new NullPointerException("PSK store must not be null!");
		}
		this.pskStore = pskStore;
		this.master = true;
	}

	/**
	 * Create an advanced pskstore from {@link PskStore}.
	 * 
	 * @param pskStore psk store
	 * @param master {@code true}, return master secret, {@code false}, return
	 *            PSK secret key.
	 * @throws NullPointerException if store is {@code null}
	 */
	public AdvancedInMemoryPskStore(PskStore pskStore, boolean master) {
		if (pskStore == null) {
			throw new NullPointerException("PSK store must not be null!");
		}
		this.pskStore = pskStore;
		this.master = master;
	}

	@Override
	public boolean hasEcdhePskSupported() {
		return true;
	}

	@Override
	public PskSecretResult generateMasterSecret(ConnectionId cid, ServerNames serverNames,
			PskPublicInformation identity, String hmacAlgorithm, SecretKey otherSecret, byte[] seed) {
		PskSecretResult result;
		SecretKey pskSecret = serverNames != null ? pskStore.getKey(serverNames, identity) : pskStore.getKey(identity);
		if (master && pskSecret != null) {
			ThreadLocalMac hmac = MAC.get(hmacAlgorithm);
			SecretKey premasterSecret = PseudoRandomFunction.generatePremasterSecretFromPSK(otherSecret, pskSecret);
			SecretKey masterSecret = PseudoRandomFunction.generateMasterSecret(hmac.current(), premasterSecret, seed);
			SecretUtil.destroy(premasterSecret);
			SecretUtil.destroy(pskSecret);
			result = new PskSecretResult(cid, identity, masterSecret);
		} else {
			result = new PskSecretResult(cid, identity, pskSecret);
		}
		return result;
	}

	@Override
	public PskPublicInformation getIdentity(InetSocketAddress peerAddress, ServerNames virtualHost) {
		return virtualHost != null ? pskStore.getIdentity(peerAddress, virtualHost) : pskStore.getIdentity(peerAddress);
	}

	@Override
	public void setResultHandler(PskSecretResultHandler resultHandler) {
	}
}
