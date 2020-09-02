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
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.dtls.PskSecretResultHandler;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * Adapter to use custom implementations of the deprecated {@link PskStore}
 * until having them migrated.
 * 
 * Delegates lookups to provided {@link PskStore}.
 * 
 * @since 2.5
 */
@SuppressWarnings("deprecation")
public class BridgePskStore implements AdvancedPskStore {

	protected final PskStore pskStore;

	/**
	 * Create an advanced pskstore from {@link PskStore}.
	 * 
	 * @param pskStore psk store
	 * @throws NullPointerException if store is {@code null}
	 */
	public BridgePskStore(PskStore pskStore) {
		if (pskStore == null) {
			throw new NullPointerException("PSK store must not be null!");
		}
		this.pskStore = pskStore;
	}

	@Override
	public boolean hasEcdhePskSupported() {
		return true;
	}

	@Override
	public PskSecretResult requestPskSecretResult(ConnectionId cid, ServerNames serverNames,
			PskPublicInformation identity, String hmacAlgorithm, SecretKey otherSecret, byte[] seed) {
		SecretKey secret = serverNames != null ? pskStore.getKey(serverNames, identity) : pskStore.getKey(identity);
		return new PskSecretResult(cid, identity, secret);
	}

	@Override
	public PskPublicInformation getIdentity(InetSocketAddress peerAddress, ServerNames virtualHost) {
		return virtualHost != null ? pskStore.getIdentity(peerAddress, virtualHost) : pskStore.getIdentity(peerAddress);
	}

	@Override
	public void setResultHandler(PskSecretResultHandler resultHandler) {
		// empty implementation
	}
}
