/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;

/**
 * Handshake parameter.
 * 
 * Parameter which are defined by exchanged handshake messages and are used to
 * decode other handshake messages.
 */
public class HandshakeParameter {

	/**
	 * Key exchange algorithm.
	 */
	private final KeyExchangeAlgorithm keyExchange;
	/**
	 * Indicate to use raw public keys certificates.
	 */
	private final boolean useRawPublicKey;

	/**
	 * Create handshake parameter.
	 * 
	 * @param keyExchange the key exchange algorithm
	 * @param useRawPublicKey {@code true} to use raw public keys certificates,
	 *            {@cod false}, otherwise.
	 * @throws NullPointerException if key exchange is {@link null}
	 */
	public HandshakeParameter(KeyExchangeAlgorithm keyExchange, boolean useRawPublicKey) {
		if (keyExchange == null) {
			throw new NullPointerException("key exchange must not be null!");
		}
		this.keyExchange = keyExchange;
		this.useRawPublicKey = useRawPublicKey;
	}

	/**
	 * Get key exchange algorithm.
	 * 
	 * @return key exchange algorithm
	 */
	public KeyExchangeAlgorithm getKeyExchangeAlgorithm() {
		return keyExchange;
	}

	/**
	 * Indicate to use raw public key certificates.
	 * 
	 * @return {@code true} to use use raw public key certificates,
	 *         {@code false} otherwise.
	 */
	public boolean useRawPublicKey() {
		return useRawPublicKey;
	}

	public String toString() {
		return "KeyExgAl=" + keyExchange + ", " + (useRawPublicKey ? "RPK" : "x.509");
	}
}
