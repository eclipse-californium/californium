/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace raw public key flag
 *                                                    by certificate type
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
	 * Certificate type.
	 */
	private final CertificateType certificateType;

	/**
	 * Create handshake parameter.
	 * 
	 * @param keyExchange the key exchange algorithm
	 * @param certificateType the certificate type
	 * @throws NullPointerException if key exchange or certificate type is {@code null}
	 */
	public HandshakeParameter(KeyExchangeAlgorithm keyExchange, CertificateType certificateType) {
		if (keyExchange == null) {
			throw new NullPointerException("key exchange must not be null!");
		}
		if (certificateType == null) {
			throw new NullPointerException("certificate type must not be null!");
		}
		this.keyExchange = keyExchange;
		this.certificateType = certificateType;
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
	 * Get certificate type.
	 * 
	 * @return certificate type
	 */
	public CertificateType getCertificateType() {
		return certificateType;
	}

	public String toString() {
		return "KeyExgAl=" + keyExchange + ", cert.type=" + certificateType;
	}
}
