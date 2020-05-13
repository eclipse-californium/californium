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
package org.eclipse.californium.scandium.dtls;

import javax.crypto.SecretKey;

/**
 * Result of PSK secret.
 * 
 * On success contains the secret and a normalized psk identity. If failed, only
 * psk identity is contained. The secret must either be a master secret
 * (algorithm "MAC"), or a PSK secret key (algorithm "PSK").
 */
public class PskSecretResult {

	public static final String ALGORITHM_PSK = "PSK";
	public static final String ALGORITHM_MAC = "MAC";
	/**
	 * Connection id of the connection.
	 */
	private final ConnectionId cid;
	/**
	 * PSK indentity. On success, the identity is
	 * {@link PskPublicInformation#normalize(String)}d.
	 */
	private final PskPublicInformation pskIdentity;
	/**
	 * Master secret (algorithm "MAC"), or PSK secret key (algorithm "PSK").
	 */
	private final SecretKey secret;

	/**
	 * Create result.
	 * 
	 * @param cid connection id
	 * @param pskIdentity PSK identity
	 * @param secret secret, {@code null}, if generation failed. Algorithm must
	 *            be "MAC" or "PSK".
	 * @throws IllegalArgumentException if algorithm is neither "MAC" nor "PSK"
	 */
	public PskSecretResult(ConnectionId cid, PskPublicInformation pskIdentity, SecretKey secret) {
		if (secret != null) {
			String algorithm = secret.getAlgorithm();
			if (!ALGORITHM_MAC.equals(algorithm) && !ALGORITHM_PSK.equals(algorithm)) {
				throw new IllegalArgumentException(
						"Secret must be either MAC for master secret, or PSK for secret key, but not " + algorithm
								+ "!");
			}
		}
		this.cid = cid;
		this.pskIdentity = pskIdentity;
		this.secret = secret;
	}

	/**
	 * Get connection id.
	 * 
	 * @return connection id
	 */
	public ConnectionId getConnectionId() {
		return cid;
	}

	/**
	 * Get PSK identity.
	 * 
	 * On success, normalized.
	 * 
	 * @return SPK identity.
	 */
	public PskPublicInformation getPskPublicInformation() {
		return pskIdentity;
	}

	/**
	 * Get master secret (algorithm "MAC"), or PSK secret key (algorithm "PSK").
	 * 
	 * @return secret, {@code null}, if not available.
	 */
	public SecretKey getSecret() {
		return secret;
	}

}
