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

import org.eclipse.californium.scandium.auth.ApplicationLevelInfoSupplier;

/**
 * Result of PSK secret.
 * 
 * On success contains the secret and a normalized psk identity. If failed, only
 * psk identity is contained. The secret must either be a master secret
 * (algorithm "MAC"), or a PSK secret key (algorithm "PSK").
 * 
 * @since 2.3
 */
public class PskSecretResult extends HandshakeResult {

	public static final String ALGORITHM_PSK = "PSK";
	public static final String ALGORITHM_MAC = "MAC";
	/**
	 * PSK identity. On success, the identity is
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
	 * @throws NullPointerException if cid or pskIdentity is {@code null}
	 */
	public PskSecretResult(ConnectionId cid, PskPublicInformation pskIdentity, SecretKey secret) {
		this(cid, pskIdentity, secret, null);
	}

	/**
	 * Create result with custom argument for
	 * {@link ApplicationLevelInfoSupplier}.
	 * 
	 * @param cid connection id
	 * @param pskIdentity PSK identity
	 * @param secret secret, {@code null}, if generation failed. Algorithm must
	 *            be "MAC" or "PSK".
	 * @param customArgument custom argument. May be {@code null}. Passed to
	 *            {@link ApplicationLevelInfoSupplier} by the
	 *            {@link Handshaker}, if a
	 *            {@link ApplicationLevelInfoSupplier} is available.
	 * @throws IllegalArgumentException if algorithm is neither "MAC" nor "PSK"
	 * @throws NullPointerException if cid or pskIdentity is {@code null}
	 */
	public PskSecretResult(ConnectionId cid, PskPublicInformation pskIdentity, SecretKey secret,
			Object customArgument) {
		super(cid, customArgument);
		if (pskIdentity == null) {
			throw new NullPointerException("PSK identity must not be null!");
		}
		if (secret != null) {
			String algorithm = secret.getAlgorithm();
			if (!ALGORITHM_MAC.equals(algorithm) && !ALGORITHM_PSK.equals(algorithm)) {
				throw new IllegalArgumentException(
						"Secret must be either MAC for master secret, or PSK for secret key, but not " + algorithm
								+ "!");
			}
		}
		this.pskIdentity = pskIdentity;
		this.secret = secret;
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
