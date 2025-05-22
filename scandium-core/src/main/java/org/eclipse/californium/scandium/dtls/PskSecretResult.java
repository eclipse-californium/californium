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

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.eclipse.californium.scandium.auth.ApplicationLevelInfoSupplier;
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalCryptoMap;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalCryptoMap.Factory;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalMac;
import org.eclipse.californium.scandium.util.SecretUtil;

/**
 * Result of PSK secret.
 * <p>
 * On success contains the secret and a normalized psk identity. If failed, only
 * psk identity is contained. The secret will either be a master secret or a PSK
 * secret key.
 * 
 * @since 4.0 implements {@link Destroyable}
 */
public class PskSecretResult extends HandshakeResult implements Destroyable {

	/**
	 * Algorithm for PSK secret.
	 * 
	 * @since 4.0 not longer required.
	 */
	public static final String ALGORITHM_PSK = "PSK";
	/**
	 * Algorithm for master secret.
	 * 
	 * @since 4.0 not longer required.
	 */
	public static final String ALGORITHM_MAC = "MAC";

	private static final ThreadLocalCryptoMap<ThreadLocalMac> MAC = new ThreadLocalCryptoMap<>(
			new Factory<ThreadLocalMac>() {

				@Override
				public ThreadLocalMac getInstance(String algorithm) {
					return new ThreadLocalMac(algorithm);
				}
			});

	/**
	 * PSK identity. On success, the identity is
	 * {@link PskPublicInformation#normalize(String)}d.
	 */
	private final PskPublicInformation pskIdentity;
	/**
	 * Master secret or PSK secret key.
	 */
	private final SecretKey secret;
	/**
	 * {@link #secret} contains master secret.
	 * 
	 * @since 4.0
	 */
	private final boolean masterSecret;
	/**
	 * Destroy {@link #secret} on {@link #destroy()}.
	 * 
	 * Cleanup generated keying material.
	 * 
	 * @since 4.0
	 */
	private final boolean destroy;

	/**
	 * Create result.
	 * 
	 * @param cid connection id
	 * @param pskIdentity PSK identity
	 * @param secret secret, or {@code null}, if generation failed.
	 * @param masterSecret {@code true} if secret contains master secret,
	 *            {@code true} if secret contains PSK secret.
	 * @param destroy {@code true} to destroy secret key with {@link #destroy()}
	 *            after usage. Intended to cleanup generated secrets.
	 * @throws NullPointerException if cid or pskIdentity is {@code null}
	 * @since 4.0 (Parameters {@code masterSecret} and {@code destroy} added.)
	 */
	public PskSecretResult(ConnectionId cid, PskPublicInformation pskIdentity, SecretKey secret, boolean masterSecret,
			boolean destroy) {
		this(cid, pskIdentity, secret, null, masterSecret, destroy);
	}

	/**
	 * Create result with custom argument for
	 * {@link ApplicationLevelInfoSupplier}.
	 * 
	 * @param cid connection id
	 * @param pskIdentity PSK identity
	 * @param secret secret, {@code null}, if generation failed.
	 * @param customArgument custom argument. Must be {@code null}, if secret is
	 *            {@code null}. May be {@code null}. Passed to
	 *            {@link ApplicationLevelInfoSupplier} by the
	 *            {@link Handshaker}, if a {@link ApplicationLevelInfoSupplier}
	 *            is available.
	 * @param masterSecret {@code true} if secret contains master secret,
	 *            {@code true} if secret contains PSK secret.
	 * @param destroy {@code true} to destroy secret key with {@link #destroy()}
	 *            after usage. Intended to cleanup generated secrets.
	 * @throws IllegalArgumentException if a custom argument is provided without
	 *             a secret
	 * @throws NullPointerException if cid or pskIdentity is {@code null}
	 * @since 4.0 (throws IllegalArgumentException, when a custom argument is
	 *        provided without a secret. Parameters {@code masterSecret} and
	 *        {@code destroy} added.)
	 */
	public PskSecretResult(ConnectionId cid, PskPublicInformation pskIdentity, SecretKey secret, Object customArgument,
			boolean masterSecret, boolean destroy) {
		super(cid, customArgument);
		if (pskIdentity == null) {
			throw new NullPointerException("PSK identity must not be null!");
		}
		if (secret == null && customArgument != null) {
			throw new IllegalArgumentException("Custom argument must be null, if no secret is provided!");
		}
		this.pskIdentity = pskIdentity;
		this.secret = secret;
		this.masterSecret = masterSecret && secret != null;
		this.destroy = destroy && secret != null;
	}

	/**
	 * Create failed result.
	 * 
	 * @param cid connection id
	 * @param pskIdentity PSK identity
	 * @throws NullPointerException if cid or pskIdentity is {@code null}
	 * @since 4.0
	 */
	public PskSecretResult(ConnectionId cid, PskPublicInformation pskIdentity) {
		this(cid, pskIdentity, null, null, false, false);
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
	 * Checks, if the secret contains the master secret.
	 * 
	 * @return {@code true}, if the secret contains the master secret.
	 * @since 4.0
	 */
	public boolean isMasterSecret() {
		return masterSecret;
	}

	/**
	 * Checks, if the secret contains the PSK secret.
	 * 
	 * @return {@code true}, if the secret contains the PSK secret.
	 * @since 4.0
	 */
	public boolean isPskSecret() {
		return !masterSecret && secret != null;
	}

	/**
	 * Get master secret or PSK secret key.
	 * 
	 * @return secret, {@code null}, if not available.
	 * 
	 * @since 4.0 this returns not longer a copy of the secret. Therefore do not
	 *        {@code destroy} the returned key but instead this result itself.
	 */
	public SecretKey getSecret() {
		return secret;
	}

	/**
	 * Generate master secret.
	 * 
	 * @param hmacAlgorithm hmac algorithm name
	 * @param otherSecret other secret derived from the EC Diffie-Hellman
	 *            exchange (ECDHE_PSK). Or {@code null} for plain PSK exchanges.
	 * @param seed the seed to use for creating the master secret
	 * @param useExtendedMasterSecret {@code true} to use the extended variant
	 *            of the master secret
	 * @return generated master secret.
	 * @throws IllegalStateException if secret is already master secret.
	 * @since 4.0
	 */
	public SecretKey generateMasterSecret(String hmacAlgorithm, SecretKey otherSecret, byte[] seed,
			boolean useExtendedMasterSecret) {
		if (masterSecret) {
			throw new IllegalStateException("Secret is already master secret!");
		}
		return generateMasterSecret(hmacAlgorithm, secret, otherSecret, seed, useExtendedMasterSecret);
	}

	/**
	 * Generate master secret.
	 * 
	 * @param hmac MAC algorithm. e.g. HmacSHA256
	 * @param otherSecret other secret derived from the EC Diffie-Hellman
	 *            exchange (ECDHE_PSK). Or {@code null} for plain PSK exchanges.
	 * @param seed the seed to use for creating the master secret
	 * @param useExtendedMasterSecret {@code true} to use the extended variant
	 *            of the master secret
	 * @return generated master secret.
	 * @throws IllegalStateException if secret is already master secret.
	 * @since 4.0
	 */
	public SecretKey generateMasterSecret(Mac hmac, SecretKey otherSecret, byte[] seed,
			boolean useExtendedMasterSecret) {
		if (masterSecret) {
			throw new IllegalStateException("Secret is already master secret!");
		}
		return generateMasterSecret(hmac, secret, otherSecret, seed, useExtendedMasterSecret);
	}

	/**
	 * {@inheritDoc}.
	 * 
	 * Cleanup generated key, if {@code destroy} has been provided in
	 * {@link #PskSecretResult}.
	 * 
	 * @since 4.0
	 */
	@Override
	public void destroy() throws DestroyFailedException {
		if (destroy) {
			SecretUtil.destroy(secret);
		}
	}

	@Override
	public boolean isDestroyed() {
		return SecretUtil.isDestroyed(secret);
	}

	/**
	 * Generate master secret.
	 * 
	 * @param hmacAlgorithm hmac algorithm name
	 * @param pskSecret psk secret
	 * @param otherSecret other secret derived from the EC Diffie-Hellman
	 *            exchange (ECDHE_PSK). Or {@code null} for plain PSK exchanges.
	 * @param seed the seed to use for creating the master secret
	 * @param useExtendedMasterSecret {@code true} to use the extended variant
	 *            of the master secret
	 * @return generated master secret.
	 * @since 4.0
	 */
	public static SecretKey generateMasterSecret(String hmacAlgorithm, SecretKey pskSecret, SecretKey otherSecret,
			byte[] seed, boolean useExtendedMasterSecret) {
		return generateMasterSecret(MAC.get(hmacAlgorithm).current(), pskSecret, otherSecret, seed,
				useExtendedMasterSecret);
	}

	/**
	 * Generate master secret.
	 * 
	 * @param hmac MAC algorithm. e.g. HmacSHA256
	 * @param pskSecret psk secret
	 * @param otherSecret other secret derived from the EC Diffie-Hellman
	 *            exchange (ECDHE_PSK). Or {@code null} for plain PSK exchanges.
	 * @param seed the seed to use for creating the master secret
	 * @param useExtendedMasterSecret {@code true} to use the extended variant
	 *            of the master secret
	 * @return generated master secret.
	 * @since 4.0
	 */
	public static SecretKey generateMasterSecret(Mac hmac, SecretKey pskSecret, SecretKey otherSecret, byte[] seed,
			boolean useExtendedMasterSecret) {
		SecretKey premasterSecret = PseudoRandomFunction.generatePremasterSecretFromPSK(otherSecret, pskSecret);
		SecretKey masterSecret = PseudoRandomFunction.generateMasterSecret(hmac, premasterSecret, seed,
				useExtendedMasterSecret);
		SecretUtil.destroy(premasterSecret);
		return masterSecret;
	}

}
