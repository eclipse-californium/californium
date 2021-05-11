/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import org.eclipse.californium.scandium.auth.ApplicationLevelInfoSupplier;
import org.eclipse.californium.scandium.dtls.x509.CertificateProvider;

/**
 * Result of certificate identity provider.
 * 
 * @see CertificateProvider
 * @since 3.0
 */
public final class CertificateIdentityResult extends HandshakeResult {

	private final PrivateKey privateKey;
	private final PublicKey publicKey;
	private final List<X509Certificate> certificateChain;

	/**
	 * Create result with {@link X509Certificate}.
	 * 
	 * @param cid connection id
	 * @param privateKey private key of identity.
	 * @param certificateChain certificate chain for identity
	 * @param customArgument custom argument. May be {@code null}. Passed to
	 *            {@link ApplicationLevelInfoSupplier} by the
	 *            {@link Handshaker}, if a {@link ApplicationLevelInfoSupplier}
	 *            is available.
	 * @throws NullPointerException if cid, private key, or chain is
	 *             {@code null}.
	 * @throws IllegalArgumentException if chain is empty.
	 */
	public CertificateIdentityResult(ConnectionId cid, PrivateKey privateKey, List<X509Certificate> certificateChain,
			Object customArgument) {
		super(cid, customArgument);
		if (privateKey == null) {
			throw new NullPointerException("Private key must not be null!");
		}
		if (certificateChain == null) {
			throw new NullPointerException("Certificate chain must not be null!");
		}
		if (certificateChain.isEmpty()) {
			throw new IllegalArgumentException("Certificate chain must not be empty!");
		}
		this.privateKey = privateKey;
		this.publicKey = certificateChain.get(0).getPublicKey();
		this.certificateChain = certificateChain;
	}

	/**
	 * Create result with RawPublicKey.
	 * 
	 * @param cid connection id
	 * @param privateKey private key of identity.
	 * @param publicKey public key for identity
	 * @param customArgument custom argument. May be {@code null}. Passed to
	 *            {@link ApplicationLevelInfoSupplier} by the
	 *            {@link Handshaker}, if a {@link ApplicationLevelInfoSupplier}
	 *            is available.
	 * @throws NullPointerException if cid, private key, or public key is
	 *             {@code null}.
	 */
	public CertificateIdentityResult(ConnectionId cid, PrivateKey privateKey, PublicKey publicKey,
			Object customArgument) {
		super(cid, customArgument);
		if (privateKey == null) {
			throw new NullPointerException("Private key must not be null!");
		}
		if (publicKey == null) {
			throw new NullPointerException("Public key must not be null!");
		}
		this.privateKey = privateKey;
		this.publicKey = publicKey;
		this.certificateChain = null;
	}

	/**
	 * Create result without matching identity.
	 * 
	 * @param cid connection id
	 * @param customArgument custom argument. May be {@code null}. Passed to
	 *            {@link ApplicationLevelInfoSupplier} by the
	 *            {@link Handshaker}, if a {@link ApplicationLevelInfoSupplier}
	 *            is available.
	 * @throws NullPointerException if cid is {@code null}.
	 */
	public CertificateIdentityResult(ConnectionId cid, Object customArgument) {
		super(cid, customArgument);
		this.privateKey = null;
		this.publicKey = null;
		this.certificateChain = null;
	}

	/**
	 * Get private key of certificate based identity
	 * 
	 * @return private key, or {@code null}, if no matching identity is
	 *         available.
	 */
	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	/**
	 * Get public key of certificate based identity
	 * 
	 * @return public key, or {@code null}, if no matching identity is
	 *         available.
	 */
	public PublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Get certificate chain of x509 based identity
	 * 
	 * @return certificate chain, or {@code null}, if no x509 identity is
	 *         available or used.
	 */
	public List<X509Certificate> getCertificateChain() {
		return certificateChain;
	}

}
