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

import java.security.PublicKey;
import java.security.cert.CertPath;

import org.eclipse.californium.scandium.auth.AdvancedApplicationLevelInfoSupplier;
import org.eclipse.californium.scandium.dtls.x509.NewAdvancedCertificateVerifier;

/**
 * Result of certificate verification.
 * 
 * On success contains the resulting certificate path for x509, or the public
 * key for RPK.
 * 
 * @since 2.5
 */
public final class CertificateVerificationResult extends HandshakeResult {

	/**
	 * Verified resulting certificate path for x.509. If
	 * {@link NewAdvancedCertificateVerifier#verifyCertificate(ConnectionId, org.eclipse.californium.scandium.util.ServerNames, Boolean, boolean, CertificateMessage, DTLSSession)}
	 * is called with {@code truncateCertificatePath} set to {@code true}, the
	 * certificate path of the received certificate message is truncated to one
	 * of the trust anchors. Maybe contain a empty path, if the received
	 * certificate message doesn't contain a certificate.
	 */
	private final CertPath certificatePath;
	/**
	 * Verified public key for RPK.
	 */
	private final PublicKey publicKey;
	/**
	 * Handshake exception.
	 */
	private final HandshakeException exception;

	/**
	 * Create result.
	 * 
	 * @param cid connection id
	 * @param certificatePath verified certificate path for x509. {@code null},
	 *            if certificate path could not be verified.
	 * @param customArgument custom argument. May be {@code null}. Passed to
	 *            {@link AdvancedApplicationLevelInfoSupplier} by the
	 *            {@link Handshaker}, if a
	 *            {@link AdvancedApplicationLevelInfoSupplier} is available.
	 * @throws NullPointerException if cid is {@code null}.
	 */
	public CertificateVerificationResult(ConnectionId cid, CertPath certificatePath, Object customArgument) {
		super(cid, customArgument);
		this.certificatePath = certificatePath;
		this.publicKey = null;
		this.exception = null;
	}

	/**
	 * Create result.
	 * 
	 * @param cid connection id
	 * @param publicKey verified public key for RPK. {@code null}, if public key
	 *            could not be verified.
	 * @param customArgument custom argument. May be {@code null}. Passed to
	 *            {@link AdvancedApplicationLevelInfoSupplier} by the
	 *            {@link Handshaker}, if a
	 *            {@link AdvancedApplicationLevelInfoSupplier} is available.
	 * @throws NullPointerException if cid is {@code null}.
	 */
	public CertificateVerificationResult(ConnectionId cid, PublicKey publicKey, Object customArgument) {
		super(cid, customArgument);
		this.certificatePath = null;
		this.publicKey = publicKey;
		this.exception = null;
	}

	/**
	 * Create result.
	 * 
	 * @param cid connection id
	 * @param exception handshake exception.
	 * @param customArgument custom argument. May be {@code null}. Passed to
	 *            {@link AdvancedApplicationLevelInfoSupplier} by the
	 *            {@link Handshaker}, if a
	 *            {@link AdvancedApplicationLevelInfoSupplier} is available.
	 * @throws NullPointerException if cid or exception is {@code null}.
	 */
	public CertificateVerificationResult(ConnectionId cid, HandshakeException exception, Object customArgument) {
		super(cid, customArgument);
		if (exception == null) {
			throw new NullPointerException("exception must not be null!");
		}
		this.certificatePath = null;
		this.publicKey = null;
		this.exception = exception;
	}

	/**
	 * Get verified certificate path for x509.
	 * 
	 * @return verified certificate path, {@code null}, if not available or not
	 *         verified.
	 */
	public CertPath getCertificatePath() {
		return certificatePath;
	}

	/**
	 * Get verified public key for RPK.
	 * 
	 * @return public key, {@code null}, if not available or not verified.
	 */
	public PublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Get exception.
	 * 
	 * @return exception, may be {@code null}, if no exception occurred.
	 */
	public HandshakeException getException() {
		return exception;
	}
}
