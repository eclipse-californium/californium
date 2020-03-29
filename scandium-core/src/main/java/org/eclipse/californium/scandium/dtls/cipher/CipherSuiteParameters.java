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
 *                    derived from ECDHECryptography
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.SupportedPointFormatsExtension.ECPointFormat;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;

/**
 * Cipher suites and parameters.
 * 
 * @since 2.3
 */
public class CipherSuiteParameters {

	private PublicKey publicKey;
	private List<X509Certificate> certificateChain;
	private boolean clientAuthenticationRequired;
	private boolean clientAuthenticationWanted;

	private List<CipherSuite> cipherSuites;
	private List<CertificateType> serverCertTypes;
	private List<CertificateType> clientCertTypes;
	private List<SupportedGroup> supportedGroups;
	private List<SignatureAndHashAlgorithm> signatures;
	private ECPointFormat format;

	private SignatureAndHashAlgorithm selectedSignature;

	/**
	 * Create common cipher suites and parameters.
	 * 
	 * @param publicKey peer's public key. Maybe {@code null}.
	 * @param certificateChain peer's certificate chain. Maybe {@code null}.
	 * @param clientAuthenticationRequired {@code true}, if client
	 *            authentication is required, {@code false} otherwise.
	 * @param clientAuthenticationWanted {@code true}, if client authentication
	 *            is wanted, {@code false} otherwise.
	 * @param cipherSuites list of common cipher suites
	 * @param serverCertTypes list of common server certificate types.
	 * @param clientCertTypes list of common client certificate types.
	 * @param supportedGroups list of common supported groups (curves)
	 * @param signatures list of common signtaures and algorithms.
	 * @param format common ec point format. Only
	 *            {@link ECPointFormat#UNCOMPRESSED} is supported.
	 */
	public CipherSuiteParameters(PublicKey publicKey, List<X509Certificate> certificateChain,
			boolean clientAuthenticationRequired, boolean clientAuthenticationWanted, List<CipherSuite> cipherSuites,
			List<CertificateType> serverCertTypes, List<CertificateType> clientCertTypes,
			List<SupportedGroup> supportedGroups, List<SignatureAndHashAlgorithm> signatures, ECPointFormat format) {
		this.publicKey = publicKey;
		this.certificateChain = certificateChain;
		this.clientAuthenticationRequired = clientAuthenticationRequired;
		this.clientAuthenticationWanted = !clientAuthenticationRequired && clientAuthenticationWanted;
		this.cipherSuites = cipherSuites;
		this.serverCertTypes = serverCertTypes;
		this.clientCertTypes = clientCertTypes;
		this.supportedGroups = supportedGroups;
		this.signatures = signatures;
		this.format = format;
	}

	public List<CipherSuite> getCipherSuites() {
		return cipherSuites;
	}

	public List<CertificateType> getServerCertTypes() {
		return serverCertTypes;
	}

	public List<CertificateType> getClientCertTypes() {
		return clientCertTypes;
	}

	public List<SupportedGroup> getSupportedGroups() {
		return supportedGroups;
	}

	public List<SignatureAndHashAlgorithm> getSignatures() {
		return signatures;
	}

	public ECPointFormat getFormat() {
		return format;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public List<X509Certificate> getCertificateChain() {
		return certificateChain;
	}

	public boolean isClientAuthenticationRequired() {
		return clientAuthenticationRequired;
	}

	public boolean isClientAuthenticationWanted() {
		return clientAuthenticationWanted;
	}

	/**
	 * Get selected cipher suite.
	 * 
	 * @return selected cipher suite
	 */
	public CipherSuite getSelectedCipherSuite() {
		return cipherSuites.get(0);
	}

	/**
	 * Get selected server certificate type
	 * 
	 * @return selected server certificate type, or {@code null}, if not
	 *         available.
	 */
	public CertificateType getSelectedServerCertificateType() {
		if (serverCertTypes.isEmpty()) {
			return null;
		}
		return serverCertTypes.get(0);
	}

	/**
	 * Get selected client certificate type
	 * 
	 * @return selected client certificate type, or {@code null}, if not
	 *         available.
	 */
	public CertificateType getSelectedClientCertificateType() {
		if (clientCertTypes.isEmpty()) {
			return null;
		}
		return clientCertTypes.get(0);
	}

	/**
	 * Get selected supported group for ECDHE.
	 * 
	 * @return supported group, or {@code null}, if not available.
	 */
	public SupportedGroup getSelectedSupportedGroup() {
		if (supportedGroups.isEmpty()) {
			return null;
		}
		return supportedGroups.get(0);
	}

	/**
	 * Get selected signature and hash algorithm for signing.
	 * 
	 * @return selected signature and hash algorithm, or {@code null}, if not
	 *         available.
	 */
	public SignatureAndHashAlgorithm getSelectedSignature() {
		return selectedSignature;
	}

	/**
	 * Select cipher suite.
	 * 
	 * @param cipherSuite selected cipher suite
	 */
	public void select(CipherSuite cipherSuite) {
		cipherSuites.clear();
		cipherSuites.add(cipherSuite);
	}

	/**
	 * Select server certificate type.
	 * 
	 * @param type selected server certificate type. Maybe {@code null}, if not
	 *            available.
	 */
	public void selectServerCertificateType(CertificateType type) {
		serverCertTypes.clear();
		if (type != null) {
			serverCertTypes.add(type);
		}
	}

	/**
	 * Select client certificate type.
	 * 
	 * @param type selected client certificate type. Maybe {@code null}, if not
	 *            available or client certificate not requested.
	 */
	public void selectClientCertificateType(CertificateType type) {
		clientCertTypes.clear();
		if (type != null) {
			clientCertTypes.add(type);
		}
	}

	/**
	 * Select signature and hashe algorithm.
	 * 
	 * @param signature selected signature and hashe algorithm. Maybe
	 *            {@code null}, if not available.
	 */
	public void selectSignatureAndHashAlgorithm(SignatureAndHashAlgorithm signature) {
		this.selectedSignature = signature;
	}
}
