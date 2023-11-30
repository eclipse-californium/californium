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

import org.eclipse.californium.elements.config.CertificateAuthenticationMode;
import org.eclipse.californium.elements.util.JceProviderUtil;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.CertificateKeyAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuiteParameters.CertificateBasedMismatch;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuiteParameters.GeneralMismatch;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default cipher suite selector.
 * 
 * Select cipher suite matching the available security parameters and
 * algorithms.
 * 
 * @since 2.3
 */
public class DefaultCipherSuiteSelector implements CipherSuiteSelector {

	// Logging ////////////////////////////////////////////////////////
	/**
	 * The logger.
	 * 
	 * @deprecated to be removed.
	 */
	@Deprecated
	protected static final Logger LOGGER = LoggerFactory.getLogger(DefaultCipherSuiteSelector.class);

	@Override
	public boolean select(CipherSuiteParameters parameters) {
		if (parameters.getCipherSuites().isEmpty()) {
			parameters.setGeneralMismatch(GeneralMismatch.CIPHER_SUITE);
			return false;
		}
		for (CipherSuite cipherSuite : parameters.getCipherSuites()) {
			if (select(cipherSuite, parameters)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Check, if provided cipher suite is supported by both peers.
	 * 
	 * Sets {@link CipherSuiteParameters#setGeneralMismatch(GeneralMismatch)},
	 * if ec based cipher suites can not be selected.
	 * 
	 * @param cipherSuite cipher suite to check,
	 * @param parameters parameters to be used to check
	 * @return {@code true}, if cipher suite is supported by both peers,
	 *         {@code false}, otherwise.
	 */
	protected boolean select(CipherSuite cipherSuite, CipherSuiteParameters parameters) {
		if (cipherSuite.isEccBased()) {
			if (parameters.getSupportedGroups().isEmpty()) {
				// no common supported group
				parameters.setGeneralMismatch(GeneralMismatch.EC_GROUPS);
				return false;
			} else if (parameters.getFormat() == null) {
				// no common supported format
				parameters.setGeneralMismatch(GeneralMismatch.EC_FORMAT);
				return false;
			}
		}
		if (cipherSuite.requiresServerCertificateMessage()) {
			if (parameters.getCertificateMismatch() == null) {
				return selectForCertificate(parameters, cipherSuite);
			} else {
				return false;
			}
		} else {
			if (cipherSuite.isEccBased()) {
				// PSK_ECDHE requires a selected supported group
				parameters.selectSupportedGroup(parameters.getSupportedGroups().get(0));
			}
			// PSK requires a selected cipher suite.
			parameters.select(cipherSuite);
			return true;
		}
	}

	/**
	 * Check, if the common parameters match the peer's certificate-chain.
	 * 
	 * Sets
	 * {@link CipherSuiteParameters#setCertificateMismatch(CertificateBasedMismatch)},
	 * if certificate based cipher suites can not be selected. Sets
	 * {@link CipherSuiteParameters#select(CipherSuite)},
	 * {@link CipherSuiteParameters#selectServerCertificateType(CertificateType)},
	 * {@link CipherSuiteParameters#selectSignatureAndHashAlgorithm(SignatureAndHashAlgorithm)},
	 * and
	 * {@link CipherSuiteParameters#selectClientCertificateType(CertificateType)},
	 * if the certificate based cipher suite is selected.
	 * 
	 * @param parameters common parameters and certificate-chain.
	 * @param cipherSuite cipher suite to check.
	 * @return {@code true}, if the cipher suite is selected, {@code false},
	 *         otherwise.
	 * @throws IllegalArgumentException if the certificate-chain is missing or
	 *             the certificate's key algorithm is not supported.
	 */
	protected boolean selectForCertificate(CipherSuiteParameters parameters, CipherSuite cipherSuite) {
		CertificateKeyAlgorithm keyAlgorithm = cipherSuite.getCertificateKeyAlgorithm();
		if (!JceProviderUtil.isSupported(keyAlgorithm.name())) {
			throw new IllegalArgumentException(keyAlgorithm.name() + " based cipher suites are supported!");
		}
		if (!keyAlgorithm.isCompatible(parameters.getPublicKey())) {
			return false;
		}
		// make sure that we support the client's proposed
		// server certificate types
		if (parameters.getServerCertTypes().isEmpty()) {
			parameters.setCertificateMismatch(CertificateBasedMismatch.SERVER_CERT_TYPE);
			return false;
		}
		CertificateAuthenticationMode clientAuthentication = parameters.getClientAuthenticationMode();
		if (clientAuthentication.useCertificateRequest() && parameters.getClientCertTypes().isEmpty()) {
			parameters.setCertificateMismatch(CertificateBasedMismatch.CLIENT_CERT_TYPE);
			return false;
		}
		if (parameters.getSignatures().isEmpty()) {
			parameters.setCertificateMismatch(CertificateBasedMismatch.SIGNATURE_ALGORITHMS);
			return false;
		}
		if (cipherSuite.getCertificateKeyAlgorithm() == CertificateKeyAlgorithm.EC) {
			// check for supported curve in certificate
			SupportedGroup group = SupportedGroup.fromPublicKey(parameters.getPublicKey());
			if (group == null || !parameters.getSupportedGroups().contains(group)) {
				parameters.setCertificateMismatch(CertificateBasedMismatch.CERTIFICATE_EC_GROUPS);
				return false;
			}
		}
		SignatureAndHashAlgorithm signatureAndHashAlgorithm = SignatureAndHashAlgorithm
				.getSupportedSignatureAlgorithm(parameters.getSignatures(), parameters.getPublicKey());
		if (signatureAndHashAlgorithm == null) {
			parameters.setCertificateMismatch(CertificateBasedMismatch.CERTIFICATE_SIGNATURE_ALGORITHMS);
			return false;
		}
		CertificateType certificateType = parameters.getServerCertTypes().get(0);
		if (CertificateType.X_509.equals(certificateType)) {
			if (parameters.getCertificateChain() == null) {
				throw new IllegalArgumentException("Certificate type x509 requires a certificate chain!");
			}
			// check, if certificate chain is supported
			boolean supported = SignatureAndHashAlgorithm
					.isSignedWithSupportedAlgorithms(parameters.getSignatures(), parameters.getCertificateChain());
			if (supported) {
				supported = SupportedGroup.isSupported(parameters.getSupportedGroups(),
						parameters.getCertificateChain());
			}
			if (!supported) {
				// x509 is not supported, because the certificate chain
				// contains unsupported signature hash algorithms or groups
				// (curves).
				if (parameters.getServerCertTypes().contains(CertificateType.RAW_PUBLIC_KEY)) {
					certificateType = CertificateType.RAW_PUBLIC_KEY;
				} else {
					parameters
							.setCertificateMismatch(CertificateBasedMismatch.CERTIFICATE_PATH_SIGNATURE_ALGORITHMS);
					return false;
				}
			}
		}
		parameters.select(cipherSuite);
		parameters.selectServerCertificateType(certificateType);
		parameters.selectSignatureAndHashAlgorithm(signatureAndHashAlgorithm);
		parameters.selectSupportedGroup(parameters.getSupportedGroups().get(0));
		certificateType = clientAuthentication.useCertificateRequest() ? parameters.getClientCertTypes().get(0)
				: null;
		parameters.selectClientCertificateType(certificateType);
		return true;
	}
}
