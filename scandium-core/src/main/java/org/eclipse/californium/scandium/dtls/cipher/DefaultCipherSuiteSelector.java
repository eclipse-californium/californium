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

import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.CertificateKeyAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default cipher suite selector.
 * 
 * Select cipher suite matching the available security parameters and algorithms.
 * 
 * @since 2.3
 */
public class DefaultCipherSuiteSelector implements CipherSuiteSelector {

	// Logging ////////////////////////////////////////////////////////

	protected static final Logger LOGGER = LoggerFactory.getLogger(DefaultCipherSuiteSelector.class);

	@Override
	public boolean select(CipherSuiteParameters parameters) {
		boolean certificateSupportFailed = false;
		for (CipherSuite cipherSuite : parameters.getCipherSuites()) {
			if (cipherSuite.requiresServerCertificateMessage()) {
				if (!certificateSupportFailed) {
					if (select(cipherSuite, parameters)) {
						return true;
					}
					// if the check for the certificate support
					// fails, it fails for all other 
					// certificate based cipher suites as well
					certificateSupportFailed = true;
				}
			} else if (select(cipherSuite, parameters)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Check, if provided cipher suite is supported by both peers.
	 * 
	 * @param cipherSuite cipher suite to check,
	 * @param parameters parameters to be used to check
	 * @return {@code true}, if cipher suite is supported by both peers,
	 *         {@code false}, otherwise.
	 */
	protected boolean select(CipherSuite cipherSuite, CipherSuiteParameters parameters) {
		if (cipherSuite.isEccBased() && (parameters.getSupportedGroups().isEmpty() || parameters.getFormat() == null)) {
			// no common supported group or format
			return false;
		}
		if (cipherSuite.requiresServerCertificateMessage()) {
			return selectForCertificate(parameters, cipherSuite);
		} else {
			// PSK or PSK_ECDHE only requires a selected cipher suite.
			parameters.select(cipherSuite);
			return true;
		}
	}

	protected boolean selectForCertificate(CipherSuiteParameters parameters, CipherSuite cipherSuite) {
		// make sure that we support the client's proposed server certificate types
		if (parameters.getServerCertTypes().isEmpty()) {
			return false;
		}
		boolean clientAuthentication = parameters.isClientAuthenticationRequired()
				|| parameters.isClientAuthenticationWanted();
		if (clientAuthentication && parameters.getClientCertTypes().isEmpty()) {
			return false;
		}
		if (parameters.getSignatures().isEmpty()) {
			return false;
		}
		if (cipherSuite.getCertificateKeyAlgorithm() == CertificateKeyAlgorithm.EC) {
			// check for supported curve in certificate
			SupportedGroup group = SupportedGroup.fromPublicKey(parameters.getPublicKey());
			if (group == null || !parameters.getSupportedGroups().contains(group)) {
				return false;
			}
			SignatureAndHashAlgorithm signatureAndHashAlgorithm = SignatureAndHashAlgorithm
					.getSupportedSignatureAlgorithm(parameters.getSignatures(), parameters.getPublicKey());
			if (signatureAndHashAlgorithm == null) {
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
						return false;
					}
				}
			}
			parameters.select(cipherSuite);
			parameters.selectServerCertificateType(certificateType);
			parameters.selectSignatureAndHashAlgorithm(signatureAndHashAlgorithm);
			certificateType = clientAuthentication ? parameters.getClientCertTypes().get(0) : null;
			parameters.selectClientCertificateType(certificateType);
			return true;
		}
		throw new IllegalArgumentException("Only ECDSA certificate based cipher suites are supported!");
	}
}
