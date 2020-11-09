/*******************************************************************************
 * Copyright (c) 2018 Sierra Wireless
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
 *    Manuel Sangoi (Sierra Wireless) - Initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - set cause of handshake failure
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.x509;

import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.eclipse.californium.elements.util.CertPathUtil;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.CertificateMessage;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This implementation uses a static set of trusted root certificates to
 * validate the chain.
 * 
 * @deprecated use {@link StaticNewAdvancedCertificateVerifier} instead.
 */
@Deprecated
public class StaticCertificateVerifier implements AdvancedCertificateVerifier {

	private static final Logger LOGGER = LoggerFactory.getLogger(StaticCertificateVerifier.class);

	/**
	 * Array of root certificates.
	 * 
	 * @see #getAcceptedIssuers()
	 */
	private final X509Certificate[] rootCertificates;

	/**
	 * Create instance of static certificate verifier.
	 * 
	 * @param rootCertificates array with trusted root certificates, empty array
	 *            to trust all.
	 */
	public StaticCertificateVerifier(X509Certificate[] rootCertificates) {
		if (rootCertificates == null) {
			throw new NullPointerException("root certificates must not be null!");
		}
		this.rootCertificates = rootCertificates;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * This method checks
	 * <ol>
	 * <li>that each certificate's issuer DN equals the subject DN of the next
	 * certificate in the chain</li>
	 * <li>that each certificate is currently valid according to its validity
	 * period</li>
	 * <li>that the chain is rooted at a trusted CA</li>
	 * </ol>
	 * 
	 * @throws HandshakeException if any of the checks fails
	 */
	@Override
	public void verifyCertificate(CertificateMessage message, DTLSSession session) throws HandshakeException {

		try {
			CertPathUtil.validateCertificatePathWithIssuer(false, message.getCertificateChain(), rootCertificates);
		} catch (GeneralSecurityException e) {
			if (LOGGER.isTraceEnabled()) {
				LOGGER.trace("Certificate validation failed", e);
			} else if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Certificate validation failed due to {}", e.getMessage());
			}
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE,
					session.getPeer());
			throw new HandshakeException("Certificate chain could not be validated", alert, e);
		}

	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return rootCertificates;
	}

	@Override
	public CertPath verifyCertificate(Boolean clientUsage, boolean truncateCertificatePath, CertificateMessage message,
			DTLSSession session) throws HandshakeException {
		try {
			CertPath certPath = message.getCertificateChain();
			if (clientUsage != null && !message.isEmpty()) {
				Certificate certificate = certPath.getCertificates().get(0);
				if (certificate instanceof X509Certificate) {
					if (!CertPathUtil.canBeUsedForAuthentication((X509Certificate) certificate, clientUsage)) {
						LOGGER.debug("Certificate validation failed: key usage doesn't match");
						AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE,
								session.getPeer());
						throw new HandshakeException("Key Usage doesn't match!", alert);
					}
				}
			}
			return CertPathUtil.validateCertificatePathWithIssuer(truncateCertificatePath, certPath, rootCertificates);
		} catch (GeneralSecurityException e) {
			if (LOGGER.isTraceEnabled()) {
				LOGGER.trace("Certificate validation failed", e);
			} else if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Certificate validation failed due to {}", e.getMessage());
			}
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE,
					session.getPeer());
			throw new HandshakeException("Certificate chain could not be validated", alert, e);
		}
	}

}
