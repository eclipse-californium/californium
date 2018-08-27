/*******************************************************************************
 * Copyright (c) 2018 Sierra Wireless
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Manuel Sangoi (Sierra Wireless) - Initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - set cause of handshake failure
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.x509;

import java.security.GeneralSecurityException;
import java.security.cert.CertPathValidator;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

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
 */
public class StaticCertificateVerifier implements CertificateVerifier {

	private static final Logger LOGGER = LoggerFactory.getLogger(StaticCertificateVerifier.class.getName());

	private final X509Certificate[] rootCertificates;

	public StaticCertificateVerifier(X509Certificate[] rootCertificates) {
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

		if (rootCertificates != null && rootCertificates.length == 0) {
			// trust empty list of root certificates
			return;
		}

		Set<TrustAnchor> trustAnchors = getTrustAnchors(rootCertificates);

		try {
			PKIXParameters params = new PKIXParameters(trustAnchors);
			// TODO: implement alternative means of revocation checking
			params.setRevocationEnabled(false);

			CertPathValidator validator = CertPathValidator.getInstance("PKIX");
			validator.validate(message.getCertificateChain(), params);

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

	private static Set<TrustAnchor> getTrustAnchors(X509Certificate[] trustedCertificates) {
		Set<TrustAnchor> result = new HashSet<>();
		if (trustedCertificates != null) {
			for (X509Certificate cert : trustedCertificates) {
				result.add(new TrustAnchor((X509Certificate) cert, null));
			}
		}
		return result;
	}

}
