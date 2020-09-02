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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.x509;

import java.security.cert.X509Certificate;

import org.eclipse.californium.scandium.dtls.CertificateMessage;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.HandshakeException;

/**
 * A class in charge of verifying a X.509 certificate chain provided by a peer.
 * 
 * @see StaticCertificateVerifier
 * @deprecated use {@link NewAdvancedCertificateVerifier} instead, or
 *             {@link BridgeCertificateVerifier} until migrated.
 */
@Deprecated
public interface CertificateVerifier {

	/**
	 * Validates the X.509 certificate chain provided by the the peer as part of
	 * this message.
	 * 
	 * @param message certificate message to be verified
	 * @param session dtls session to verify
	 * @throws HandshakeException if verification fails
	 */
	void verifyCertificate(CertificateMessage message, DTLSSession session) throws HandshakeException;

	/**
	 * Return an array of certificate authority certificates which are trusted
	 * for authenticating peers.
	 * 
	 * The javadoc of previous versions (2.1.0 and before) permits to use
	 * {@code null}. This causes a failure, please adapt to use an empty array.
	 * 
	 * @return a non-null (possibly empty) array of acceptable CA issuer
	 *         certificates.
	 */
	X509Certificate[] getAcceptedIssuers();

}
