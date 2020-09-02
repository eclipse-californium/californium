/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial API and implementation
 *******************************************************************************/
package org.eclipse.californium.scandium.dtls.x509;

import java.security.cert.CertPath;

import org.eclipse.californium.scandium.dtls.CertificateMessage;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.HandshakeException;

/**
 * A class in charge of verifying a X.509 certificate chain provided by a peer.
 * 
 * @see StaticCertificateVerifier
 * @since 2.1
 * @deprecated use {@link NewAdvancedCertificateVerifier} instead, or
 *             {@link BridgeCertificateVerifier} until migrated.
 */
@Deprecated
public interface AdvancedCertificateVerifier extends CertificateVerifier {

	/**
	 * Validates the X.509 certificate chain provided by the the peer as part of
	 * this message.
	 * 
	 * @param clientUsage indicator to check certificate usage. {@code null}
	 *            don't check key usage, {@code true}, check key usage for
	 *            client, {@code false} for server.
	 * @param truncateCertificatePath {@code true} truncate certificate path at
	 *            a trusted certificate before validation.
	 * @param message certificate message to be validated
	 * @param session dtls session to be used for validation
	 * @return actually validated certificate path.
	 * @throws HandshakeException if validation fails
	 */
	CertPath verifyCertificate(Boolean clientUsage, boolean truncateCertificatePath, CertificateMessage message,
			DTLSSession session) throws HandshakeException;

}
