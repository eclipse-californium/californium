/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.credentialsstore;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.dtls.rpkstore.TrustedRpkStore;
import org.eclipse.californium.scandium.dtls.x509.CertificateVerifier;

/**
 * Credentials configuration single destination.
 */
public interface CredentialsConfiguration {

	/**
	 * Gets the cipher suites the connector should advertise in a DTLS
	 * handshake.
	 * 
	 * @return the supported cipher suites (ordered by preference)
	 */
	CipherSuite[] getSupportedCipherSuites();

	/**
	 * Gets Store containing PSK credentials.
	 * 
	 * @return the store
	 */
	PskStore getPskStore();

	/**
	 * Gets the private key to use for proving identity to a peer during a DTLS
	 * handshake.
	 * 
	 * @return the key
	 */
	PrivateKey getPrivateKey();

	/**
	 * Gets the public key to send to peers during the DTLS handshake for
	 * authentication purposes.
	 * 
	 * @return the key
	 */
	PublicKey getPublicKey();

	/**
	 * @return The trust store for raw public keys verified out-of-band for
	 *         DTLS-RPK handshakes
	 */
	TrustedRpkStore getRpkTrustStore();

	/**
	 * Gets the certificates forming the chain-of-trust from a root CA down to
	 * the certificate asserting the server's identity.
	 * 
	 * @return the certificates or <code>null</code> if the connector is not
	 *         supposed to support certificate based authentication
	 */
	X509Certificate[] getCertificateChain();

	/**
	 * Gets the class responsible to verify foreign peer certificate
	 * 
	 * Note that this property is only relevant for cipher suites using
	 * certificate based authentication.
	 * 
	 * @return the certificate verifier
	 */
	CertificateVerifier getCertificateVerifier();

	/**
	 * Checks whether the connector will send a <em>raw public key</em> instead
	 * of an X.509 certificate in order to authenticate to the peer during a
	 * DTLS handshake.
	 * 
	 * Note that this property is only relevant for cipher suites using
	 * certificate based authentication.
	 * 
	 * @return <code>true</code> if <em>RawPublicKey</em> is used by the
	 *         connector
	 */
	Boolean isSendRawKey();
}
