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
 *    Bosch Software Innovations GmbH - initial creation
 *                                      Moved from DtlsTestTools
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class TestCertificatesTools {

	public static final char[] TRUST_STORE_PASSWORD = "rootPass".toCharArray();
	public static final char[] KEY_STORE_PASSWORD = "endPass".toCharArray();
	public static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	public static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";
	public static final String SERVER_NAME = "server";
	/**
	 * Alias for mixed signed server certificate chain. Include ECDSA and RSA
	 * certificates.
	 * 
	 * @since 2.3
	 */
	public static final String SERVER_RSA_NAME = "serverrsa";
	public static final String CLIENT_NAME = "client";
	public static final String ROOT_CA_ALIAS = "root";
	public static final String CA_ALIAS = "ca";
	public static final String NO_SIGNING_ALIAS = "nosigning";
	private static SslContextUtil.Credentials clientCredentials;
	private static SslContextUtil.Credentials serverCredentials;
	private static SslContextUtil.Credentials serverRsaCredentials;
	private static X509Certificate[] trustedCertificates;
	private static X509Certificate rootCaCertificate;
	private static X509Certificate caCertificate;
	private static X509Certificate nosigningCertificate; // a certificate without digitalSignature value in keyusage

	static {
		try {
			// load key stores once only
			clientCredentials = SslContextUtil.loadCredentials(
					SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION, CLIENT_NAME, KEY_STORE_PASSWORD,
					KEY_STORE_PASSWORD);
			serverCredentials = SslContextUtil.loadCredentials(
					SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION, SERVER_NAME, KEY_STORE_PASSWORD,
					KEY_STORE_PASSWORD);
			serverRsaCredentials = SslContextUtil.loadCredentials(
					SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION, SERVER_RSA_NAME, KEY_STORE_PASSWORD,
					KEY_STORE_PASSWORD);
			Certificate[] certificates = SslContextUtil.loadTrustedCertificates(
					SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION, null, TRUST_STORE_PASSWORD);

			trustedCertificates = SslContextUtil.asX509Certificates(certificates);
			certificates = SslContextUtil.loadTrustedCertificates(
					SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION, ROOT_CA_ALIAS, TRUST_STORE_PASSWORD);
			rootCaCertificate = (X509Certificate) certificates[0];
			certificates = SslContextUtil.loadTrustedCertificates(
					SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION, CA_ALIAS, TRUST_STORE_PASSWORD);
			caCertificate = (X509Certificate) certificates[0];
			X509Certificate[] chain = SslContextUtil.loadCertificateChain(
					SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION, NO_SIGNING_ALIAS, KEY_STORE_PASSWORD);
			nosigningCertificate = chain[0];
		} catch (IOException | GeneralSecurityException e) {
			// nothing we can do
		}
	}

	protected TestCertificatesTools() {
	}

	public static X509Certificate[] getServerCertificateChain()	throws IOException, GeneralSecurityException {
		X509Certificate[] certificateChain = serverCredentials.getCertificateChain();
		return Arrays.copyOf(certificateChain, certificateChain.length);
	}

	/**
	 * Get mixed server certificate chain. Contains ECDSA and RSA certificates.
	 * 
	 * @return mixed server certificate chain
	 * @throws IOException if the key store cannot be read
	 * @throws GeneralSecurityException if the key cannot be found
	 * @since 2.3
	 */
	public static X509Certificate[] getServerRsaCertificateChain()	throws IOException, GeneralSecurityException {
		X509Certificate[] certificateChain = serverRsaCredentials.getCertificateChain();
		return Arrays.copyOf(certificateChain, certificateChain.length);
	}

	public static X509Certificate[] getClientCertificateChain()	throws IOException, GeneralSecurityException {
		X509Certificate[] certificateChain = clientCredentials.getCertificateChain();
		return Arrays.copyOf(certificateChain, certificateChain.length);
	}

	/**
	 * Gets the server's private key from the example key store.
	 * 
	 * @return the key
	 * @throws IOException if the key store cannot be read
	 * @throws GeneralSecurityException if the key cannot be found
	 */
	public static PrivateKey getPrivateKey() throws IOException, GeneralSecurityException {
		return serverCredentials.getPrivateKey();
	}

	/**
	 * Gets the server's private key from the example key store. Use the server
	 * with mixed certificate chain wiht ECDSA and RSA certificates.
	 * 
	 * @return the key
	 * @throws IOException if the key store cannot be read
	 * @throws GeneralSecurityException if the key cannot be found
	 * @since 2.3
	 */
	public static PrivateKey getServerRsPrivateKey() throws IOException, GeneralSecurityException {
		return serverRsaCredentials.getPrivateKey();
	}

	/**
	 * Gets the client's private key from the example key store.
	 * 
	 * @return the key
	 * @throws IOException if the key store cannot be read
	 * @throws GeneralSecurityException if the key cannot be found
	 */
	public static PrivateKey getClientPrivateKey() throws IOException, GeneralSecurityException {
		return clientCredentials.getPrivateKey();
	}

	/**
	 * Gets the server's public key from the example key store.
	 * 
	 * @return The key.
	 * @throws IOException if the key store cannot be read
	 * @throws GeneralSecurityException if the key cannot be found
	 * @throws IllegalStateException if the key store does not contain a server certificate chain.
	 */
	public static PublicKey getPublicKey() throws IOException, GeneralSecurityException {
		return serverCredentials.getCertificateChain()[0].getPublicKey();
	}

	/**
	 * Gets the client's public key from the example key store.
	 * 
	 * @return The key.
	 * @throws IOException if the key store cannot be read
	 * @throws GeneralSecurityException if the key cannot be found
	 * @throws IllegalStateException if the key store does not contain a client certificate chain.
	 */
	public static PublicKey getClientPublicKey() throws IOException, GeneralSecurityException {
		return clientCredentials.getCertificateChain()[0].getPublicKey();
	}

	/**
	 * Gets the trusted anchor certificates from the example trust store.
	 * 
	 * @return The trusted certificates.
	 */
	public static X509Certificate[] getTrustedCertificates() {
		return trustedCertificates;
	}

	/**
	 * Gets the trusted root CA certificate.
	 * 
	 * @return The certificate.
	 */
	public static X509Certificate getTrustedRootCA() {
		return rootCaCertificate;
	}

	/**
	 * Gets the trusted CA certificate.
	 * 
	 * @return The certificate.
	 */
	public static X509Certificate getTrustedCA() {
		return caCertificate;
	}

	/**
	 * @return a certificate without digitalSignature in keyusage extension
	 */
	public static X509Certificate getNoSigningCertificate() {
		return nosigningCertificate;
	}
}
