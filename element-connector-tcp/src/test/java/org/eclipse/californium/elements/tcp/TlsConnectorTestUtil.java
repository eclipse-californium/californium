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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation
 *    Achim Kraus (Bosch Software Innovations GmbH) - adapt to use
 *                                                    SslContextUtil.createSSLContext
 *                                                    with default to TLSv1.2
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.SSLContext;

import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.SslContextUtil.Credentials;

/**
 * Utils for TLS based connector tests.
 */
public class TlsConnectorTestUtil {

	public static final char[] KEY_STORE_PASSWORD = "endPass".toCharArray();
	public static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	public static final char[] TRUST_STORE_PASSWORD = "rootPass".toCharArray();
	public static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";

	public static final String SERVER_NAME = "server";
	public static final String CLIENT_NAME = "client";

	public static SSLContext serverSslContext;
	public static SSLContext clientSslContext;
	public static Principal serverSubjectDN;
	public static X509CertPath serverCertPath;
	public static Principal clientSubjectDN;
	public static X509CertPath clientCertPath;

	public static void initializeSsl() throws Exception {
		Credentials clientCredentials = SslContextUtil.loadCredentials(
				SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION, CLIENT_NAME, KEY_STORE_PASSWORD,
				KEY_STORE_PASSWORD);
		Credentials serverCredentials = SslContextUtil.loadCredentials(
				SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION, SERVER_NAME, KEY_STORE_PASSWORD,
				KEY_STORE_PASSWORD);
		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(
				SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION, null, TRUST_STORE_PASSWORD);

		clientSubjectDN = getSubjectDN(clientCredentials);
		clientCertPath = getX509CertPath(clientCredentials);
		serverSubjectDN = getSubjectDN(serverCredentials);
		serverCertPath = getX509CertPath(serverCredentials);
		log("client " + clientSubjectDN, clientCredentials);
		log("server " + serverSubjectDN, serverCredentials);
		log("trusts", trustedCertificates, true);

		serverSslContext = SslContextUtil.createSSLContext(null, serverCredentials.getPrivateKey(),
				serverCredentials.getCertificateChain(), trustedCertificates);

		clientSslContext = SslContextUtil.createSSLContext(null, clientCredentials.getPrivateKey(),
				clientCredentials.getCertificateChain(), trustedCertificates);
	}

	/**
	 * Initialize a SSL context.
	 * 
	 * @param aliasPrivateKey    alias for private key. If <code>null</code>,
	 *                           replaced by aliasChain.
	 * @param aliasChain         alias for certificate chain.
	 * @param aliasTrustsPattern alias pattern for trusts.
	 * @return ssl test context.
	 * @throws Exception if an error occurred
	 */
	public static SSLTestContext initializeContext(String aliasPrivateKey, String aliasChain, String aliasTrustsPattern)
			throws Exception {
		if (aliasPrivateKey == null) {
			aliasPrivateKey = aliasChain;
		}
		Credentials privateCredentials = SslContextUtil.loadCredentials(
				SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION, aliasPrivateKey, KEY_STORE_PASSWORD,
				KEY_STORE_PASSWORD);
		Credentials publicCredentials = SslContextUtil.loadCredentials(
				SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION, aliasChain, KEY_STORE_PASSWORD,
				KEY_STORE_PASSWORD);

		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(
				SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION, aliasTrustsPattern, TRUST_STORE_PASSWORD);

		Principal subjectDN = getSubjectDN(publicCredentials);
		log("keys ", publicCredentials);
		log("trusts", trustedCertificates, true);

		SSLContext context = SslContextUtil.createSSLContext(null, privateCredentials.getPrivateKey(),
				publicCredentials.getCertificateChain(), trustedCertificates);

		return new SSLTestContext(context, subjectDN);
	}

	public static Principal getSubjectDN(Credentials credentials) {
		if (credentials != null) {
			X509Certificate[] chain = credentials.getCertificateChain();
			if (chain != null && chain.length > 0) {
				return chain[0].getSubjectX500Principal();
			}
		}
		return null;
	}

	public static X509CertPath getX509CertPath(Credentials credentials) {
		if (credentials != null) {
			X509Certificate[] chain = credentials.getCertificateChain();
			if (chain != null && chain.length > 0) {
				try {
					java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory
							.getInstance("X.509");
					java.security.cert.CertPath javaCertPath = cf.generateCertPath(Arrays.asList(chain));
					return new X509CertPath(javaCertPath);
				} catch (CertificateException e) {
					/* ignore it */
				}
			}
		}
		return null;
	}

	public static void log(String name, Credentials credentials) {
		if (credentials == null) {
			System.out.println(name + ": null");
			return;
		}
		System.out.println(name + ": " + credentials.getCertificateChain().length);
		for (X509Certificate certificate : credentials.getCertificateChain()) {
			System.out.println("      " + certificate.getSubjectX500Principal().getName());
		}
	}

	public static void log(String name, Certificate[] trustedCertificates, boolean logCertificate) {
		if (trustedCertificates == null) {
			System.out.println(name + ": null");
			return;
		}
		System.out.println(name + ": " + trustedCertificates.length);
		for (Certificate trust : trustedCertificates) {
			if (logCertificate && trust instanceof X509Certificate) {
				X509Certificate issuer = (X509Certificate) trust;
				System.out.println("      " + issuer.getSubjectX500Principal().getName());
			}
		}
	}

	public static class SSLTestContext {

		public final SSLContext context;
		public final Principal subjectDN;

		public SSLTestContext(final SSLContext context, final Principal subjectDN) {
			this.context = context;
			this.subjectDN = subjectDN;
		}
	}
}
