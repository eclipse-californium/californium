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
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;

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
		KeyManager[] clientKeys = SslContextUtil.loadKeyManager(SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION,
				CLIENT_NAME, KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
		KeyManager[] serverKeys = SslContextUtil.loadKeyManager(SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION,
				SERVER_NAME, KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
		TrustManager[] trusts = SslContextUtil
				.loadTrustManager(SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION, null, TRUST_STORE_PASSWORD);

		clientSubjectDN = getSubjectDN(clientKeys, CLIENT_NAME);
		clientCertPath = getX509CertPath(clientKeys, CLIENT_NAME);
		serverSubjectDN = getSubjectDN(serverKeys, SERVER_NAME);
		serverCertPath = getX509CertPath(serverKeys, SERVER_NAME);
		log("client " + clientSubjectDN, clientKeys);
		log("server " + serverSubjectDN, serverKeys);
		log("trusts", trusts, true);

		// Initialize the SSLContext to work with our key managers.
		serverSslContext = SSLContext.getInstance("TLS");
		serverSslContext.init(serverKeys, trusts, null);

		clientSslContext = SSLContext.getInstance("TLS");
		clientSslContext.init(clientKeys, trusts, null);
	}

	/**
	 * Initialize a SSL context.
	 * 
	 * @param aliasPrivateKey alias for private key. If <code>null</code>,
	 *            replaced by aliasChain.
	 * @param aliasChain alias for certificate chain.
	 * @param aliasTrustsPattern alias pattern for trusts.
	 * @return ssl context.
	 * @throws Exception if an error occurred
	 */
	public static SSLTestContext initializeContext(String aliasPrivateKey, String aliasChain, String aliasTrustsPattern)
			throws Exception {
		if (aliasPrivateKey == null) {
			aliasPrivateKey = aliasChain;
		}
		Credentials credentials = SslContextUtil.loadCredentials(SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION,
				aliasPrivateKey, KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
		X509Certificate[] chain = SslContextUtil.loadCertificateChain(
				SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION, aliasChain, KEY_STORE_PASSWORD);

		KeyManager[] keys = SslContextUtil.createKeyManager(aliasChain, credentials.getPrivateKey(), chain);

		TrustManager[] trusts = SslContextUtil.loadTrustManager(
				SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION, aliasTrustsPattern, TRUST_STORE_PASSWORD);

		Principal subjectDN = getSubjectDN(keys, aliasChain);
		log("keys ", keys);
		log("trusts", trusts, true);

		SSLContext context = SSLContext.getInstance("TLS");
		context.init(keys, trusts, null);
		return new SSLTestContext(context, subjectDN);
	}

	public static Principal getSubjectDN(KeyManager[] manager, String alias) {
		if (manager != null && manager.length > 0) {
			if (manager[0] instanceof X509ExtendedKeyManager) {
				X509ExtendedKeyManager extendedManager = (X509ExtendedKeyManager) manager[0];
				X509Certificate[] chain = extendedManager.getCertificateChain(alias);
				if (chain != null && chain.length > 0) {
					return chain[0].getSubjectX500Principal();
				}
			}
		}
		return null;
	}

	public static X509CertPath getX509CertPath(KeyManager[] manager, String alias) {
		if (manager == null || manager.length == 0 || !(manager[0] instanceof X509ExtendedKeyManager)) {
			return null;
		}

		X509ExtendedKeyManager extendedManager = (X509ExtendedKeyManager) manager[0];
		X509Certificate[] chain = extendedManager.getCertificateChain(alias);
		if (chain != null && chain.length > 0) {
			try {
				java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
				java.security.cert.CertPath javaCertPath = cf.generateCertPath(Arrays.asList(chain));
				return new X509CertPath(javaCertPath);
			} catch (CertificateException e) {
				/* ignore it */
			}
		}

		return null;
	}

	public static void log(String name, KeyManager[] managers) {
		if (managers == null) {
			System.out.println(name + ": null");
			return;
		}
		System.out.println(name + ": " + managers.length);
		for (KeyManager manager : managers) {
			System.out.println("   " + manager);
		}
	}

	public static void log(String name, TrustManager[] managers, boolean logCertificate) {
		if (managers == null) {
			System.out.println(name + ": null");
			return;
		}
		System.out.println(name + ": " + managers.length);
		for (TrustManager manager : managers) {
			System.out.println("   " + manager);
			if (logCertificate && manager instanceof X509ExtendedTrustManager) {
				X509ExtendedTrustManager extendedManager = (X509ExtendedTrustManager) manager;
				X509Certificate[] issuers = extendedManager.getAcceptedIssuers();
				if (issuers != null) {
					for (X509Certificate issuer : issuers) {
						System.out.println("      " + issuer.getSubjectX500Principal().getName());
					}
				}
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
