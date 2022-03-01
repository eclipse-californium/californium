/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.cluster;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.SslContextUtil.Credentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The credentials utility.
 * 
 * For usage with https.
 * 
 * @since 3.0
 */
public class CredentialsUtil {

	private static final Logger LOGGER = LoggerFactory.getLogger(CredentialsUtil.class);

	/**
	 * Create ssl context for https.
	 * 
	 * @param identity credentials to identify this peer
	 * @param trust certificates to trust by this peer.
	 * @return ssl context.
	 * @throws GeneralSecurityException if an crypto error occurred.
	 * @throws IOException if an i/o error occurred
	 */
	public static SSLContext getSslContext(String identity, String trust) throws GeneralSecurityException, IOException {
		KeyManager[] keyManager;
		TrustManager[] trustManager;
		if (identity != null && !identity.isEmpty()) {
			Credentials credentials = SslContextUtil.loadCredentials(identity);
			keyManager = SslContextUtil.createKeyManager("https", credentials.getPrivateKey(),
					credentials.getCertificateChain());
		} else {
			keyManager = SslContextUtil.createAnonymousKeyManager();
		}
		if (trust != null && !trust.isEmpty()) {
			Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(trust);
			trustManager = SslContextUtil.createTrustManager("https", trustedCertificates);
		} else {
			trustManager = SslContextUtil.createTrustAllManager();
		}
		SSLContext sslContext;
		try {
			sslContext = SSLContext.getInstance("TLSv1.3");
		} catch (NoSuchAlgorithmException ex) {
			sslContext = SSLContext.getInstance("TLS");
		}
		sslContext.init(keyManager, trustManager, null);
		return sslContext;
	}

	/**
	 * Create ssl context for k8s management api https clients.
	 * 
	 * @param defaultTrust default trusted certificate. May be {@code null}
	 * @return ssl context for k8s management api https clients.
	 */
	public static SSLContext getK8sHttpsClientContext(File defaultTrust) {
		try {
			String trusts = null;
			File file = new File("/etc/certs/https_k8s_client_trust.pem");
			if (file.exists()) {
				trusts = "file://" + file.getAbsolutePath();
			} else if (defaultTrust != null && defaultTrust.exists()) {
				trusts = "file://" + defaultTrust.getAbsolutePath();
			}
			LOGGER.info("https-k8s-client load's trusts from {}.", trusts);
			return CredentialsUtil.getSslContext(null, trusts);
		} catch (GeneralSecurityException e) {
			LOGGER.warn("https-k8s-client:", e);
		} catch (IOException e) {
			LOGGER.warn("https-k8s-client:", e);
		}
		return null;
	}

	/**
	 * Create ssl context for cluster internal https clients.
	 * 
	 * {@link RestoreJdkHttpClient} disables hostname verification. Use with care!
	 * This usually requires, that no public trust root is used!
	 * 
	 * @return ssl context for cluster internal https clients.
	 */
	public static SSLContext getClusterInternalHttpsClientContext() {
		try {
			return CredentialsUtil.getSslContext("file:///etc/certs/https_client_cert.pem",
					"file:///etc/certs/https_client_trust.pem");
		} catch (GeneralSecurityException e) {
			LOGGER.warn("https-client:", e);
		} catch (IOException e) {
			LOGGER.warn("https-client:", e);
		}
		return null;
	}

	/**
	 * Create ssl context for cluster internal https server.
	 * 
	 * Though the {@link RestoreJdkHttpClient} disables hostname verification, use
	 * with care! This usually requires, that no public trust root is used!
	 * 
	 * @return ssl context for cluster internal https server.
	 */
	public static SSLContext getClusterInternalHttpsServerContext() {
		try {
			return CredentialsUtil.getSslContext("file:///etc/certs/https_server_cert.pem",
					"file:///etc/certs/https_server_trust.pem");
		} catch (GeneralSecurityException e) {
			LOGGER.warn("https-server:", e);
		} catch (IOException e) {
			LOGGER.warn("https-server:", e);
		}
		return null;
	}

}
