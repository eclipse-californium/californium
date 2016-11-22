/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation. 
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * Utility function for TLS/SSL context supporting "direct-trust".
 * 
 * Implements utility for "direct trust" (LWM2M TS, 7.1.3, "The LWM2M Client
 * MUST either directly trust the server's X509 certificate or trust it
 * indirectly by verifying it is correctly signed by a trusted CA.") Using the
 * default TrustManager would use the "direct trusts" as issuer. Using plenty
 * clients, this result in a large certificate request. Also the default
 * KeyManager would try to find a certificate, which was issued by one of those
 * issuer, but would not check, if the certificate is the one of the issuer. So
 * using "direct-trust" requires to report a empty issuer list. This is
 * implemented by {@link DirectX509ExtendedTrustManager}, which could be created
 * by {@link #loadDirectTrustManager(String, String, char[])} or
 * {@link #createDirectTrustManager(String, Certificate[])}. It still uses the
 * default TrustManager, but reports a empty issuer list.
 * 
 * Note: for large number of client certificates a more specialized
 * implementation may be required.
 * 
 * @see OMA-TS-LightweightM2M-V1_0-20161123-D
 */
public class SslDirectTrustContextUtil {

	private static final Logger LOG = Logger.getLogger(SslDirectTrustContextUtil.class.getName());

	/**
	 * Load "direct-trust" manager from key store.
	 * 
	 * @param keyStoreUri key store URI. If {@link #CLASSPATH_PROTOCOL} is used,
	 *            loaded from classpath.
	 * @param aliasPattern regular expression for aliases to load specific
	 *            certificates into the TrustManager.
	 * @param storePassword password for key store.
	 * @return array with TrustManager
	 * @throws IOException if key store could not be loaded.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws IllegalArgumentException if no matching certificates are found
	 */
	public static TrustManager[] loadDirectTrustManager(String keyStoreUri, String aliasPattern, char[] storePassword)
			throws IOException, GeneralSecurityException {
		Certificate[] trust = SslContextUtil.loadTrustedCertificates(keyStoreUri, aliasPattern, storePassword);
		return createDirectTrustManager("direct-trust", trust);
	}

	/**
	 * Create SSLContext with provided credentials and trusts using a empty issuer list.
	 * 
	 * @param alias alias to be used in KeyManager. Used for identification
	 *            according the X509ExtendedKeyManager API to select the
	 *            credentials matching the provided key. Though the create
	 *            KeyManager currently only supports on set of credentials, the
	 *            alias is only used to select that. If null, its replaced by a
	 *            default "californium".
	 * @param privateKey private key
	 * @param trustChain certificate trust chain related to private key.
	 * @param trusts trusted certificates. Not used as issuers.
	 * @return created SSLContext.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws IllegalArgumentException, if private key is null, or the chain is
	 *             null or empty, or the trusts null or empty.
	 */
	public static SSLContext createSSLContext(String alias, PrivateKey privateKey, X509Certificate[] chain,
			Certificate[] trusts) throws GeneralSecurityException {
		if (null == alias) {
			alias = "californium";
		}
		KeyManager[] keyManager = SslContextUtil.createKeyManager(alias, privateKey, chain);
		TrustManager[] trustManager = createDirectTrustManager(alias, trusts);
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(keyManager, trustManager, null);
		return sslContext;
	}

	/**
	 * Create "direct-trust" manager from trusted certificates.
	 * 
	 * @param alias alias to be used to store certificates in keystore.
	 * @param trusts trusted certificates for "direct-trust"
	 * @return trust manager for "direct-trust".
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws IllegalArgumentException if trusts is empty or null
	 */
	public static TrustManager[] createDirectTrustManager(String alias, final Certificate[] trusts)
			throws GeneralSecurityException {
		if (null == trusts || 0 == trusts.length) {
			throw new IllegalArgumentException("trusted certificates must be provided!");
		}
		LOG.log(Level.INFO, "{0}", SslContextLoggingUtil.supplier("direct-trust", trusts));
		TrustManager[] trustManagers = SslContextUtil.createTrustManager(alias, trusts);
		for (int index = 0; trustManagers.length > index; ++index) {
			if (trustManagers[index] instanceof X509ExtendedTrustManager) {
				trustManagers[index] = new DirectX509ExtendedTrustManager(
						(X509ExtendedTrustManager) trustManagers[index]);
			}
		}
		return trustManagers;
	}

	/**
	 * X509ExtendedTrustManager implementation not returning trusted
	 * certificates as issuer.
	 */
	private static class DirectX509ExtendedTrustManager extends X509ExtendedTrustManager {

		/**
		 * Empty array of issuers.
		 * 
		 * @see #getAcceptedIssuers()
		 */
		private static final X509Certificate[] EMPTY_ISSUERS = new X509Certificate[0];

		/**
		 * Origin trust manager. All calls, but {@link #getAcceptedIssuers()},
		 * are delegated to this manager.
		 */
		private final X509ExtendedTrustManager manager;

		/**
		 * Create instance of "direct-trust" X509ExtendedTrustManager.
		 * 
		 * @param manager origin manager. Calls are delegated to this manager.
		 */
		public DirectX509ExtendedTrustManager(final X509ExtendedTrustManager manager) {
			this.manager = manager;
		}

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			manager.checkClientTrusted(chain, authType);
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			manager.checkServerTrusted(chain, authType);
		}

		/**
		 * {@inheritDoc}
		 * 
		 * Though "direct trust" doesn't use issuer for trusting, return
		 * {@link #EMPTY_ISSUERS}.
		 */
		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return EMPTY_ISSUERS;
		}

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
				throws CertificateException {
			manager.checkClientTrusted(chain, authType, socket);
		}

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
				throws CertificateException {
			manager.checkClientTrusted(chain, authType, engine);
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
				throws CertificateException {
			manager.checkServerTrusted(chain, authType, socket);
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
				throws CertificateException {
			manager.checkServerTrusted(chain, authType, engine);
		}
	}
}
