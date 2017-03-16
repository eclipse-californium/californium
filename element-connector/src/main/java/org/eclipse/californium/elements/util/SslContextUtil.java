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
import java.io.InputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * Utility functions for {@link javax.net.ssl.SSLContext}.
 * 
 * This utility converts between the informations used by the javax SSL
 * implementation and the plain credentials used by scandium. It offers reading
 * KeyStores, extracting credentials, and creating KeyManager and TrustManager
 * from the KeyStores or extracted credentials. Java SSLContext is able to
 * maintain different key-certificate pairs for different key and signing
 * algorithms. The californium-scandium concentrates on embedded client and
 * therefore supports only one key-signing algorithm. This utility therefore
 * helps, to select the right credentials or create a javax security classes for
 * javax SSL implementation from that selected credentials.
 */
public class SslContextUtil {

	/**
	 * Pseudo protocol for key store URI. Used to load the key store from
	 * classpath.
	 */
	public static final String CLASSPATH_PROTOCOL = "classpath://";
	/**
	 * Separator for parameters.
	 * 
	 * @see #loadTrustedCertificates(String)
	 * @see #loadCredentials(String)
	 */
	public static final String PARAMETER_SEPARATOR = "#";

	/**
	 * Load trusted certificates from key store.
	 * 
	 * @param trust trust definition keystore#hexstorepwd#aliaspattern. If no
	 *            aliaspattern should be used, just leave it blank
	 *            keystore#hexstorepwd#
	 * @return array with trusted certificates.
	 * @throws IOException if key store could not be loaded.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws IllegalArgumentException if trust doesn't match
	 *             keystore#hexstorepwd#aliaspattern or no matching trusts are
	 *             found
	 * @throws NullPointerException if trust is null.
	 * @see #PARAMETER_SEPARATOR
	 */
	public static Certificate[] loadTrustedCertificates(String trust) throws IOException, GeneralSecurityException {
		if (null == trust) {
			throw new NullPointerException("trust must be provided!");
		}
		String[] parameters = trust.split(PARAMETER_SEPARATOR, 3);
		if (3 != parameters.length) {
			throw new IllegalArgumentException("trust must comply the pattern <keystore" + PARAMETER_SEPARATOR
					+ "hexstorepwd" + PARAMETER_SEPARATOR + "aliaspattern>");
		}
		return loadTrustedCertificates(parameters[0], parameters[2], StringUtil.hex2CharArray(parameters[1]));
	}

	/**
	 * Load credentials from key store.
	 * 
	 * @param credentials credentials definition
	 *            keystore#hexstorepwd#hexkeypwd#alias.
	 * @return credentials
	 * @throws IOException if key store could not be loaded.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws IllegalArgumentException if keys doesn't match
	 *             keystore#hexstorepwd#hexkeypwd#alias or no matching trusts
	 *             are found
	 * @throws NullPointerException if trust is null.
	 * @see #PARAMETER_SEPARATOR
	 */
	public static Credentials loadCredentials(String credentials) throws IOException, GeneralSecurityException {
		if (null == credentials) {
			throw new NullPointerException("credentials must be provided!");
		}
		String[] parameters = credentials.split(PARAMETER_SEPARATOR, 4);
		if (4 != parameters.length) {
			throw new IllegalArgumentException("credentials must comply the pattern <keystore" + PARAMETER_SEPARATOR
					+ "hexstorepwd" + PARAMETER_SEPARATOR + "hexkeypwd" + PARAMETER_SEPARATOR + "alias>");
		}
		return loadCredentials(parameters[0], parameters[3], StringUtil.hex2CharArray(parameters[1]),
				StringUtil.hex2CharArray(parameters[2]));
	}

	/**
	 * Load TrustManager from key store.
	 * 
	 * @param keyStoreUri key store URI. If {@link #CLASSPATH_PROTOCOL} is used,
	 *            loaded from classpath.
	 * @param aliasPattern regular expression for aliases to load only specific
	 *            certificates for the TrustManager. null to load all
	 *            certificates.
	 * @param storePassword password for key store.
	 * @return array with TrustManager
	 * @throws IOException if key store could not be loaded.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws IllegalArgumentException if no matching trusts are found
	 * @throws NullPointerException if keyStoreUri or storePassword is null.
	 */
	public static TrustManager[] loadTrustManager(String keyStoreUri, String aliasPattern, char[] storePassword)
			throws IOException, GeneralSecurityException {
		Certificate[] trustedCertificates = loadTrustedCertificates(keyStoreUri, aliasPattern, storePassword);
		return createTrustManager("trusts", trustedCertificates);
	}

	/**
	 * Load KeyManager from key store.
	 * 
	 * @param keyStoreUri key store URI. If {@link #CLASSPATH_PROTOCOL} is used,
	 *            loaded from classpath.
	 * @param alias alias to load only specific credentials into the KeyManager.
	 *            null to load all credentials into the KeyManager.
	 * @param storePassword password for key store.
	 * @param keyPassword password for private key.
	 * @return array with KeyManager
	 * @throws IOException if key store could not be loaded.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws IllegalArgumentException if no matching credentials are found
	 * @throws NullPointerException if keyStoreUri, storePassword, or
	 *             keyPassword is null.
	 */
	public static KeyManager[] loadKeyManager(String keyStoreUri, String alias, char[] storePassword,
			char[] keyPassword) throws IOException, GeneralSecurityException {
		if (null == keyPassword) {
			throw new NullPointerException("keyPassword must be provided!");
		}
		KeyStore ks = loadKeyStore(keyStoreUri, alias, storePassword, keyPassword);
		return createKeyManager(ks, keyPassword);
	}

	/**
	 * Load trusted certificates from key store.
	 * 
	 * @param keyStoreUri key store URI. If {@link #CLASSPATH_PROTOCOL} is used,
	 *            loaded from classpath.
	 * @param aliasPattern regular expression for aliases to load only specific
	 *            certificates for trusting. null to load all certificates.
	 * @param storePassword password for key store.
	 * @return array with trusted certificates.
	 * @throws IOException if key store could not be loaded.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws IllegalArgumentException if no matching certificates are found
	 * @throws NullPointerException if keyStoreUri or storePassword is null.
	 */
	public static Certificate[] loadTrustedCertificates(String keyStoreUri, String aliasPattern, char[] storePassword)
			throws IOException, GeneralSecurityException {
		KeyStore ks = loadKeyStore(keyStoreUri, storePassword);

		Pattern pattern = null;
		if (null != aliasPattern && !aliasPattern.isEmpty()) {
			pattern = Pattern.compile(aliasPattern);
		}
		List<Certificate> trustedCertificates = new ArrayList<Certificate>();
		for (Enumeration<String> e = ks.aliases(); e.hasMoreElements();) {
			String alias = e.nextElement();
			if (null != pattern) {
				Matcher matcher = pattern.matcher(alias);
				if (!matcher.matches()) {
					continue;
				}
			}
			Certificate certificate = ks.getCertificate(alias);
			if (null != certificate) {
				trustedCertificates.add(certificate);
			}
		}
		if (trustedCertificates.isEmpty()) {
			throw new IllegalArgumentException(
					"no trusted x509 certificates found in '" + keyStoreUri + "' for '" + aliasPattern + "'!");
		}
		return trustedCertificates.toArray(new Certificate[trustedCertificates.size()]);
	}

	/**
	 * Load credentials from key store.
	 * 
	 * @param keyStoreUri key store URI. If {@link #CLASSPATH_PROTOCOL} is used,
	 *            loaded from classpath.
	 * @param alias alias to load specific credentials.
	 * @param storePassword password for key store.
	 * @param keyPassword password for private key.
	 * @return credentials for the alias.
	 * @throws IOException if key store could not be loaded.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws IllegalArgumentException if alias is empty, or no matching
	 *             credentials are found.
	 * @throws NullPointerException if keyStoreUri, storePassword, keyPassword,
	 *             or alias is null.
	 */
	public static Credentials loadCredentials(String keyStoreUri, String alias, char[] storePassword,
			char[] keyPassword) throws IOException, GeneralSecurityException {
		if (null == alias) {
			throw new NullPointerException("alias must be provided!");
		}
		if (alias.isEmpty()) {
			throw new IllegalArgumentException("alias must not be empty!");
		}
		if (null == keyPassword) {
			throw new NullPointerException("keyPassword must be provided!");
		}
		KeyStore ks = loadKeyStore(keyStoreUri, storePassword);
		if (ks.entryInstanceOf(alias, PrivateKeyEntry.class)) {
			Entry entry = ks.getEntry(alias, new KeyStore.PasswordProtection(keyPassword));
			if (entry instanceof PrivateKeyEntry) {
				PrivateKeyEntry pkEntry = (PrivateKeyEntry) entry;
				Certificate[] chain = pkEntry.getCertificateChain();
				X509Certificate[] x509Chain = asX509Certificates(chain);
				return new Credentials(pkEntry.getPrivateKey(), x509Chain);
			}
		}
		throw new IllegalArgumentException("no credentials found for '" + alias + "' in '" + keyStoreUri + "'!");
	}

	/**
	 * Load certificate chain from key store.
	 * 
	 * @param keyStoreUri key store URI. If {@link #CLASSPATH_PROTOCOL} is used,
	 *            loaded from classpath.
	 * @param alias alias to load the certificate chain.
	 * @param storePassword password for key store.
	 * @return certificate chain for the alias.
	 * @throws IOException if key store could not be loaded.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws IllegalArgumentException if alias is empty, or no matching
	 *             certificate chain is found.
	 * @throws NullPointerException if keyStoreUri, storePassword, or alias is
	 *             null.
	 */
	public static X509Certificate[] loadCertificateChain(String keyStoreUri, String alias, char[] storePassword)
			throws IOException, GeneralSecurityException {
		if (null == alias) {
			throw new NullPointerException("alias must be provided!");
		}
		if (alias.isEmpty()) {
			throw new IllegalArgumentException("alias must not be empty!");
		}
		KeyStore ks = loadKeyStore(keyStoreUri, storePassword);
		Certificate[] chain = ks.getCertificateChain(alias);
		return asX509Certificates(chain);
	}

	/**
	 * Load key store.
	 * 
	 * @param keyStoreUri key store URI. If {@link #CLASSPATH_PROTOCOL} is used,
	 *            loaded from classpath.
	 * @param alias alias to load only the specific entries to the key store.
	 *            null to load the complete key store.
	 * @param storePassword password for key store.
	 * @param keyPassword password for private key. Not required for
	 *            certificates.
	 * @return key store.
	 * @throws IOException if key store could not be loaded.
	 * @throws GeneralSecurityException if security setup failed, or no
	 *             credentials or certificates are available for the provided
	 *             alias.
	 * @throws NullPointerException if keyStoreUri or storePassword is null.
	 */
	private static KeyStore loadKeyStore(String keyStoreUri, String alias, char[] storePassword, char[] keyPassword)
			throws IOException, GeneralSecurityException {
		KeyStore ks = loadKeyStore(keyStoreUri, storePassword);
		if (null == alias || alias.isEmpty()) {
			return ks;
		}
		if (null == keyPassword) {
			Certificate certificate = ks.getCertificate(alias);
			if (null != certificate) {
				KeyStore ksAlias = KeyStore.getInstance("JKS");
				ksAlias.load(null);
				ksAlias.setCertificateEntry(alias, certificate);
				return ksAlias;
			}
			throw new GeneralSecurityException(
					"key stores '" + keyStoreUri + "' doesn't contain certificates for '" + alias + "'");
		} else {
			Entry entry = ks.getEntry(alias, new KeyStore.PasswordProtection(keyPassword));
			if (null != entry) {
				KeyStore ksAlias = KeyStore.getInstance("JKS");
				ksAlias.load(null);
				ksAlias.setEntry(alias, entry, new KeyStore.PasswordProtection(keyPassword));
				return ksAlias;
			}
			throw new GeneralSecurityException(
					"key stores '" + keyStoreUri + "' doesn't contain credentials for '" + alias + "'");
		}
	}

	/**
	 * Load key store.
	 * 
	 * @param keyStoreUri key store URI. If {@link #CLASSPATH_PROTOCOL} is used,
	 *            loaded from classpath.
	 * @param storePassword password for key store.
	 * @return key store
	 * @throws IOException if key store could not be loaded.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws NullPointerException if keyStoreUri or storePassword is null.
	 */
	private static KeyStore loadKeyStore(String keyStoreUri, char[] storePassword)
			throws GeneralSecurityException, IOException {
		if (null == keyStoreUri) {
			throw new NullPointerException("keyStoreUri must be provided!");
		}
		if (null == storePassword) {
			throw new NullPointerException("storePassword must be provided!");
		}
		InputStream inStream;
		if (keyStoreUri.startsWith(CLASSPATH_PROTOCOL)) {
			String resource = keyStoreUri.substring(CLASSPATH_PROTOCOL.length());
			inStream = SslContextUtil.class.getClassLoader().getResourceAsStream(resource);
			if (null == inStream) {
				throw new IOException("'" + keyStoreUri + "' not found!");
			}
		} else {
			URL url = new URL(keyStoreUri);
			inStream = url.openStream();
		}
		try {
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(inStream, storePassword);
			return keyStore;
		} finally {
			inStream.close();
		}
	}

	/**
	 * Return certificates as x509 certificates.
	 * 
	 * Ensure, that all provided certificates are x509.
	 * 
	 * @param certificates to check
	 * @return array with x509 certificates.
	 * @throws IllegalArgumentException if null, a empty array is provided or a
	 *             none x509 certificate was found or a array entry was null.
	 */
	private static X509Certificate[] asX509Certificates(Certificate[] certificates) {
		if (null == certificates || 0 == certificates.length) {
			throw new IllegalArgumentException("certificates missing!");
		}
		X509Certificate[] x509Certificates = new X509Certificate[certificates.length];
		for (int index = 0; certificates.length > index; ++index) {
			if (null == certificates[index]) {
				throw new IllegalArgumentException("[" + index + "] is null!");
			}
			try {
				x509Certificates[index] = (X509Certificate) certificates[index];
			} catch (ClassCastException e) {
				throw new IllegalArgumentException("[" + index + "] is not a x509 certificate! Instead it's a "
						+ certificates[index].getClass().getName());
			}
		}
		return x509Certificates;
	}

	/**
	 * Create SSLContext with provided credentials and trusts.
	 * 
	 * @param alias alias to be used in KeyManager. Used for identification
	 *            according the X509ExtendedKeyManager API to select the
	 *            credentials matching the provided key. Though the create
	 *            KeyManager currently only supports on set of credentials, the
	 *            alias is only used to select that. If null, its replaced by a
	 *            default "californium".
	 * @param privateKey private key
	 * @param chain certificate trust chain related to private key.
	 * @param trusts trusted certificates.
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
		KeyManager[] keyManager = createKeyManager(alias, privateKey, chain);
		TrustManager[] trustManager = createTrustManager(alias, trusts);
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(keyManager, trustManager, null);
		return sslContext;
	}

	/**
	 * Create key manager from private key and certificate path. Creates a
	 * {@link KeyStore} to use {@link KeyManagerFactory}.
	 * 
	 * @param alias alias to be used for key store
	 * @param privateKey private key
	 * @param chain certificate chain.
	 * @return key manager.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws IllegalArgumentException, if private key is null, or the chain is
	 *             null or empty.
	 */
	public static KeyManager[] createKeyManager(String alias, PrivateKey privateKey, X509Certificate[] chain)
			throws GeneralSecurityException {
		if (null == privateKey) {
			throw new NullPointerException("private key must be provided!");
		}
		if (null == chain) {
			throw new NullPointerException("certificate chain must be provided!");
		}
		if (0 == chain.length) {
			throw new IllegalArgumentException("certificate chain must not be empty!");
		}
		if (null == alias) {
			alias = "californium";
		}
		try {
			/* key used for creating a non-persistent KeyStore */
			char[] key = "intern".toCharArray();
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(null);
			ks.setKeyEntry(alias, privateKey, key, chain);
			return createKeyManager(ks, key);
		} catch (IOException e) {
			throw new GeneralSecurityException(e.getMessage());
		}
	}

	/**
	 * Create trust manager from trusted certificates. Creates a
	 * {@link KeyStore} to use {@link TrustManagerFactory}.
	 * 
	 * @param alias alias to be used for key store.
	 * @param trusts trusted certificates
	 * @return trust manager
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws NullPointerException, if trusted certificates is null.
	 * @throws IllegalArgumentException, if trusted certificates is empty.
	 */
	public static TrustManager[] createTrustManager(String alias, Certificate[] trusts)
			throws GeneralSecurityException {
		if (null == trusts) {
			throw new NullPointerException("trusted certificates must be provided!");
		}
		if (0 == trusts.length) {
			throw new IllegalArgumentException("trusted certificates must not be empty!");
		}
		if (null == alias) {
			alias = "californium";
		}
		try {
			int index = 1;
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(null);
			for (Certificate certificate : trusts) {
				ks.setCertificateEntry(alias + index, certificate);
				++index;
			}
			return createTrustManager(ks);
		} catch (IOException e) {
			throw new GeneralSecurityException(e.getMessage());
		}
	}

	/**
	 * Create key manager from key store.
	 *
	 * @param store key store
	 * @param keyPassword password for private key
	 * @return key manager
	 * @throws GeneralSecurityException if security setup failed.
	 */
	private static KeyManager[] createKeyManager(KeyStore store, char[] keyPassword) throws GeneralSecurityException {
		String algorithm = Security.getProperty("ssl.KeyManagerFactory.algorithm");
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
		kmf.init(store, keyPassword);
		return kmf.getKeyManagers();
	}

	/**
	 * Create trust manager from key store.
	 * 
	 * @param store key store
	 * @return trust manager
	 * @throws GeneralSecurityException if security setup failed.
	 */
	private static TrustManager[] createTrustManager(KeyStore store) throws GeneralSecurityException {
		String algorithm = Security.getProperty("ssl.TrustManagerFactory.algorithm");
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(algorithm);
		tmf.init(store);
		return tmf.getTrustManagers();
	}

	/**
	 * Credentials. Pair of private key and certificate trustedChain.
	 */
	public static class Credentials {

		/**
		 * Private key.
		 */
		private final PrivateKey privateKey;
		/**
		 * Certificate trustedChain.
		 */
		private final X509Certificate[] chain;

		/**
		 * Create credentials.
		 * 
		 * @param privateKey private key
		 * @param trustedChain certificate trustedChain
		 */
		private Credentials(PrivateKey privateKey, X509Certificate[] chain) {
			this.privateKey = privateKey;
			this.chain = chain;
		}

		/**
		 * Get private key.
		 * 
		 * @return private key
		 */
		public PrivateKey getPrivateKey() {
			return privateKey;
		}

		/**
		 * Get certificate trustedChain.
		 * 
		 * @return certificate trustedChain
		 */
		public X509Certificate[] getCertificateChain() {
			return chain;
		}
	}
}
