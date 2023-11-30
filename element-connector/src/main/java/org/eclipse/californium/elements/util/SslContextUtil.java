/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation.
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce configurable
 *                                                    key store type and
 *                                                    InputStreamFactory.
 *    Achim Kraus (Bosch Software Innovations GmbH) - use file system, if
 *                                                    no scheme is provided in URI
 *    Achim Kraus (Bosch Software Innovations GmbH) - add SSLContext protocol to
 *                                                    selective disable TLSv1.3 for
 *                                                    TLSv1.2 dependent unit tests.
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
 * 
 * The utility provides a configurable mapping of URI endings with key store
 * type, enable to use different KeyStore implementations and formats. The URI
 * ending is defined as the part starting with the last "." after all "/"
 * separator. e.g.: "cert/keyStore.p12" has ending ".p12", and
 * "cert/keyStore.p12/test" has no ending. The currently pre-configured mapping
 * contains:
 * 
 * <pre>
 * ".jks" to "JKS"
 * ".bks" to "BKS"
 * ".p12" to "PKCS12"
 * ".pem" to "CRT/PEM" (custom reader)
 * ".crt" to "CRT/PEM" (custom reader)
 * "*" to system default
 * </pre>
 * 
 * CRT/PEM Custom Reader: Read private keys (PKCS8 and PKCS12 (EC only)), public
 * key (x509), and certificates (x509). These credentials are stored in the PEM
 * format, which is base64 encoded. The sections of the file contains a
 * description of the encoded credential. If a general load function is used,
 * {@link Credentials} are returned with the loaded data filled in.
 * 
 * Example:
 * 
 * <pre>
 * -----BEGIN EC PRIVATE KEY-----
 * MHcCAQEEIBw7lyMR21FDpCecT0bNr4oKBuYw1VdNnCB5xSS4dQrcoAoGCCqGSM49
 * AwEHoUQDQgAETY8Y02TZuaRUQvXnguxg6EPN7wR5vzxthmDk+6vvf6oJgBylWIU2
 * E3khCBkZM9Um7JCA9/kcbNezwJDzyQAnIw==
 * -----END EC PRIVATE KEY-----
 * </pre>
 *
 * You may use
 * <a href="https://lapo.it/asn1js" target="_blank">lapo.it/asn1js</a> to decode
 * the content. Please ensure, that you only provide test- or demo-credentials.
 * 
 * If that example file is loaded with {@link #loadCredentials(String)} the
 * returned {@link Credentials} contains a private key, and here, also the
 * corresponding public key.
 * 
 * The utility provides also a configurable input stream factory of URI schemes.
 * Currently only {@link #CLASSPATH_SCHEME} is pre-configured to load key stores
 * from the classpath. If the scheme of the URI has no configured input stream
 * factory, the URI is loaded with {@link URL#URL(String)}.
 * 
 * Note: It is not intended, that the configuration is changed during usage,
 * this may cause race conditions! Currently this class provides a class level
 * access based API. Therefore only one configuration at all is possible.
 * Depending on the usage, this may change to instance level access based API to
 * support more parallel configurations to be used.
 * 
 * @see #configure(String, KeyStoreType)
 * @see #configure(String, InputStreamFactory)
 */
public class SslContextUtil {

	/**
	 * The logger.
	 * 
	 * @deprecated scope will change to private.
	 */
	@Deprecated
	public static final Logger LOGGER = LoggerFactory.getLogger(SslContextUtil.class);

	/**
	 * Scheme for key store URI. Used to load the key stores from classpath.
	 */
	public static final String CLASSPATH_SCHEME = "classpath://";
	/**
	 * Separator for parameters.
	 * 
	 * @see #loadTrustedCertificates(String)
	 * @see #loadCredentials(String)
	 */
	public static final String PARAMETER_SEPARATOR = "#";
	/**
	 * Ending for key stores with type {@link #JKS_TYPE}.
	 */
	public static final String JKS_ENDING = ".jks";
	/**
	 * Ending for key stores with type {@link #BKS_TYPE}.
	 */
	public static final String BKS_ENDING = ".bks";
	/**
	 * Ending for key stores with type {@link #PKCS12_TYPE}.
	 */
	public static final String PKCS12_ENDING = ".p12";
	/**
	 * Ending for CRT/PEM key stores.
	 * 
	 * @see SimpleKeyStore
	 * @see #CRT_ENDING
	 */
	public static final String PEM_ENDING = ".pem";
	/**
	 * Ending for CRT/PEM key stores.
	 * 
	 * @see SimpleKeyStore
	 * @see #PEM_ENDING
	 */
	public static final String CRT_ENDING = ".crt";
	/**
	 * Label to provide default key store type.
	 */
	public static final String DEFAULT_ENDING = "*";
	/**
	 * Key store type JKS.
	 */
	public static final String JKS_TYPE = "JKS";
	/**
	 * Key store type BKS.
	 */
	public static final String BKS_TYPE = "BKS";
	/**
	 * Key store type PKCS12.
	 */
	public static final String PKCS12_TYPE = "PKCS12";
	/**
	 * Default protocol used for
	 * {@link #createSSLContext(String, PrivateKey, X509Certificate[], Certificate[])}.
	 */
	public static final String DEFAULT_SSL_PROTOCOL = "TLSv1.2";
	/**
	 * Schema delimiter.
	 */
	private static final String SCHEME_DELIMITER = "://";
	/**
	 * Default alias.
	 */
	private static final String DEFAULT_ALIAS = "californium";
	/**
	 * Map URI endings to key store types.
	 * 
	 * @see #configure(String, KeyStoreType)
	 * @see #getKeyStoreTypeFromUri(String)
	 */
	private static final Map<String, KeyStoreType> KEY_STORE_TYPES = new ConcurrentHashMap<>();
	/**
	 * Map URI scheme to input stream factories.
	 * 
	 * @see #configure(String, InputStreamFactory)
	 * @see #getInputStreamFromUri(String)
	 */
	private static final Map<String, InputStreamFactory> INPUT_STREAM_FACTORIES = new ConcurrentHashMap<>();

	/**
	 * Anonymous key manager.
	 * 
	 * @since 2.4
	 */
	private static final KeyManager ANONYMOUS = new AnonymousX509ExtendedKeyManager();

	/**
	 * TrustManager to trust all.
	 * 
	 * @since 2.4
	 */
	private static final TrustManager TRUST_ALL;

	static {
		JceProviderUtil.init();
		configureDefaults();
		TrustManager trustAll;
		try {
			trustAll = new X509ExtendedTrustAllManager();
		} catch (NoClassDefFoundError ex) {
			trustAll = new X509TrustAllManager();
		}
		TRUST_ALL = trustAll;
	}

	/**
	 * Load trusted certificates from key store.
	 * 
	 * @param trust trust definition keystore#hexstorepwd#aliaspattern or
	 *            keystore.pem. If no aliaspattern should be used, just leave it
	 *            blank keystore#hexstorepwd#
	 * @return array with trusted certificates.
	 * @throws IOException if key store could not be loaded.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws IllegalArgumentException if trust doesn't match
	 *             keystore#hexstorepwd#aliaspattern or no matching trusts are
	 *             found
	 * @throws NullPointerException if trust is {@code null}.
	 * @see #PARAMETER_SEPARATOR
	 */
	public static Certificate[] loadTrustedCertificates(String trust) throws IOException, GeneralSecurityException {
		if (null == trust) {
			throw new NullPointerException("trust must be provided!");
		}
		String[] parameters = trust.split(PARAMETER_SEPARATOR, 3);
		if (1 == parameters.length) {
			KeyStoreType configuration = getKeyStoreTypeFromUri(parameters[0]);
			if (configuration.simpleStore != null) {
				return loadTrustedCertificates(parameters[0], null, null);
			}
		}
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
	 *            keystore#hexstorepwd#hexkeypwd#alias or keystore.pem
	 * @return credentials
	 * @throws IOException if key store could not be loaded.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws IllegalArgumentException if keys doesn't match
	 *             keystore#hexstorepwd#hexkeypwd#alias or no matching trusts
	 *             are found
	 * @throws IncompleteCredentialsException if either private key or
	 *             certificate chain and public key is missing.
	 * @throws NullPointerException if credentials is {@code null}.
	 * @see #PARAMETER_SEPARATOR
	 * @since 3.0 IncompleteCredentialsException added
	 */
	public static Credentials loadCredentials(String credentials) throws IOException, GeneralSecurityException {
		if (null == credentials) {
			throw new NullPointerException("credentials must be provided!");
		}
		String[] parameters = credentials.split(PARAMETER_SEPARATOR, 4);
		if (1 == parameters.length) {
			KeyStoreType configuration = getKeyStoreTypeFromUri(parameters[0]);
			if (configuration.simpleStore != null) {
				return loadCredentials(parameters[0], null, null, null);
			}
		}
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
	 * @param keyStoreUri key store URI. Supports configurable URI scheme based
	 *            input streams and URI ending based key store type.
	 * @param aliasPattern regular expression for aliases to load only specific
	 *            certificates for the TrustManager. null to load all
	 *            certificates.
	 * @param storePassword password for key store.
	 * @return array with TrustManager
	 * @throws IOException if key store could not be loaded.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws IllegalArgumentException if no matching trusts are found
	 * @throws NullPointerException if keyStoreUri or storePassword is
	 *             {@code null}.
	 */
	public static TrustManager[] loadTrustManager(String keyStoreUri, String aliasPattern, char[] storePassword)
			throws IOException, GeneralSecurityException {
		Certificate[] trustedCertificates = loadTrustedCertificates(keyStoreUri, aliasPattern, storePassword);
		return createTrustManager("trusts", trustedCertificates);
	}

	/**
	 * Load KeyManager from key store.
	 * 
	 * @param keyStoreUri key store URI. Supports configurable URI scheme based
	 *            input streams and URI ending based key store type.
	 * @param aliasPattern alias pattern to load only specific credentials into
	 *            the KeyManager. null to load all credentials into the
	 *            KeyManager.
	 * @param storePassword password for key store.
	 * @param keyPassword password for private key.
	 * @return array with KeyManager
	 * @throws IOException if key store could not be loaded.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws IllegalArgumentException if no matching credentials are found
	 * @throws NullPointerException if keyStoreUri, storePassword, or
	 *             keyPassword is {@code null}.
	 * @since 3.0 (add support for alias pattern)
	 */
	public static KeyManager[] loadKeyManager(String keyStoreUri, String aliasPattern, char[] storePassword,
			char[] keyPassword) throws IOException, GeneralSecurityException {
		KeyStoreType configuration = getKeyStoreTypeFromUri(keyStoreUri);
		KeyStore ks;
		if (configuration.simpleStore != null) {
			Credentials credentials = loadSimpleKeyStore(keyStoreUri, configuration);
			if (credentials.privateKey == null) {
				throw new IllegalArgumentException("credentials missing! No private key found!");
			}
			if (credentials.chain == null) {
				throw new IllegalArgumentException("credentials missing! No certificate chain found!");
			}
			return createKeyManager(DEFAULT_ALIAS, credentials.privateKey, credentials.chain);
		} else {
			if (null == keyPassword) {
				throw new NullPointerException("keyPassword must be provided!");
			}
			ks = loadKeyStore(keyStoreUri, storePassword, configuration);
			if (aliasPattern != null && !aliasPattern.isEmpty()) {
				boolean found = false;
				;
				Pattern pattern = Pattern.compile(aliasPattern);
				KeyStore ksAlias = KeyStore.getInstance(ks.getType());
				ksAlias.load(null);
				for (Enumeration<String> e = ks.aliases(); e.hasMoreElements();) {
					String alias = e.nextElement();
					Matcher matcher = pattern.matcher(alias);
					if (!matcher.matches()) {
						continue;
					}
					Entry entry = ks.getEntry(alias, new KeyStore.PasswordProtection(keyPassword));
					if (null != entry) {
						ksAlias.setEntry(alias, entry, new KeyStore.PasswordProtection(keyPassword));
						found = true;
					} else {
						throw new GeneralSecurityException(
								"key stores '" + keyStoreUri + "' doesn't contain credentials for '" + alias + "'");
					}
				}
				if (!found) {
					throw new GeneralSecurityException(
							"no credentials found in '" + keyStoreUri + "' for '" + aliasPattern + "'!");
				}
				ks = ksAlias;
			}
			return createKeyManager(ks, keyPassword);
		}
	}

	/**
	 * Load trusted certificates from key store.
	 * 
	 * @param keyStoreUri key store URI. Supports configurable URI scheme based
	 *            input streams and URI ending based key store type.
	 * @param aliasPattern regular expression for aliases to load only specific
	 *            certificates for trusting. null to load all certificates.
	 * @param storePassword password for key store.
	 * @return array with trusted certificates.
	 * @throws IOException if key store could not be loaded.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws IllegalArgumentException if no matching certificates are found
	 * @throws NullPointerException if keyStoreUri or storePassword is
	 *             {@code null}.
	 */
	public static Certificate[] loadTrustedCertificates(String keyStoreUri, String aliasPattern, char[] storePassword)
			throws IOException, GeneralSecurityException {
		KeyStoreType configuration = getKeyStoreTypeFromUri(keyStoreUri);
		if (configuration.simpleStore != null) {
			Credentials credentials = loadSimpleKeyStore(keyStoreUri, configuration);
			if (credentials.trusts != null) {
				return credentials.trusts;
			} else if (credentials.chain != null) {
				return credentials.chain;
			}
			throw new IllegalArgumentException("no trusted x509 certificates found in '" + keyStoreUri + "'!");
		}

		KeyStore ks = loadKeyStore(keyStoreUri, storePassword, configuration);

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
			if (!trustedCertificates.contains(certificate)) {
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
	 * @param keyStoreUri key store URI. Supports configurable URI scheme based
	 *            input streams and URI ending based key store type.
	 * @param alias alias to load specific credentials.
	 * @param storePassword password for key store.
	 * @param keyPassword password for private key.
	 * @return credentials for the alias.
	 * @throws IOException if key store could not be loaded.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws IllegalArgumentException if alias is empty, or no matching
	 *             credentials are found.
	 * @throws IncompleteCredentialsException if either private key or
	 *             certificate chain and public key is missing.
	 * @throws NullPointerException if keyStoreUri, storePassword, keyPassword,
	 *             or alias is {@code null}.
	 * @since 3.0 IncompleteCredentialsException added
	 */
	public static Credentials loadCredentials(String keyStoreUri, String alias, char[] storePassword,
			char[] keyPassword) throws IOException, GeneralSecurityException {
		KeyStoreType configuration = getKeyStoreTypeFromUri(keyStoreUri);
		if (configuration.simpleStore != null) {
			Credentials credentials = loadSimpleKeyStore(keyStoreUri, configuration);
			if (credentials.publicKey == null && credentials.privateKey == null) {
				throw new IllegalArgumentException("credentials missing! No keys found!");
			} else if (credentials.privateKey == null) {
				throw new IncompleteCredentialsException(credentials, "credentials missing! No private key found!");
			} else if (credentials.publicKey == null) {
				throw new IncompleteCredentialsException(credentials,
						"credentials missing! Neither certificate chain nor public key found!");
			}
			return credentials;
		}
		if (null == alias) {
			throw new NullPointerException("alias must be provided!");
		}
		if (alias.isEmpty()) {
			throw new IllegalArgumentException("alias must not be empty!");
		}
		if (null == keyPassword) {
			throw new NullPointerException("keyPassword must be provided!");
		}
		KeyStore ks = loadKeyStore(keyStoreUri, storePassword, configuration);
		if (ks.entryInstanceOf(alias, PrivateKeyEntry.class)) {
			Entry entry = ks.getEntry(alias, new KeyStore.PasswordProtection(keyPassword));
			if (entry instanceof PrivateKeyEntry) {
				PrivateKeyEntry pkEntry = (PrivateKeyEntry) entry;
				Certificate[] chain = pkEntry.getCertificateChain();
				X509Certificate[] x509Chain = asX509Certificates(chain);
				return new Credentials(pkEntry.getPrivateKey(), null, x509Chain);
			}
		}
		throw new IllegalArgumentException("no credentials found for '" + alias + "' in '" + keyStoreUri + "'!");
	}

	/**
	 * Load private key from key store.
	 * 
	 * @param keyStoreUri key store URI. Supports configurable URI scheme based
	 *            input streams and URI ending based key store type.
	 * @param alias alias to load specific credentials.
	 * @param storePassword password for key store.
	 * @param keyPassword password for private key.
	 * @return private key for the alias.
	 * @throws IOException if key store could not be loaded.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws IllegalArgumentException if alias is empty, or no matching
	 *             credentials are found.
	 * @throws NullPointerException if keyStoreUri, storePassword, keyPassword,
	 *             or alias is {@code null}.
	 */
	public static PrivateKey loadPrivateKey(String keyStoreUri, String alias, char[] storePassword, char[] keyPassword)
			throws IOException, GeneralSecurityException {
		KeyStoreType configuration = getKeyStoreTypeFromUri(keyStoreUri);
		if (configuration.simpleStore != null) {
			Credentials credentials = loadSimpleKeyStore(keyStoreUri, configuration);
			if (credentials.privateKey != null) {
				return credentials.privateKey;
			}
		} else {
			if (null == alias) {
				throw new NullPointerException("alias must be provided!");
			}
			if (alias.isEmpty()) {
				throw new IllegalArgumentException("alias must not be empty!");
			}
			if (null == keyPassword) {
				throw new NullPointerException("keyPassword must be provided!");
			}
			KeyStore ks = loadKeyStore(keyStoreUri, storePassword, configuration);
			if (ks.entryInstanceOf(alias, PrivateKeyEntry.class)) {
				Entry entry = ks.getEntry(alias, new KeyStore.PasswordProtection(keyPassword));
				if (entry instanceof PrivateKeyEntry) {
					PrivateKeyEntry pkEntry = (PrivateKeyEntry) entry;
					return pkEntry.getPrivateKey();
				}
			}
		}
		throw new IllegalArgumentException("no private key found for '" + alias + "' in '" + keyStoreUri + "'!");
	}

	/**
	 * Load public key from key store.
	 * 
	 * @param keyStoreUri key store URI. Supports configurable URI scheme based
	 *            input streams and URI ending based key store type.
	 * @param alias alias to load specific credentials.
	 * @param storePassword password for key store.
	 * @return public key for the alias.
	 * @throws IOException if key store could not be loaded.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws IllegalArgumentException if alias is empty, or no matching
	 *             credentials are found.
	 * @throws NullPointerException if keyStoreUri, storePassword, keyPassword,
	 *             or alias is {@code null}.
	 */
	public static PublicKey loadPublicKey(String keyStoreUri, String alias, char[] storePassword)
			throws IOException, GeneralSecurityException {
		KeyStoreType configuration = getKeyStoreTypeFromUri(keyStoreUri);
		if (configuration.simpleStore != null) {
			Credentials credentials = loadSimpleKeyStore(keyStoreUri, configuration);
			if (credentials.publicKey != null) {
				return credentials.publicKey;
			}
		} else {
			if (null == alias) {
				throw new NullPointerException("alias must be provided!");
			}
			if (alias.isEmpty()) {
				throw new IllegalArgumentException("alias must not be empty!");
			}
			KeyStore ks = loadKeyStore(keyStoreUri, storePassword, configuration);
			Certificate[] chain = ks.getCertificateChain(alias);
			return chain[0].getPublicKey();
		}
		throw new IllegalArgumentException("no public key found for '" + alias + "' in '" + keyStoreUri + "'!");
	}

	/**
	 * Load certificate chain from key store.
	 * 
	 * @param keyStoreUri key store URI. Supports configurable URI scheme based
	 *            input streams and URI ending based key store type.
	 * @param alias alias to load the certificate chain.
	 * @param storePassword password for key store.
	 * @return certificate chain for the alias.
	 * @throws IOException if key store could not be loaded.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws IllegalArgumentException if alias is empty, or no matching
	 *             certificate chain is found.
	 * @throws NullPointerException if keyStoreUri, storePassword, or alias is
	 *             {@code null}.
	 */
	public static X509Certificate[] loadCertificateChain(String keyStoreUri, String alias, char[] storePassword)
			throws IOException, GeneralSecurityException {
		KeyStoreType configuration = getKeyStoreTypeFromUri(keyStoreUri);
		if (configuration.simpleStore != null) {
			Credentials credentials = loadSimpleKeyStore(keyStoreUri, configuration);
			if (credentials.chain == null) {
				throw new IllegalArgumentException("No certificate chain found!");
			}
			return credentials.chain;
		}
		if (null == alias) {
			throw new NullPointerException("alias must be provided!");
		}
		if (alias.isEmpty()) {
			throw new IllegalArgumentException("alias must not be empty!");
		}
		KeyStore ks = loadKeyStore(keyStoreUri, storePassword, configuration);
		Certificate[] chain = ks.getCertificateChain(alias);
		return asX509Certificates(chain);
	}

	/**
	 * Configure defaults.
	 * 
	 * Key store type:
	 * 
	 * <pre>
	 * ".jks" to "JKS"
	 * ".bks" to "BKS"
	 * ".p12" to "PKCS12"
	 * ".pem" to "CRT/PEM" (custom reader)
	 * ".crt" to "CRT/PEM" (custom reader)
	 * "*" to system default
	 * </pre>
	 * 
	 * Input stream factory: {@link #CLASSPATH_SCHEME} to classpath loader.
	 * 
	 * Clear previous configuration. Custom entry must be added again using
	 * {@link #configure(String, InputStreamFactory)},
	 * {@link #configure(String, KeyStoreType)}, and
	 * {@link #configureAlias(String, String)}.
	 */
	public static void configureDefaults() {
		KEY_STORE_TYPES.clear();

		KEY_STORE_TYPES.put(JKS_ENDING, new KeyStoreType(JKS_TYPE));
		KEY_STORE_TYPES.put(BKS_ENDING, new KeyStoreType(BKS_TYPE));
		KEY_STORE_TYPES.put(PKCS12_ENDING, new KeyStoreType(PKCS12_TYPE));

		KeyStoreType simple = new KeyStoreType(new SimpleKeyStore() {

			@Override
			public Credentials load(InputStream inputStream) throws GeneralSecurityException, IOException {
				return loadPemCredentials(inputStream);
			}
		});

		KEY_STORE_TYPES.put(PEM_ENDING, simple);
		KEY_STORE_TYPES.put(CRT_ENDING, simple);
		KEY_STORE_TYPES.put(DEFAULT_ENDING, new KeyStoreType(KeyStore.getDefaultType()));

		INPUT_STREAM_FACTORIES.clear();
		INPUT_STREAM_FACTORIES.put(CLASSPATH_SCHEME, new ClassLoaderInputStreamFactory());
	}

	/**
	 * Configure a {@link KeyStoreType} for a URI ending.
	 * 
	 * @param ending URI ending. If {@link #DEFAULT_ENDING} is used, the key
	 *            store default type is configured. Ending is converted to lower
	 *            case before added to the {@link #KEY_STORE_TYPES}.
	 * @param type the key store type.
	 * @return previous key store type, or {@code null}, if no key store type
	 *         was configured before
	 * @throws NullPointerException if ending or type is {@code null}.
	 * @throws IllegalArgumentException if ending doesn't start with "." and
	 *             isn't {@link #DEFAULT_ENDING}.
	 * @since 3.0 (changed parameter type to KeyStoreType)
	 */
	public static KeyStoreType configure(String ending, KeyStoreType type) {
		if (ending == null) {
			throw new NullPointerException("ending must not be null!");
		}
		if (!ending.equals(DEFAULT_ENDING) && !ending.startsWith(".")) {
			throw new IllegalArgumentException("ending must start with \".\"!");
		}
		if (type == null) {
			throw new NullPointerException("key store type must not be null!");
		}
		return KEY_STORE_TYPES.put(ending.toLowerCase(), type);
	}

	/**
	 * Add alias for ending.
	 * 
	 * Use the same {@link KeyStoreType} for the alias as for the ending.
	 * 
	 * @param alias new alias
	 * @param ending already configured ending
	 * @return previous key store type, or {@code null}, if no key store type
	 *         was configured before
	 * @throws NullPointerException if alias of ending is {@code null}.
	 * @throws IllegalArgumentException if alias and ending are equal, or alias
	 *             or ending doesn't start with "." and isn't
	 *             {@link #DEFAULT_ENDING}.
	 * @since 3.6
	 */
	public static KeyStoreType configureAlias(String alias, String ending) {
		if (alias == null) {
			throw new NullPointerException("alias must not be null!");
		}
		if (ending == null) {
			throw new NullPointerException("ending must not be null!");
		}
		if (ending.equals(alias)) {
			throw new IllegalArgumentException("alias must differ from ending!");
		}
		if (!ending.equals(DEFAULT_ENDING) && !ending.startsWith(".")) {
			throw new IllegalArgumentException("ending must start with \".\"!");
		}
		if (!alias.equals(DEFAULT_ENDING) && !ending.startsWith(".")) {
			throw new IllegalArgumentException("alias must start with \".\"!");
		}
		KeyStoreType type = KEY_STORE_TYPES.get(ending);
		if (type == null) {
			throw new IllegalArgumentException("ending must already be configured!");
		}
		return KEY_STORE_TYPES.put(alias, type);
	}

	/**
	 * Configure input stream factory for URI scheme.
	 * 
	 * @param scheme URI scheme. Scheme is converted to lower case before added
	 *            to the {@link #INPUT_STREAM_FACTORIES}.
	 * @param streamFactory input stream factory to read key stores access with
	 *            this URI scheme.
	 * @return previous stream factory, if already configure, or {@code null},
	 *         if not stream factory was previously configured.
	 * @throws NullPointerException if scheme or stream factory is {@code null}.
	 * @throws IllegalArgumentException if scheme doesn't end with "://".
	 */
	public static InputStreamFactory configure(String scheme, InputStreamFactory streamFactory) {
		if (scheme == null) {
			throw new NullPointerException("scheme must not be null!");
		}
		if (!scheme.endsWith(SCHEME_DELIMITER)) {
			throw new IllegalArgumentException("scheme must end with \"" + SCHEME_DELIMITER + "\"!");
		}
		if (streamFactory == null) {
			throw new NullPointerException("stream factory must not be null!");
		}
		return INPUT_STREAM_FACTORIES.put(scheme.toLowerCase(), streamFactory);
	}

	/**
	 * Check, if input stream from URI is available.
	 * 
	 * @param keyStoreUri URI of input stream
	 * @return {@code true}, if available, {@code false}, if not.
	 * @throws NullPointerException if the keyStoreUri is {@code null}
	 * @since 3.0
	 */
	public static boolean isAvailableFromUri(String keyStoreUri) {
		try {
			InputStream in = getInputStreamFromUri(keyStoreUri);
			if (in != null) {
				in.close();
				return true;
			}
		} catch (IOException ex) {
		}
		return false;
	}

	/**
	 * Get key store type from URI.
	 * 
	 * Get the configured key store type for URI ending from
	 * {@link #KEY_STORE_TYPES}. If no key store type for URI ending is
	 * available, get the key store type for {@link #DEFAULT_ENDING}.
	 * 
	 * @param uri URI provide ending for lookup. Converted to lower case before
	 *            used.
	 * @return configured key store type for ending or default, if ending is not
	 *         configured.
	 * @throws GeneralSecurityException if configuration is not available
	 * @see #configure(String, KeyStoreType)
	 * @since 3.0 (renamed, was getKeyStoreConfigurationFromUri)
	 */
	private static KeyStoreType getKeyStoreTypeFromUri(String uri) throws GeneralSecurityException {
		String ending = null;
		KeyStoreType type = null;
		if (!uri.equals(DEFAULT_ENDING)) {
			int lastPartIndex = uri.lastIndexOf('/');
			int endingIndex = uri.lastIndexOf('.');
			if (lastPartIndex < endingIndex) {
				ending = uri.substring(endingIndex).toLowerCase();
				type = KEY_STORE_TYPES.get(ending);
			}
		}
		if (type == null) {
			type = KEY_STORE_TYPES.get(DEFAULT_ENDING);
		}
		if (type == null) {
			throw new GeneralSecurityException("no key store type for " + uri);
		}
		return type;
	}

	/**
	 * Get scheme from URI.
	 * 
	 * Use {@link #SCHEME_DELIMITER} to split scheme from URI.
	 * 
	 * @param uri URI starting with scheme.
	 * @return scheme, or {@code null}, if no scheme is provided.
	 */
	private static String getSchemeFromUri(String uri) {
		int schemeIndex = uri.indexOf(SCHEME_DELIMITER);
		if (0 < schemeIndex) {
			return uri.substring(0, schemeIndex + SCHEME_DELIMITER.length()).toLowerCase();
		}
		return null;
	}

	/**
	 * Get input stream from URI.
	 * 
	 * Create input stream from URI. If no scheme is provided
	 * ({@link #SCHEME_DELIMITER} not found), open a file using the URI.
	 * Otherwise, if a scheme is provided, use that scheme to lookup a
	 * configured {@link InputStreamFactory}. If no factory for that scheme was
	 * configured with {@link #configure(String, InputStreamFactory)}, then use
	 * {@link URL}.
	 * 
	 * @param keyStoreUri URI of input stream
	 * @return input stream
	 * @throws IOException if input stream is not available
	 * @throws NullPointerException if the keyStoreUri is {@code null}
	 */
	private static InputStream getInputStreamFromUri(String keyStoreUri) throws IOException {
		if (null == keyStoreUri) {
			throw new NullPointerException("keyStoreUri must be provided!");
		}
		InputStream inStream = null;
		String scheme = getSchemeFromUri(keyStoreUri);
		if (scheme == null) {
			// no scheme, fall-back to local file
			String errorMessage = null;
			File file = new File(keyStoreUri);
			if (!file.exists()) {
				errorMessage = " doesn't exists!";
			} else if (!file.isFile()) {
				errorMessage = " is not a file!";
			} else if (!file.canRead()) {
				errorMessage = " could not be read!";
			}
			if (errorMessage == null) {
				inStream = new FileInputStream(file);
			} else {
				throw new IOException("URI: " + keyStoreUri + ", file: " + file.getAbsolutePath() + errorMessage);
			}
		} else {
			InputStreamFactory streamFactory = INPUT_STREAM_FACTORIES.get(scheme);
			if (streamFactory != null) {
				inStream = streamFactory.create(keyStoreUri);
			}
		}
		if (inStream == null) {
			URL url = new URL(keyStoreUri);
			inStream = url.openStream();
		}
		return inStream;
	}

	/**
	 * Load key store.
	 * 
	 * @param keyStoreUri key store URI. Use
	 *            {@link #getInputStreamFromUri(String)} to read the key store,
	 *            and {@link #getKeyStoreTypeFromUri(String)} to determine the
	 *            type of the key store.
	 * @param storePassword password for key store.
	 * @param configuration password for key store.
	 * @return key store
	 * @throws IOException if key store could not be loaded.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws NullPointerException if keyStoreUri or storePassword is null.
	 * @since 3.0 (changed parameter type to KeyStoreType)
	 */
	private static KeyStore loadKeyStore(String keyStoreUri, char[] storePassword, KeyStoreType configuration)
			throws GeneralSecurityException, IOException {
		if (null == storePassword) {
			throw new NullPointerException("storePassword must be provided!");
		}
		InputStream inStream = getInputStreamFromUri(keyStoreUri);
		KeyStore keyStore = KeyStore.getInstance(configuration.type);
		try {
			keyStore.load(inStream, storePassword);
			return keyStore;
		} catch (IOException ex) {
			throw new IOException(ex + ", URI: " + keyStoreUri + ", type: " + configuration.type + ", "
					+ keyStore.getProvider().getName());
		} finally {
			inStream.close();
		}
	}

	/**
	 * Load simple key store
	 * 
	 * @param keyStoreUri key store URI. Use
	 *            {@link #getInputStreamFromUri(String)} to read the simple key
	 *            store
	 * @param configuration the key store configuration to read the simnple key
	 *            store
	 * @return credentials
	 * @throws GeneralSecurityException if credentials could not be read
	 * @throws IOException if key store could not be read
	 * @since 3.0 (changed parameter type to KeyStoreType)
	 */
	private static Credentials loadSimpleKeyStore(String keyStoreUri, KeyStoreType configuration)
			throws GeneralSecurityException, IOException {
		InputStream inputStream = getInputStreamFromUri(keyStoreUri);
		try {
			return configuration.simpleStore.load(inputStream);
		} finally {
			inputStream.close();
		}
	}

	/**
	 * Load credentials in PEM format
	 * 
	 * @param inputStream input stream
	 * @return credentials
	 * @throws GeneralSecurityException if credentials could not be read
	 * @throws IOException if key store could not be read
	 * @since 3.0 (changed scope to public)
	 */
	public static Credentials loadPemCredentials(InputStream inputStream) throws GeneralSecurityException, IOException {
		PemReader reader = new PemReader(inputStream);
		try {
			String tag;
			Asn1DerDecoder.Keys keys = new Asn1DerDecoder.Keys();
			List<Certificate> certificatesList = new ArrayList<>();
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			while ((tag = reader.readNextBegin()) != null) {
				byte[] decode = reader.readToEnd();
				if (decode != null) {
					if (tag.contains("CERTIFICATE")) {
						certificatesList.add(factory.generateCertificate(new ByteArrayInputStream(decode)));
					} else if (tag.contains("PRIVATE KEY")) {
						Asn1DerDecoder.Keys read = Asn1DerDecoder.readPrivateKey(decode);
						if (read == null) {
							throw new GeneralSecurityException("private key type not supported!");
						}
						keys.add(read);
					} else if (tag.contains("PUBLIC KEY")) {
						PublicKey read = Asn1DerDecoder.readSubjectPublicKey(decode);
						if (read == null) {
							throw new GeneralSecurityException("public key type not supported!");
						}
						keys.setPublicKey(read);
					} else {
						LOGGER.warn("{} not supported!", tag);
					}
				}
			}
			if (keys.getPrivateKey() == null && keys.getPublicKey() == null) {
				if (!certificatesList.isEmpty()) {
					List<Certificate> unique = new ArrayList<>();
					for (Certificate certificate : certificatesList) {
						if (!unique.contains(certificate)) {
							unique.add(certificate);
						}
					}
					if (unique.size() == certificatesList.size()) {
						// try, if certificates form a chain
						try {
							CertPath certPath = factory.generateCertPath(certificatesList);
							List<? extends Certificate> path = certPath.getCertificates();
							X509Certificate[] x509Certificates = path.toArray(new X509Certificate[path.size()]);
							// OK, return certificate chain
							return new Credentials(null, null, x509Certificates);
						} catch (GeneralSecurityException ex) {
						}
					}
					Certificate[] certificates = unique.toArray(new Certificate[unique.size()]);
					return new Credentials(certificates);
				} else {
					// no certificates
					return new Credentials(null);
				}
			} else {
				CertPath certPath = factory.generateCertPath(certificatesList);
				List<? extends Certificate> path = certPath.getCertificates();
				X509Certificate[] x509Certificates = path.toArray(new X509Certificate[path.size()]);
				return new Credentials(keys.getPrivateKey(), keys.getPublicKey(), x509Certificates);
			}
		} finally {
			reader.close();
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
	public static X509Certificate[] asX509Certificates(Certificate[] certificates) {
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
	 * Gets first x509 key manager.
	 * 
	 * @param keyManagers key managers
	 * @return x509 key manager
	 * @throws NullPointerException if key managers is {@code null}
	 * @throws IllegalArgumentException if key managers are empty, or no x509
	 *             key manager is available
	 * @since 3.0
	 */
	public static X509KeyManager getX509KeyManager(KeyManager[] keyManagers) {
		if (keyManagers == null) {
			throw new NullPointerException("Key managers must not be null!");
		}
		if (keyManagers.length == 0) {
			throw new IllegalArgumentException("Key managers must not be empty!");
		}
		for (KeyManager manager : keyManagers) {
			if (manager instanceof X509KeyManager) {
				return (X509KeyManager) manager;
			}
		}
		throw new IllegalArgumentException("Missing a X509KeyManager in key managers!");
	}

	/**
	 * Ensure, that all certificates are unique.
	 * 
	 * @param certificates array of certificates.
	 * @throws IllegalArgumentException if certificates contains duplicates
	 * @since 2.5
	 */
	public static void ensureUniqueCertificates(X509Certificate[] certificates) {

		// Search for duplicates
		Set<X509Certificate> set = new HashSet<>();
		for (X509Certificate certificate : certificates) {
			if (!set.add(certificate)) {
				throw new IllegalArgumentException("Truststore contains certificates duplicates with subject: "
						+ certificate.getSubjectX500Principal());
			}
		}
	}

	/**
	 * Create SSLContext with provided credentials and trusts.
	 * 
	 * Uses {@link #DEFAULT_SSL_PROTOCOL}.
	 * 
	 * @param alias alias to be used in KeyManager. Used for identification
	 *            according the X509ExtendedKeyManager API to select the
	 *            credentials matching the provided key. Though the create
	 *            KeyManager currently only supports on set of credentials, the
	 *            alias is only used to select that. If {@code null}, it's
	 *            replaced by a default "californium".
	 * @param privateKey private key
	 * @param chain certificate trust chain related to private key.
	 * @param trusts trusted certificates.
	 * @return created SSLContext.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws NullPointerException if private key, or the chain, or the trusts
	 *             is {@code null}.
	 * @throws IllegalArgumentException if the chain or trusts is empty.
	 */
	public static SSLContext createSSLContext(String alias, PrivateKey privateKey, X509Certificate[] chain,
			Certificate[] trusts) throws GeneralSecurityException {
		return createSSLContext(alias, privateKey, chain, trusts, DEFAULT_SSL_PROTOCOL);
	}

	/**
	 * Create SSLContext with provided credentials and trusts.
	 * 
	 * @param alias alias to be used in KeyManager. Used for identification
	 *            according the X509ExtendedKeyManager API to select the
	 *            credentials matching the provided key. Though the create
	 *            KeyManager currently only supports on set of credentials, the
	 *            alias is only used to select that. If {@code null}, it's
	 *            replaced by a default "californium".
	 * @param privateKey private key
	 * @param chain certificate trust chain related to private key.
	 * @param trusts trusted certificates.
	 * @param protocol specific protocol for SSLContext. See
	 *            {@link SSLContext#getInstance(String)}.
	 * @return created SSLContext.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws NullPointerException if private key, or the chain, or the trusts
	 *             is {@code null}.
	 * @throws IllegalArgumentException if the chain or trusts is empty.
	 */
	public static SSLContext createSSLContext(String alias, PrivateKey privateKey, X509Certificate[] chain,
			Certificate[] trusts, String protocol) throws GeneralSecurityException {
		if (null == alias) {
			alias = DEFAULT_ALIAS;
		}
		KeyManager[] keyManager = createKeyManager(alias, privateKey, chain);
		TrustManager[] trustManager = createTrustManager(alias, trusts);
		SSLContext sslContext = SSLContext.getInstance(protocol);
		sslContext.init(keyManager, trustManager, null);
		return sslContext;
	}

	/**
	 * Get weak cipher suites for provided {@link SSLContext}.
	 * 
	 * Intended to be used, if {@link JceProviderUtil#hasStrongEncryption()}
	 * returns {@code false}. Selects the "AES_128" cipher suites only.
	 * 
	 * @param sslContext context to get list of weak cipher suites.
	 * @return array with weak cipher suites, or {@code  null}, if all cipher
	 *         suites of the context are already weak or no weak one is
	 *         available in the context at all.
	 * @since 3.0
	 */
	public static String[] getWeakCipherSuites(SSLContext sslContext) {
		SSLParameters sslParameters = sslContext.getDefaultSSLParameters();
		List<String> weakCipherSuites = new ArrayList<>();
		String[] enabledCipherSuites = sslParameters.getCipherSuites();
		for (String suite : enabledCipherSuites) {
			if (suite.contains("AES_128")) {
				weakCipherSuites.add(suite);
			}
		}
		if (!weakCipherSuites.isEmpty() && weakCipherSuites.size() < enabledCipherSuites.length) {
			return weakCipherSuites.toArray(new String[weakCipherSuites.size()]);
		}
		return null;
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
	 * @throws NullPointerException if private key or the chain is {@code null}.
	 * @throws IllegalArgumentException if the chain is empty.
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
			alias = DEFAULT_ALIAS;
		}
		try {
			/* key used for creating a non-persistent KeyStore */
			char[] key = "intern".toCharArray();
			KeyStoreType configuration = getKeyStoreTypeFromUri(DEFAULT_ENDING);
			KeyStore ks = KeyStore.getInstance(configuration.type);
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
	 * @throws NullPointerException if trusted certificates is {@code null}.
	 * @throws IllegalArgumentException if trusted certificates is empty.
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
			alias = DEFAULT_ALIAS;
		}
		try {
			int index = 1;
			KeyStoreType configuration = getKeyStoreTypeFromUri(DEFAULT_ENDING);
			KeyStore ks = KeyStore.getInstance(configuration.type);
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
	 * Create anonymous key manager.
	 * 
	 * @return anonymous key manager
	 * @since 2.4
	 */
	public static KeyManager[] createAnonymousKeyManager() {
		return new KeyManager[] { ANONYMOUS };
	}

	/**
	 * Create trust manager trusting all.
	 * 
	 * @return trust manager trusting all
	 * @since 2.4
	 */
	@NotForAndroid
	public static TrustManager[] createTrustAllManager() {
		return new TrustManager[] { TRUST_ALL };
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
	 * Scheme specific input stream factory.
	 * 
	 * @see SslContextUtil#configure(String, InputStreamFactory)
	 */
	public static interface InputStreamFactory {

		/**
		 * Create input stream of the provided URI.
		 * 
		 * @param uri URI to read
		 * @return input stream
		 * @throws IOException if creating the input stream fails
		 */
		InputStream create(String uri) throws IOException;
	}

	/**
	 * Input stream factory for classpath resources.
	 */
	private static class ClassLoaderInputStreamFactory implements InputStreamFactory {

		@Override
		public InputStream create(String uri) throws IOException {
			String resource = uri.substring(CLASSPATH_SCHEME.length());
			InputStream inStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(resource);
			if (null == inStream) {
				throw new IOException("'" + uri + "' not found!");
			}
			return inStream;
		}

	}

	/**
	 * Credentials.
	 * 
	 * Pair of private key and public key or certificate chain. Or set of trusted
	 * certificates.
	 */
	public static class Credentials {

		/**
		 * Private key.
		 */
		private final PrivateKey privateKey;
		/**
		 * Public key.
		 */
		private final PublicKey publicKey;
		/**
		 * Certificate trust chain.
		 */
		private final X509Certificate[] chain;
		/**
		 * Certificate trusts.
		 */
		private final Certificate[] trusts;

		/**
		 * Create credentials.
		 * 
		 * @param privateKey private key
		 * @param publicKey public key
		 * @param chain certificate chain
		 * @throws IllegalArgumentException if public key and chain is provided,
		 *             but the public key doesn't match the one of the
		 *             certificates head
		 */
		public Credentials(PrivateKey privateKey, PublicKey publicKey, X509Certificate[] chain) {
			if (chain != null) {
				if (chain.length == 0) {
					chain = null;
				} else if (publicKey != null) {
					if (!publicKey.equals(chain[0].getPublicKey())) {
						throw new IllegalArgumentException("public key doesn't match certificate!");
					}
				} else {
					publicKey = chain[0].getPublicKey();
				}
			}
			this.privateKey = privateKey;
			this.chain = chain;
			this.publicKey = publicKey;
			this.trusts = null;
		}

		/**
		 * Create credentials.
		 * 
		 * @param trusts certificate trusts, {@code null} for no trusted
		 *            certificates.
		 */
		public Credentials(Certificate[] trusts) {
			this.privateKey = null;
			this.publicKey = null;
			this.chain = null;
			this.trusts = trusts;
		}

		/**
		 * Get private key.
		 * 
		 * @return private key. May be {@code null}, if not available.
		 */
		public PrivateKey getPrivateKey() {
			return privateKey;
		}

		/**
		 * Get public key.
		 * 
		 * @return public key. May be {@code null}, if not available.
		 */
		public PublicKey getPublicKey() {
			return publicKey;
		}

		/**
		 * Get certificate trust chain.
		 * 
		 * @return certificate trust chain. May be {@code null}, if not
		 *         available.
		 */
		public X509Certificate[] getCertificateChain() {
			return chain;
		}

		/**
		 * Get certificate trust chain as list.
		 * 
		 * @return certificate trust chain as list. May be {@code null}, if not
		 *         available.
		 * @since 3.0
		 */
		public List<X509Certificate> getCertificateChainAsList() {
			return chain == null ? null : Arrays.asList(chain);
		}

		/**
		 * Get trusted certificates.
		 * 
		 * @return trusted certificates. May be {@code null}, if not available.
		 */
		public Certificate[] getTrustedCertificates() {
			return trusts;
		}

		/**
		 * Checks, if the node certificate is expired.
		 * 
		 * @return {@code true} expired, {@code false} not expired.
		 * @since 3.10
		 */
		public boolean isExpired() {
			if (chain != null && chain.length > 0) {
				try {
					chain[0].checkValidity();
				} catch (CertificateExpiredException ex) {
					LOGGER.debug("{} is expired!", chain[0].getSubjectX500Principal(), ex);
					return true;
				} catch (CertificateNotYetValidException ex) {
					LOGGER.debug("{} is not valid yet!", chain[0].getSubjectX500Principal(), ex);
				}
			}
			return false;
		}
	}

	/**
	 * Report incomplete credentials.
	 * 
	 * Missing private or public key.
	 * 
	 * @since 3.0
	 */
	public static class IncompleteCredentialsException extends IllegalArgumentException {

		private static final long serialVersionUID = -53656L;

		/**
		 * Incomplete credentials.
		 * 
		 * Either private or public key is missing.
		 */
		private final Credentials incompleteCredentials;

		/**
		 * Create incomplete credentials exception.
		 * 
		 * @param incompleteCredentials incomplete credentials
		 */
		public IncompleteCredentialsException(Credentials incompleteCredentials) {
			this.incompleteCredentials = incompleteCredentials;
		}

		/**
		 * Create incomplete credentials exception with message.
		 * 
		 * @param incompleteCredentials incomplete credentials
		 * @param message message
		 */
		public IncompleteCredentialsException(Credentials incompleteCredentials, String message) {
			super(message);
			this.incompleteCredentials = incompleteCredentials;
		}

		/**
		 * Create incomplete credentials exception with message and root cause.
		 * 
		 * @param incompleteCredentials incomplete credentials
		 * @param message message
		 * @param cause root cause
		 */
		public IncompleteCredentialsException(Credentials incompleteCredentials, String message, Throwable cause) {
			super(message, cause);
			this.incompleteCredentials = incompleteCredentials;
		}

		/**
		 * Get incomplete credentials.
		 * 
		 * @return incomplete credentials
		 */
		public Credentials getIncompleteCredentials() {
			return incompleteCredentials;
		}
	}

	public static interface SimpleKeyStore {

		/**
		 * Load credentials from input stream.
		 * 
		 * @param inputStream input stream
		 * @return loaded credentials
		 * @throws IOException if reading the input stream fails
		 * @throws GeneralSecurityException if reading the credentials fails
		 */
		Credentials load(InputStream inputStream) throws GeneralSecurityException, IOException;
	}

	/**
	 * Key store type.
	 * 
	 * Either a type supported by {@link KeyStore#getInstance(String)}, or a
	 * {@link SimpleKeyStore} custom-reader.
	 * 
	 * @since 3.0 (renamed, was KeyStoreConfiguration)
	 */
	public static class KeyStoreType {

		/**
		 * Type supported by {@link KeyStore#getInstance(String)}.
		 */
		public final String type;
		/**
		 * Custom key store reader.
		 */
		public final SimpleKeyStore simpleStore;

		/**
		 * Create type supported by {@link KeyStore#getInstance(String)}.
		 * 
		 * @param type type supported by {@link KeyStore#getInstance(String)}.
		 * @throws NullPointerException if type is {@code null}
		 * @throws IllegalArgumentException if type is empty
		 * @since 3.0
		 */
		public KeyStoreType(String type) {
			if (type == null) {
				throw new NullPointerException("key store type must not be null!");
			}
			if (type.isEmpty()) {
				throw new IllegalArgumentException("key store type must not be empty!");
			}
			this.type = type;
			this.simpleStore = null;
		}

		/**
		 * Create type with custom key store reader.
		 * 
		 * @param simpleStore custom key store reader
		 * @throws NullPointerException if simpleStore is {@code null}
		 * @since 3.0
		 */
		public KeyStoreType(SimpleKeyStore simpleStore) {
			if (simpleStore == null) {
				throw new NullPointerException("simple key store must not be null!");
			}
			this.type = null;
			this.simpleStore = simpleStore;
		}
	}

	/**
	 * Anonymous key manager.
	 * 
	 * Never returns aliases nor credentials.
	 * 
	 * @since 2.4
	 */
	private static class AnonymousX509ExtendedKeyManager extends X509ExtendedKeyManager {

		@Override
		public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
			return null;
		}

		@Override
		public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
			return null;
		}

		@Override
		public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
			return null;
		}

		@Override
		public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
			return null;
		}

		@Override
		public X509Certificate[] getCertificateChain(String alias) {
			return null;
		}

		@Override
		public String[] getClientAliases(String keyType, Principal[] issuers) {
			return null;
		}

		@Override
		public PrivateKey getPrivateKey(String alias) {
			return null;
		}

		@Override
		public String[] getServerAliases(String keyType, Principal[] issuers) {
			return null;
		}
	}

	/**
	 * Trust all manager.
	 * 
	 * Validate certificate chains, but does not use a trust-anchors. Use with
	 * care! This is usually only used for test scenarios!
	 * 
	 * @since 3.0
	 */
	private static class X509TrustAllManager implements X509TrustManager {

		private static final X509Certificate[] EMPTY = new X509Certificate[0];

		/**
		 * Create trust all manager.
		 */
		private X509TrustAllManager() {
		}

		/**
		 * Validate certificate chain trusting any trust-anchors.
		 * 
		 * @param chain chain to be validate
		 * @param client {@code true} for client's chain, {@code false}, for
		 *            server's chain.
		 * @throws CertificateException if the validation fails.
		 */
		private static void validateChain(X509Certificate[] chain, boolean client) throws CertificateException {
			if (chain != null && chain.length > 0) {
				LOGGER.debug("check certificate {} for {}", chain[0].getSubjectX500Principal(),
						client ? "client" : "server");
				if (!CertPathUtil.canBeUsedForAuthentication(chain[0], client)) {
					LOGGER.debug("check certificate {} for {} failed on key-usage!", chain[0].getSubjectX500Principal(),
							client ? "client" : "server");
					throw new CertificateException("Key usage not proper for " + (client ? "client" : "server"));
				} else {
					LOGGER.trace("check certificate {} for {} succeeded on key-usage!",
							chain[0].getSubjectX500Principal(), client ? "client" : "server");
				}
				CertPath path = CertPathUtil.generateValidatableCertPath(Arrays.asList(chain), null);
				try {
					CertPathUtil.validateCertificatePathWithIssuer(true, path, EMPTY);
					LOGGER.trace("check certificate {} [chain.length={}] for {} validated!",
							chain[0].getSubjectX500Principal(), chain.length, client ? "client" : "server");
				} catch (GeneralSecurityException e) {
					LOGGER.debug("check certificate {} for {} failed on {}!", chain[0].getSubjectX500Principal(),
							client ? "client" : "server", e.getMessage());
					if (e instanceof CertificateException) {
						throw (CertificateException) e;
					} else {
						throw new CertificateException(e);
					}
				}
			}
		}

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			validateChain(chain, true);
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			validateChain(chain, false);
		}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return EMPTY;
		}

	}

	/**
	 * Extended trust all manager.
	 * 
	 * Validate certificate chains, but does not use a trust-anchors. Use with
	 * care! This is usually only used for test scenarios!
	 */
	@NotForAndroid
	private static class X509ExtendedTrustAllManager extends X509ExtendedTrustManager {

		/**
		 * Create extended trust all manager.
		 */
		private X509ExtendedTrustAllManager() {
		}

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			X509TrustAllManager.validateChain(chain, true);
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			X509TrustAllManager.validateChain(chain, false);
		}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return X509TrustAllManager.EMPTY;
		}

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
				throws CertificateException {
			X509TrustAllManager.validateChain(chain, true);
		}

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
				throws CertificateException {
			X509TrustAllManager.validateChain(chain, true);
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
				throws CertificateException {
			X509TrustAllManager.validateChain(chain, false);
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
				throws CertificateException {
			X509TrustAllManager.validateChain(chain, false);
		}
	}
}
