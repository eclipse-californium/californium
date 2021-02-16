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
import java.security.cert.CertificateFactory;
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
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;

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
 * ".pem" to "PEM" (simple key store, experimental!)
 * "*" to system default
 * </pre>
 * 
 * PEM: Read private keys (PKCS8 and PKCS12 (EC only)), public key (x509), and
 * certificates (x509).
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
 * @see #configure(String, String)
 * @see #configure(String, KeyStoreConfiguration)
 * @see #configure(String, InputStreamFactory)
 */
public class SslContextUtil {

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
	 * Ending for key stores with pseudo type {@link #PEM_TYPE}.
	 * 
	 * @see #KEY_STORE_TYPES
	 */
	public static final String PEM_ENDING = ".pem";
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
	 * Pseudo key store type PEM.
	 * 
	 * @see #KEY_STORE_TYPES
	 */
	public static final String PEM_TYPE = "PEM";
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
	 * @see #configure(String, String)
	 * @see #getKeyStoreTypeFromUri(String)
	 */
	private static final Map<String, String> KEY_STORE_TYPES = new ConcurrentHashMap<>();
	private static final Map<String, KeyStoreConfiguration> KEY_STORE_CONFIGS = new ConcurrentHashMap<>();
	/**
	 * Map URI scheme to input stream factories.
	 * 
	 * @see #configure(String, InputStreamFactory)
	 * @see #getInputStreamFactoryFromUri(String)
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
	@NotForAndroid
	private static final TrustManager TRUST_ALL = new SimpleX509ExtendedTrustManager(new X509Certificate[0]);

	static {
		Asn1DerDecoder.getEdDsaProvider();
		configureDefaults();
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
			KeyStoreConfiguration configuration = getKeyStoreConfigurationFromUri(parameters[0]);
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
	 * @throws NullPointerException if credentials is {@code null}.
	 * @see #PARAMETER_SEPARATOR
	 */
	public static Credentials loadCredentials(String credentials) throws IOException, GeneralSecurityException {
		if (null == credentials) {
			throw new NullPointerException("credentials must be provided!");
		}
		String[] parameters = credentials.split(PARAMETER_SEPARATOR, 4);
		if (1 == parameters.length) {
			KeyStoreConfiguration configuration = getKeyStoreConfigurationFromUri(parameters[0]);
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
	 * @param alias alias to load only specific credentials into the KeyManager.
	 *            null to load all credentials into the KeyManager.
	 * @param storePassword password for key store.
	 * @param keyPassword password for private key.
	 * @return array with KeyManager
	 * @throws IOException if key store could not be loaded.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws IllegalArgumentException if no matching credentials are found
	 * @throws NullPointerException if keyStoreUri, storePassword, or
	 *             keyPassword is {@code null}.
	 */
	public static KeyManager[] loadKeyManager(String keyStoreUri, String alias, char[] storePassword,
			char[] keyPassword) throws IOException, GeneralSecurityException {
		KeyStoreConfiguration configuration = getKeyStoreConfigurationFromUri(keyStoreUri);
		KeyStore ks;
		if (configuration.simpleStore != null) {
			Credentials credentials = loadSimpleKeyStore(keyStoreUri, configuration);
			if (credentials.privateKey == null) {
				throw new IllegalArgumentException("credentials missing! No private key found!");
			}
			if (credentials.chain == null) {
				throw new IllegalArgumentException("credentials missing! No certificate chain found!");
			}
			return createKeyManager(alias, credentials.privateKey, credentials.chain);
		} else {
			if (null == keyPassword) {
				throw new NullPointerException("keyPassword must be provided!");
			}
			ks = loadKeyStore(keyStoreUri, storePassword, configuration);
			if (alias != null && !alias.isEmpty()) {
				KeyStore ksAlias = KeyStore.getInstance(ks.getType());
				ksAlias.load(null);
				Entry entry = ks.getEntry(alias, new KeyStore.PasswordProtection(keyPassword));
				if (null != entry) {
					ksAlias.setEntry(alias, entry, new KeyStore.PasswordProtection(keyPassword));
				} else {
					throw new GeneralSecurityException(
							"key stores '" + keyStoreUri + "' doesn't contain credentials for '" + alias + "'");
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
		KeyStoreConfiguration configuration = getKeyStoreConfigurationFromUri(keyStoreUri);
		if (configuration.simpleStore != null) {
			Credentials credentials = loadSimpleKeyStore(keyStoreUri, configuration);
			if (credentials.trusts == null) {
				throw new IllegalArgumentException("no trusted x509 certificates found in '" + keyStoreUri + "'!");
			}
			return credentials.trusts;
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
	 * @throws NullPointerException if keyStoreUri, storePassword, keyPassword,
	 *             or alias is {@code null}.
	 */
	public static Credentials loadCredentials(String keyStoreUri, String alias, char[] storePassword,
			char[] keyPassword) throws IOException, GeneralSecurityException {
		KeyStoreConfiguration configuration = getKeyStoreConfigurationFromUri(keyStoreUri);
		if (configuration.simpleStore != null) {
			Credentials credentials = loadSimpleKeyStore(keyStoreUri, configuration);
			if (credentials.privateKey == null) {
				throw new IllegalArgumentException("credentials missing! No private key found!");
			}
			if (credentials.chain == null && credentials.publicKey == null) {
				throw new IllegalArgumentException(
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
		KeyStoreConfiguration configuration = getKeyStoreConfigurationFromUri(keyStoreUri);
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
		KeyStoreConfiguration configuration = getKeyStoreConfigurationFromUri(keyStoreUri);
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
		KeyStoreConfiguration configuration = getKeyStoreConfigurationFromUri(keyStoreUri);
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
	 * ".pem" to "PEM"
	 * "*" to system default
	 * </pre>
	 * 
	 * Input stream factory: {@link #CLASSPATH_SCHEME} to classpath loader.
	 */
	public static void configureDefaults() {
		KEY_STORE_TYPES.clear();
		KEY_STORE_TYPES.put(JKS_ENDING, JKS_TYPE);
		KEY_STORE_TYPES.put(BKS_ENDING, BKS_TYPE);
		KEY_STORE_TYPES.put(PKCS12_ENDING, PKCS12_TYPE);
		KEY_STORE_TYPES.put(PEM_ENDING, PEM_TYPE);
		KEY_STORE_TYPES.put(DEFAULT_ENDING, KeyStore.getDefaultType());

		KEY_STORE_CONFIGS.put(JKS_TYPE, new KeyStoreConfiguration(JKS_TYPE, null));
		KEY_STORE_CONFIGS.put(BKS_TYPE, new KeyStoreConfiguration(BKS_TYPE, null));
		KEY_STORE_CONFIGS.put(PKCS12_TYPE, new KeyStoreConfiguration(PKCS12_TYPE, null));
		KEY_STORE_CONFIGS.put(PEM_TYPE, new KeyStoreConfiguration(PEM_TYPE, new SimpleKeyStore() {

			@Override
			public Credentials load(InputStream inputStream) throws GeneralSecurityException, IOException {
				return loadPemCredentials(inputStream);
			}
		}));

		INPUT_STREAM_FACTORIES.clear();
		INPUT_STREAM_FACTORIES.put(CLASSPATH_SCHEME, new ClassLoaderInputStreamFactory());
	}

	/**
	 * Configure key store types for URI endings.
	 * 
	 * @param ending URI ending. If {@link #DEFAULT_ENDING} is used, the key
	 *            store default type is configured. Ending is converted to lower
	 *            case before added to the {@link #KEY_STORE_TYPES}.
	 * @param keyStoreType key store type.
	 * @return old key store type for ending, or {@code null}, if no key store
	 *         type was configured before
	 * @throws NullPointerException if ending or key store type is {@code null}.
	 * @throws IllegalArgumentException if ending doesn't start with "." and
	 *             isn't {@link #DEFAULT_ENDING}, or key store type is empty.
	 */
	public static String configure(String ending, String keyStoreType) {
		if (ending == null) {
			throw new NullPointerException("ending must not be null!");
		}
		if (!ending.equals(DEFAULT_ENDING) && !ending.startsWith(".")) {
			throw new IllegalArgumentException("ending must start with \".\"!");
		}
		if (keyStoreType == null) {
			throw new NullPointerException("key store type must not be null!");
		}
		if (keyStoreType.isEmpty()) {
			throw new IllegalArgumentException("key store type must not be empty!");
		}
		return KEY_STORE_TYPES.put(ending.toLowerCase(), keyStoreType);
	}

	/**
	 * Configure a {@link KeyStoreConfiguration} for a key store type.
	 * 
	 * @param keyStoreType the key store type
	 * @param config the key store configuration
	 * @return previous key store configuration, or {@code null}, if no key
	 *         store configuration was configured before
	 */
	public static KeyStoreConfiguration configure(String keyStoreType, KeyStoreConfiguration config) {
		if (keyStoreType == null) {
			throw new NullPointerException("key store type must not be null!");
		}
		if (keyStoreType.isEmpty()) {
			throw new IllegalArgumentException("key store type must not be empty!");
		}
		if (config == null) {
			throw new NullPointerException("key store configuration must not be null!");
		}
		return KEY_STORE_CONFIGS.put(keyStoreType, config);
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
	 * @see #configure(String, String)
	 */
	private static KeyStoreConfiguration getKeyStoreConfigurationFromUri(String uri) throws GeneralSecurityException {
		String ending = null;
		String type = null;
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
		KeyStoreConfiguration configuration = KEY_STORE_CONFIGS.get(type.toUpperCase());
		if (configuration == null) {
			throw new GeneralSecurityException("no key store configuration for " + type);
		}
		return configuration;
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
	 * configured {@link #InputStreamFactory}. If no factory for that scheme was
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
	 *            and {@link #getKeyStoreConfigurationFromUri(String)} to
	 *            determine the type of the key store.
	 * @param storePassword password for key store.
	 * @return key store
	 * @throws IOException if key store could not be loaded.
	 * @throws GeneralSecurityException if security setup failed.
	 * @throws NullPointerException if keyStoreUri or storePassword is null.
	 */
	private static KeyStore loadKeyStore(String keyStoreUri, char[] storePassword, KeyStoreConfiguration configuration)
			throws GeneralSecurityException, IOException {
		if (null == storePassword) {
			throw new NullPointerException("storePassword must be provided!");
		}
		InputStream inStream = getInputStreamFromUri(keyStoreUri);
		try {
			KeyStore keyStore = KeyStore.getInstance(configuration.type);
			keyStore.load(inStream, storePassword);
			return keyStore;
		} catch (IOException ex) {
			throw new IOException(ex + ", URI: " + keyStoreUri + ", type: " + configuration.type);
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
	 */
	private static Credentials loadSimpleKeyStore(String keyStoreUri, KeyStoreConfiguration configuration)
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
	 */
	private static Credentials loadPemCredentials(InputStream inputStream)
			throws GeneralSecurityException, IOException {
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
				List<Certificate> unique = new ArrayList<>();
				for (Certificate certificate : certificatesList) {
					if (!unique.contains(certificate)) {
						unique.add(certificate);
					}
				}
				Certificate[] certificates = unique.toArray(new Certificate[unique.size()]);
				return new Credentials(certificates);
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
	 * Ensure, that all certificates are unique.
	 * 
	 * @param certificates array of certificates.
	 * @throws IllegalArgumentException if certificates contains duplicates
	 * @since 2.5
	 */
	public static void ensureUniqueCertificates(X509Certificate[] certificates) {

		// Search for duplicates
		Set<X509Certificate> set = new HashSet<>();
		for (X509Certificate certificate: certificates) {
			if (!set.add(certificate)) {
				throw new IllegalArgumentException("Truststore contains certificates duplicates with subject: " + certificate.getSubjectX500Principal());
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
			KeyStoreConfiguration configuration = getKeyStoreConfigurationFromUri(DEFAULT_ENDING);
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
			KeyStoreConfiguration configuration = getKeyStoreConfigurationFromUri(DEFAULT_ENDING);
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
	 * @see #createSimpleTrustManager(Certificate[])
	 * @since 2.4
	 */
	@NotForAndroid
	public static TrustManager[] createTrustAllManager() {
		return new TrustManager[] { TRUST_ALL };
	}

	/**
	 * Create simple trust manager from trusted certificates.
	 * 
	 * Validate certificate chains, but does not validate the destination using
	 * the subject. Use with care! This usually requires, that no public trust
	 * root is used!
	 * 
	 * @param trusts trusted certificates. If an empty array is provided, the
	 *            trust anchor is not checked.
	 * @return trust manager
	 * @throws NullPointerException if trusted certificates is {@code null}.
	 * @see #createTrustAllManager()
	 * @since 3.0
	 */
	@NotForAndroid
	public static TrustManager[] createSimpleTrustManager(Certificate[] trusts) throws GeneralSecurityException {
		if (null == trusts) {
			throw new NullPointerException("trusted certificates must be provided!");
		}
		X509Certificate[] x509trusts = asX509Certificates(trusts);
		return new TrustManager[] { new SimpleX509ExtendedTrustManager(x509trusts) };
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
	 * Credentials. Pair of private key and certificate trustedChain.
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
		 * Certificate trustedChain.
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
		 * @param trusts certificate trusts
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
		 * @return private key
		 */
		public PrivateKey getPrivateKey() {
			return privateKey;
		}

		/**
		 * Get public key.
		 * 
		 * @return public key
		 */
		public PublicKey getPubicKey() {
			return publicKey;
		}

		/**
		 * Get certificate trustedChain.
		 * 
		 * @return certificate trustedChain
		 */
		public X509Certificate[] getCertificateChain() {
			return chain;
		}

		/**
		 * Get certificate trusts.
		 * 
		 * @return certificate trusts
		 */
		public Certificate[] getTrustedCertificates() {
			return trusts;
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

	public static class KeyStoreConfiguration {

		public final String type;
		public final SimpleKeyStore simpleStore;

		public KeyStoreConfiguration(String type, SimpleKeyStore simpleStore) {
			this.type = type;
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
	 * Simple trust manager.
	 * 
	 * Validate certificate chains, but does not validate the destination by the
	 * subject. Use with care! This usually requires, that no public trust root
	 * is used!
	 * 
	 * @since 3.0 (was X509ExtendedTrustAllManager)
	 */
	@NotForAndroid
	private static class SimpleX509ExtendedTrustManager extends X509ExtendedTrustManager {

		private final X509Certificate[] trusts;

		/**
		 * Create simple trust manager.
		 * 
		 * @param trusts trusted certificates. If an empty array is provided,
		 *            the trust anchor is not checked.
		 * @since 3.0
		 */
		private SimpleX509ExtendedTrustManager(X509Certificate[] trusts) {
			this.trusts = trusts;
		}

		/**
		 * Validate certificate chain trusting all chain roots.
		 * 
		 * @param chain chain to be validate
		 * @param client {@code true} for client's chain, {@code false}, for
		 *            server's chain.
		 * @throws CertificateException if the validation fails.
		 */
		private void validateChain(X509Certificate[] chain, boolean client) throws CertificateException {
			if (chain != null && chain.length > 0) {
				LOGGER.debug("check certificate {} for {}", chain[0].getSubjectDN(), client ? "client" : "server");
				if (!CertPathUtil.canBeUsedForAuthentication(chain[0], client)) {
					LOGGER.debug("check certificate {} for {} failed on key-usage!", chain[0].getSubjectDN(),
							client ? "client" : "server");
					throw new CertificateException("Key usage not proper for " + (client ? "client" : "server"));
				} else {
					LOGGER.trace("check certificate {} for {} succeeded on key-usage!", chain[0].getSubjectDN(),
							client ? "client" : "server");
				}
				CertPath path = CertPathUtil.generateValidatableCertPath(Arrays.asList(chain), null);
				try {
					CertPathUtil.validateCertificatePathWithIssuer(true, path, trusts);
					LOGGER.trace("check certificate {} [chain.length={}] for {} validated!", chain[0].getSubjectDN(),
							chain.length,
							client ? "client" : "server");
				} catch (GeneralSecurityException e) {
					LOGGER.debug("check certificate {} for {} failed on {}!", chain[0].getSubjectDN(),
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
			return trusts;
		}

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
				throws CertificateException {
			validateChain(chain, true);
		}

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
				throws CertificateException {
			validateChain(chain, true);
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
				throws CertificateException {
			validateChain(chain, false);
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
				throws CertificateException {
			validateChain(chain, false);
		}
	}
}
