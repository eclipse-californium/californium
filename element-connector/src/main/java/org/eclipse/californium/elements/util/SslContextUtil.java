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
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce configurable 
 *                                                    key store type and 
 *                                                    InputStreamFactory. 
 *    Achim Kraus (Bosch Software Innovations GmbH) - use file system, if 
 *                                                    no scheme is provided in URI 
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.io.File;
import java.io.FileInputStream;
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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
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
 * "*" to system default
 * </pre>
 * 
 * The utility provides also a configurable input stream factory of URI schemes.
 * Currently only {@link #CLASSPATH_SCHEME} is pre-configured to load key stores
 * from the classpath. If the scheme of the URI has no configured input stream
 * factory, the URI is loaded with {@link URL#URL(String)}.
 * 
 * Note: currently this class provides a class access based API. Depending on
 * the usage, this may change to instance access based API. It is not intended,
 * that the configuration is changed during usage, this may cause race
 * conditions!
 * 
 * @see #configure(String, String)
 * @see #configure(String, InputStreamFactory)
 */
public class SslContextUtil {

	/**
	 * Scheme for key store URI. Used to load the key stores from classpath.
	 */
	public static final String CLASSPATH_SCHEME = "classpath://";
	/**
	 * @deprecated use CLASSPATH_SCHEME instead!
	 */
	public static final String CLASSPATH_PROTOCOL = CLASSPATH_SCHEME;
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
	 * Schema delimiter.
	 */
	private static final String SCHEME_DELIMITER = "://";
	/**
	 * Map URI endings to key store types.
	 * 
	 * @see #configure(String, String)
	 * @see #getKeyStoreTypeFromUri(String)
	 */
	private static final Map<String, String> KEY_STORE_TYPES = new ConcurrentHashMap<>();
	/**
	 * Map URI scheme to input stream factories.
	 * 
	 * @see #configure(String, InputStreamFactory)
	 * @see #getInputStreamFactoryFromUri(String)
	 */
	private static final Map<String, InputStreamFactory> INPUT_STREAM_FACTORIES = new ConcurrentHashMap<>();

	static {
		configureDefaults();
	}

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
	 * @throws NullPointerException if credentials is null.
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
	 * @param keyStoreUri key store URI. Supports configurable URI scheme based
	 *            input streams and URI ending based key store type.
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
	 * Configure defaults.
	 * 
	 * Key store type:
	 * 
	 * <pre>
	 * ".jks" to "JKS"
	 * ".bks" to "BKS"
	 * ".p12" to "PKCS12"
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
		KEY_STORE_TYPES.put(DEFAULT_ENDING, KeyStore.getDefaultType());
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
	 * @see #configure(String, String)
	 */
	private static String getKeyStoreTypeFromUri(String uri) {
		String type = null;
		if (!uri.equals(DEFAULT_ENDING)) {
			int lastPartIndex = uri.lastIndexOf('/');
			int endingIndex = uri.lastIndexOf('.');
			if (lastPartIndex < endingIndex) {
				String ending = uri.substring(endingIndex).toLowerCase();
				type = KEY_STORE_TYPES.get(ending);
			}
		}
		if (type == null) {
			type = KEY_STORE_TYPES.get(DEFAULT_ENDING);
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
	 * Load key store.
	 * 
	 * @param keyStoreUri key store URI. Supports configurable URI scheme based
	 *            input streams and URI ending based key store type.
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
				KeyStore ksAlias = KeyStore.getInstance(ks.getType());
				ksAlias.load(null);
				ksAlias.setCertificateEntry(alias, certificate);
				return ksAlias;
			}
			throw new GeneralSecurityException(
					"key stores '" + keyStoreUri + "' doesn't contain certificates for '" + alias + "'");
		} else {
			Entry entry = ks.getEntry(alias, new KeyStore.PasswordProtection(keyPassword));
			if (null != entry) {
				KeyStore ksAlias = KeyStore.getInstance(ks.getType());
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
	 * @param keyStoreUri key store URI. Use
	 *            {@link #getInputStreamFactoryFromUri(String)} configured by
	 *            {@link #configure(String, InputStreamFactory)} to read the key
	 *            store according the specified scheme. e.g. if
	 *            {@link #CLASSPATH_SCHEME} is used, loaded from classpath. Use
	 *            {@link #getKeyStoreTypeFromUri(String)} to determine the type
	 *            of the key store.
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
		}
		if (scheme != null) {
			InputStreamFactory streamFactory = INPUT_STREAM_FACTORIES.get(scheme);
			if (streamFactory != null) {
				inStream = streamFactory.create(keyStoreUri);
			}
		}
		if (inStream == null) {
			URL url = new URL(keyStoreUri);
			inStream = url.openStream();
		}
		String keyStoreType = getKeyStoreTypeFromUri(keyStoreUri);
		try {
			KeyStore keyStore = KeyStore.getInstance(keyStoreType);
			keyStore.load(inStream, storePassword);
			return keyStore;
		} catch (IOException ex) {
			throw new IOException(ex + ", URI: " + keyStoreUri + ", type: " + keyStoreType);
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
			String keyStoreType = getKeyStoreTypeFromUri(DEFAULT_ENDING);
			KeyStore ks = KeyStore.getInstance(keyStoreType);
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
			String keyStoreType = getKeyStoreTypeFromUri(DEFAULT_ENDING);
			KeyStore ks = KeyStore.getInstance(keyStoreType);
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
			InputStream inStream = SslContextUtil.class.getClassLoader().getResourceAsStream(resource);
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
