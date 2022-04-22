/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial implementation
 *                    derived from Asn1DerDecoder
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.Cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JCE provider util.
 * <p>
 * Initialize JCE provider.
 * <p>
 * To support EdDSA, either java 15 (or newer), or java 11 with
 * <a href="https://github.com/str4d/ed25519-java" target=
 * "_blank">ed25519-java</a> is required at runtime. Using java 15 to build
 * Californium, leaves out {@code ed25519-java}, using java 11 for building,
 * includes {@code ed25519-java} by default. If {@code ed25519-java} should
 * <b>NOT</b> be included into the Californium's jars, add
 * {@code -Dno.net.i2p.crypto.eddsa=true} to maven's arguments. In that case,
 * it's still possible to use {@code ed25519-java}, if the <a href=
 * "https://repo1.maven.org/maven2/net/i2p/crypto/eddsa/0.3.0/eddsa-0.3.0.jar"
 * target="_blank">eddsa-0.3.0.jar</a> is provided to the classpath separately.
 * <p>
 * If java 11 is used to run maven, but the build uses the toolchain with java
 * 7, {@code -Dno.net.i2p.crypto.eddsa=true} must be used, because X25519 is not
 * supported with java 7 and causes the build to fail.
 * <p>
 * With Californium version 3.0 an experimental support for using Bouncy Castle,
 * version 1.69, as JCE is available. And with Californium version 3.3 Bouncy
 * Castle version 1.70 is supported. On class startup, the default JCE is
 * checked for providing EdDSA. If that fails, ed25519-java is tested and, on
 * success, added as provider. To use Bouncy Castle, or if the default JCE
 * provider should not be used, the environment variable
 * "CALIFORNIUM_JCE_PROVIDER" is used. Configure that with one of the values
 * "SYSTEM" (keep the providers configured externally), "BC" (load and insert
 * the Bouncy Castle provider), "I2P" (load net.i2p.crypto.eddsa ed25519-java
 * and use that for EdDSA).
 * <p>
 * Though Bouncy Castle uses JUL for logging, jul2slf4j2 is added when using BC.
 * That requires {@code org.slf4j.bridge.SLF4JBridgeHandler} in the classpath.
 * The bridge is only activated, if "CALIFORNIUM_JCE_PROVIDER" is set to "BC"
 * and Bouncy Castle is not already set as security provider.
 * <p>
 * In some cases, Bouncy Castle blocks on startup by missing entropy. That may
 * exceed even 60s. To mitigate that, tools may be available, which provides
 * more entropy, e.g. for linux
 * <a href= "https://github.com/nhorman/rng-tools" target=
 * "_blank">rng-tools</a>. Alternatively, it's possible to use a non-blocking,
 * maybe weaker, random generator to startup Bouncy Castle, use
 * {@code "BC_NON_BLOCKING_RANDOM"}.
 * 
 * @since 3.0
 */
public class JceProviderUtil {

	private static final Logger LOGGER = LoggerFactory.getLogger(JceProviderUtil.class);

	/**
	 * Information about JCE features.
	 * 
	 * @see #setupJce()
	 */
	private static volatile JceProviderUtil features;
	/**
	 * Alias algorithms for Ed25519.
	 * 
	 * @since 3.3
	 */
	private static final String[] ED25519_ALIASES = { JceNames.ED25519, "1.3.101.112", JceNames.OID_ED25519,
			JceNames.EDDSA, JceNames.ED25519v2 };

	/**
	 * Alias algorithms for Ed448.
	 * 
	 * @since 3.3
	 */
	private static final String[] ED448_ALIASES = { JceNames.ED448, "1.3.101.113", JceNames.OID_ED448, JceNames.EDDSA,
			JceNames.ED448v2 };
	/**
	 * Table of algorithm aliases.
	 * 
	 * @since 3.3
	 */
	private static final String[][] ALGORITHM_ALIASES = { { JceNames.DH, "DiffieHellman" },
			{ JceNames.EC, JceNames.ECv2 }, ED25519_ALIASES, ED448_ALIASES,
			{ JceNames.X25519, JceNames.X25519v2, JceNames.OID_X25519 },
			{ JceNames.X448, JceNames.X448v2, JceNames.OID_X448 } };

	/**
	 * Package name for external java 7 EdDSA provider.
	 */
	private static final String NET_I2P_CRYPTO_EDDSA = "net.i2p.crypto.eddsa";
	/**
	 * Name of i2p EdDSA JCE provider.
	 */
	private static final String NET_I2P_CRYPTO_EDDSA_PROVIDER = NET_I2P_CRYPTO_EDDSA + ".EdDSASecurityProvider";
	/**
	 * Name of Bouncy Castle JCE provider.
	 */
	private static final String BOUNCY_CASTLE_JCE_PROVIDER = "org.bouncycastle.jce.provider.BouncyCastleProvider";
	/**
	 * Name of Bouncy Castle JSSE provider.
	 */
	private static final String BOUNCY_CASTLE_JSSE_PROVIDER = "org.bouncycastle.jsse.provider.BouncyCastleJsseProvider";
	/**
	 * Value to use Bouncy Castle as JSSE (TLS only).
	 */
	private static final String JSSE_PROVIDER_BOUNCY_CASTLE = "BCJSSE";

	/**
	 * Cipher name to check for the maximum allowed key length.
	 * 
	 * A key length of 256 bits or larger is considered as strong encryption.
	 */
	private static final String AES = "AES";

	private final boolean useBc;
	private final boolean rsa;
	private final boolean ec;
	private final boolean ed25519;
	private final boolean ed448;
	private final boolean strongEncryption;
	private final boolean ecdsaVulnerable;
	private final String providerVersion;

	static {
		try {
			// prepare for removing AccessController
			Class.forName(AccessController.class.getName());
			doPrivileged();
		} catch (ClassNotFoundException e) {
			try {
				setupJce();
			} catch (Throwable t) {
				LOGGER.error("JCE:", t);
			}
		}
	}

	private static void doPrivileged() {
		AccessController.doPrivileged(new PrivilegedAction<Void>() {

			@Override
			public Void run() {
				try {
					setupJce();
				} catch (Throwable t) {
					LOGGER.error("JCE:", t);
				}
				return null;
			}
		});
	}

	/**
	 * Checks, if provider is Bouncy Castle.
	 * 
	 * @param provider provider to check. May be {@code null}.
	 * @return {@code true}, if provided provider is Bouncy Castle,
	 *         {@code false}, if either no providers is provided or provider is
	 *         not Bouncy Castle.
	 */
	private static boolean isBouncyCastle(Provider provider) {
		return provider != null && provider.getName().equals(JceNames.JCE_PROVIDER_BOUNCY_CASTLE);
	}

	/**
	 * Checks, if provider is i2p EdDSA JCE provider.
	 * 
	 * @param provider provider to check. May be {@code null}.
	 * @return {@code true}, if provided provider is i2p EdDSA JCE provider,
	 *         {@code false}, if either no providers is provided or provider is
	 *         not i2p EdDSA JCE provider.
	 * @since 3.3
	 */
	private static boolean isNetI2PEdDsa(Provider provider) {
		return provider != null && provider.getClass().getName().equals(NET_I2P_CRYPTO_EDDSA_PROVIDER);
	}

	/**
	 * Configure provider.
	 * 
	 * Set value for property, if current
	 * 
	 * @param provider provider to configure
	 * @param key property key
	 * @param value property value
	 */
	private static void configure(Provider provider, String key, String value) {
		String current = provider.getProperty(key);
		if (!value.equals(current)) {
			provider.setProperty(key, value);
		}
	}

	/**
	 * Load provider by class-name.
	 * 
	 * @param clzName class-name
	 * @return loaded provider, or {@code null}, if class could not be loaded or
	 *         instance could not be created.
	 */
	private static Provider loadProvider(String clzName) {
		try {
			Class<?> clz = Class.forName(clzName);
			Provider provider = (Provider) clz.getConstructor().newInstance();
			LOGGER.debug("Loaded {}", clzName);
			return provider;
		} catch (Throwable e) {
			if (LOGGER.isTraceEnabled()) {
				LOGGER.trace("Loading {} failed!", clzName, e);
			} else {
				LOGGER.debug("Loading {} failed!", clzName);
			}
			return null;
		}
	}

	/**
	 * Setup logging bridge for jul to slf4j2. BC is using jul.
	 * 
	 * Requires {@code org.slf4j:jul-to-slf4j} in classpath.
	 * 
	 * @since 3.0
	 */
	private static void setupLoggingBridge() {
		try {
			Class<?> clz = Class.forName("org.slf4j.bridge.SLF4JBridgeHandler");
			Method method = clz.getMethod("removeHandlersForRootLogger");
			method.invoke(null);
			method = clz.getMethod("install");
			method.invoke(null);
		} catch (ClassNotFoundException e) {
			LOGGER.warn("Setup BC logging failed, missing logging bridge 'jul-to-slf4j'!");
		} catch (Throwable e) {
			LOGGER.warn("Setup BC logging failed!", e);
		}
	}

	/**
	 * Setup secure random to non-blocking variant to prevent sporadical delays
	 * during start up.
	 * 
	 * Checks secure property {@code 'securerandom.strongAlgorithms'} for
	 * {@code 'NativePRNGBlocking'} and replace that by
	 * {@code 'NativePRNGNonBlocking'}. If {@code 'NativePRNGBlocking'} is not
	 * found, add the algorithm of a default {@link SecureRandom} at the head,
	 * if not already contained.
	 * 
	 * @return previous strong algorithm, or {@code null}, if not available.
	 * @since 3.3
	 */
	private static String setupNonBlockingSecureRandom() {
		String strongAlgorithms = Security.getProperty("securerandom.strongAlgorithms");
		if (strongAlgorithms != null) {
			if (strongAlgorithms.contains("NativePRNGBlocking")) {
				// use non-blocking variant to prevent random delays on startup
				String weakerAlgorithms = strongAlgorithms.replaceAll("NativePRNGBlocking", "NativePRNGNonBlocking");
				Security.setProperty("securerandom.strongAlgorithms", weakerAlgorithms);
			} else {
				SecureRandom random = new SecureRandom();
				String defaultAlgorithm = random.getAlgorithm() + ":";
				if (!strongAlgorithms.contains(defaultAlgorithm)) {
					// use default variant to prevent random delays on startup
					String defaultProvider = random.getProvider().getName();
					String weakerAlgorithms = defaultAlgorithm + defaultProvider + "," + strongAlgorithms;
					Security.setProperty("securerandom.strongAlgorithms", weakerAlgorithms);
				} else {
					LOGGER.info("Random: {} already in {}", defaultAlgorithm, strongAlgorithms);
				}
			}
		}
		return strongAlgorithms;
	}

	/**
	 * Setup JCE.
	 * 
	 * Prepare and check, if EdDSA is supported.
	 * 
	 * @since 3.0
	 */
	private static void setupJce() {
		boolean tryJce = false;
		boolean tryBc = false;
		boolean tryEd25519Java = false;
		boolean nonBlockingRandom = false;
		String jce = StringUtil.getConfiguration(JceNames.CALIFORNIUM_JCE_PROVIDER);
		if (jce != null && !jce.isEmpty()) {
			LOGGER.info("JCE setup: {}", jce);
			if (JceNames.JCE_PROVIDER_SYSTEM.equalsIgnoreCase(jce)) {
				tryJce = true;
			} else if (JceNames.JCE_PROVIDER_BOUNCY_CASTLE.equalsIgnoreCase(jce)) {
				tryBc = true;
			} else if (JceNames.JCE_PROVIDER_BOUNCY_CASTLE_NON_BLOCKING_RANDOM.equalsIgnoreCase(jce)) {
				tryBc = true;
				nonBlockingRandom = true;
			} else if (JceNames.JCE_PROVIDER_NET_I2P_CRYPTO.equalsIgnoreCase(jce)) {
				tryEd25519Java = true;
			}
		} else {
			// default
			LOGGER.info("JCE default setup");
			tryJce = true;
			tryEd25519Java = true;
		}
		boolean found = false;
		Provider provider = null;
		try {
			KeyFactory factory = KeyFactory.getInstance(JceNames.EDDSA);
			provider = factory.getProvider();
			if (tryJce) {
				found = true;
				LOGGER.trace("EdDSA from default jce {}", provider.getName());
			}
		} catch (NoSuchAlgorithmException e) {
		}
		if (!found && tryBc) {
			if (isBouncyCastle(provider)) {
				found = true;
				LOGGER.trace("EdDSA from BC");
			} else {
				setupLoggingBridge();
				String strongAlgorithms = nonBlockingRandom ? setupNonBlockingSecureRandom() : null;
				Provider newProvider = loadProvider(BOUNCY_CASTLE_JCE_PROVIDER);
				if (newProvider != null) {
					try {
						KeyFactory.getInstance(JceNames.EDDSA, newProvider);
						Security.removeProvider(newProvider.getName());
						Security.insertProviderAt(newProvider, 1);
						provider = newProvider;
						found = true;
						// tweak the SecureRandom to initialize
						SecureRandom start = new SecureRandom();
						start.nextInt();
						String algorithms = Security.getProperty("securerandom.strongAlgorithms");
						if (algorithms == null) {
							algorithms = "not available";
						}
						LOGGER.info("StrongRandom: {}", algorithms);
						LOGGER.trace("EdDSA added from BC");
					} catch (SecurityException e) {
					} catch (NoSuchAlgorithmException e) {
					}
				}
				if (strongAlgorithms != null) {
					// restore configuration
					Security.setProperty("securerandom.strongAlgorithms", strongAlgorithms);
				}
				if (found && Security.getProvider(JSSE_PROVIDER_BOUNCY_CASTLE) == null) {
					// support netty.io TLS
					newProvider = loadProvider(BOUNCY_CASTLE_JSSE_PROVIDER);
					if (newProvider != null) {
						Security.setProperty("ssl.KeyManagerFactory.algorithm", "PKIX");
						Security.setProperty("ssl.TrustManagerFactory.algorithm", "PKIX");
						try {
							Security.insertProviderAt(newProvider, 2);
							LOGGER.trace("TLS from added BC");
						} catch (SecurityException e) {
						}
					}
				}
			}
		}
		if (!found && tryEd25519Java) {
			if (isNetI2PEdDsa(provider)) {
				found = true;
				LOGGER.trace("EdDSA from {}", NET_I2P_CRYPTO_EDDSA);
			} else {
				Provider newProvider = loadProvider(NET_I2P_CRYPTO_EDDSA_PROVIDER);
				if (newProvider != null) {
					try {
						KeyFactory.getInstance(JceNames.EDDSA, newProvider);
						Security.removeProvider(newProvider.getName());
						Security.addProvider(newProvider);
						provider = newProvider;
						found = true;
						LOGGER.trace("EdDSA added from {}", NET_I2P_CRYPTO_EDDSA);
					} catch (SecurityException e) {
					} catch (NoSuchAlgorithmException e) {
					}
				}
			}
		}
		boolean ec = false;
		boolean rsa = false;
		boolean ecdsaVulnerable = false;
		String aesPermission = "not supported";
		int aesMaxAllowedKeyLength = 0;
		try {
			aesMaxAllowedKeyLength = Cipher.getMaxAllowedKeyLength(AES);
			if (aesMaxAllowedKeyLength == Integer.MAX_VALUE) {
				aesPermission = "not restricted";
			} else {
				aesPermission = "restricted to " + aesMaxAllowedKeyLength + " bits key length";
			}
		} catch (NoSuchAlgorithmException ex) {
		}
		LOGGER.debug("AES: {}", aesPermission);
		try {
			KeyFactory.getInstance(JceNames.RSA);
			rsa = true;
		} catch (NoSuchAlgorithmException e) {
		}
		LOGGER.debug("RSA: {}", rsa);
		try {
			KeyFactory.getInstance(JceNames.EC);
			ec = true;
		} catch (NoSuchAlgorithmException e) {
		}
		LOGGER.debug("EC: {}", ec);
		if (ec) {
			String ecdsaFix = StringUtil.getConfiguration(JceNames.CALIFORNIUM_JCE_ECDSA_FIX);
			if (ecdsaFix == null || !ecdsaFix.equalsIgnoreCase("false")) {
				ecdsaVulnerable = true;
				try {
					Signature signature = Signature.getInstance("SHA256withECDSA");
					KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
					keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
					KeyPair keyPair = keyPairGenerator.generateKeyPair();
					// malicious signature
					byte[] ghost = StringUtil.hex2ByteArray("3006020100020100");
					signature.initVerify(keyPair.getPublic());
					signature.update(ghost);
					ecdsaVulnerable = signature.verify(ghost);
				} catch (NoSuchAlgorithmException e) {
				} catch (InvalidAlgorithmParameterException e) {
				} catch (InvalidKeyException e) {
				} catch (SignatureException e) {
				}
				LOGGER.debug("ECDSA {}vulnerable.", ecdsaVulnerable ? "" : "not ");
			}
		}
		if (!LOGGER.isDebugEnabled()) {
			LOGGER.info("RSA: {}, EC: {}, AES: {}", rsa, ec, aesPermission);
		}
		String version = provider == null ? "n.a." : Double.toString(provider.getVersion());
		boolean ed25519 = false;
		boolean ed448 = false;
		if (found && provider != null) {
			if (isBouncyCastle(provider)) {
				// Bouncy Castle support: add OIDs to KeyFactory
				configure(provider, "Alg.Alias.KeyFactory." + JceNames.OID_ED25519, JceNames.ED25519);
				configure(provider, "Alg.Alias.KeyFactory." + JceNames.OID_ED448, JceNames.ED448);
			} else if (isNetI2PEdDsa(provider)) {
				// i2p EdDSA support: add Ed25519 to KeyFactory
				configure(provider, "Alg.Alias.KeyFactory." + JceNames.ED25519, JceNames.EDDSA);
			}
			try {
				KeyFactory.getInstance(JceNames.ED25519);
				ed25519 = true;
			} catch (NoSuchAlgorithmException e) {
			}
			try {
				KeyFactory.getInstance(JceNames.ED448);
				ed448 = true;
			} catch (NoSuchAlgorithmException e) {
			}
			LOGGER.info("EdDSA supported by {}, Ed25519: {}, Ed448: {}", provider.getName(), ed25519, ed448);
		} else {
			provider = null;
			LOGGER.info("EdDSA not supported!");
		}
		JceProviderUtil newSupport = new JceProviderUtil(isBouncyCastle(provider), rsa, ec, ed25519, ed448,
				aesMaxAllowedKeyLength >= 256, ecdsaVulnerable, version);
		if (!newSupport.equals(features)) {
			features = newSupport;
		}
		LOGGER.info("JCE setup: {}, ready.", provider);
		if (LOGGER.isDebugEnabled()) {
			Provider[] providers = Security.getProviders();
			for (int index = 0; index < providers.length; ++index) {
				provider = providers[index];
				LOGGER.debug("Security Provider [{}]: {}.", index, provider);
			}
			LOGGER.trace("JCE setup callstack:", new Throwable("JCE setup"));
		}
	}

	/**
	 * Ensure, the class is initialized.
	 */
	public static void init() {
		// empty
	}

	/**
	 * Check, if Bouncy Castle is used in order to support EdDSA.
	 * 
	 * @return {@code true}, if Bouncy Castle is used, or {@code false}, if not.
	 */
	public static boolean usesBouncyCastle() {
		return features.useBc;
	}

	/**
	 * Checks, whether the JCE support strong encryption according to the
	 * installed JCE jurisdiction policy files.
	 * 
	 * Checks for AES-256.
	 * 
	 * @return {@code true}, if strong encryption is available, {@code false},
	 *         if not
	 */
	public static boolean hasStrongEncryption() {
		return features.strongEncryption;
	}

	/**
	 * Checks, if the JCE is affected by the ECDSA vulnerability.
	 * 
	 * Some java JCE versions 15 to 18 fail to check the signature for 0 and n.
	 * 
	 * @return {@code true}, if the JCE has the ECDSA vulnerability,
	 *         {@code false}, otherwise. signature received signature.
	 * @see <a href=
	 *      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21449"
	 *      target="_blank">CVE-2022-21449</a>
	 * @see JceNames#CALIFORNIUM_JCE_ECDSA_FIX
	 * @since 3.5
	 */
	public static boolean isEcdsaVulnerable() {
		return features.ecdsaVulnerable;
	}

	/**
	 * Check, if key algorithm is supported.
	 * 
	 * @param algorithm key algorithm
	 * @return {@code true}, if supported, {@code false}, otherwise.
	 */
	public static boolean isSupported(String algorithm) {
		if (JceNames.EC.equalsIgnoreCase(algorithm)) {
			return features.ec;
		} else if (JceNames.RSA.equalsIgnoreCase(algorithm)) {
			return features.rsa;
		} else {
			String oid = getEdDsaStandardAlgorithmName(algorithm, null);
			if (JceNames.OID_ED25519.equals(oid)) {
				return features.ed25519;
			} else if (JceNames.OID_ED448.equals(oid)) {
				return features.ed448;
			} else if (JceNames.EDDSA.equalsIgnoreCase(algorithm)) {
				return features.ed25519 || features.ed448;
			}
		}
		return false;
	}

	/**
	 * Get EdDSA standard algorithm name.
	 * 
	 * @param algorithm algorithm
	 * @param def default algorithm
	 * @return Either {@link JceNames#OID_ED25519}, {@link JceNames#OID_ED448},
	 *         {@link JceNames#EDDSA}, or the provided default algorithm
	 * @since 3.3
	 */
	public static String getEdDsaStandardAlgorithmName(String algorithm, String def) {
		if (JceNames.EDDSA.equalsIgnoreCase(algorithm)) {
			return JceNames.EDDSA;
		} else if (StringUtil.containsIgnoreCase(ED25519_ALIASES, algorithm)) {
			return JceNames.OID_ED25519;
		} else if (StringUtil.containsIgnoreCase(ED448_ALIASES, algorithm)) {
			return JceNames.OID_ED448;
		} else {
			return def;
		}
	}

	/**
	 * Check for equal key algorithm synonyms.
	 * 
	 * @param keyAlgorithm1 key algorithm 1
	 * @param keyAlgorithm2 key algorithm 2
	 * @return {@code true}, if the key algorithms are equal or synonyms,
	 *         {@code false}, otherwise.
	 * @since 3.3
	 */
	public static boolean equalKeyAlgorithmSynonyms(String keyAlgorithm1, String keyAlgorithm2) {
		if (keyAlgorithm1 != null && keyAlgorithm1.equals(keyAlgorithm2)) {
			return true;
		}
		for (String[] aliases : ALGORITHM_ALIASES) {
			if (StringUtil.containsIgnoreCase(aliases, keyAlgorithm1)
					&& StringUtil.containsIgnoreCase(aliases, keyAlgorithm2)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Get provider version.
	 * 
	 * @return provider version. {@code "n.a."}, if not available.
	 * @see Provider#getVersion()
	 * @since 3.3
	 */
	public static String getProviderVersion() {
		return features.providerVersion;
	}

	private JceProviderUtil(boolean useBc, boolean rsa, boolean ec, boolean ed25519, boolean ed448,
			boolean strongEncryption, boolean ecdsaVulnerable, String providerVersion) {
		this.useBc = useBc;
		this.rsa = rsa;
		this.ec = ec;
		this.ed25519 = ed25519;
		this.ed448 = ed448;
		this.strongEncryption = strongEncryption;
		this.ecdsaVulnerable = ecdsaVulnerable;
		this.providerVersion = providerVersion;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (ed25519 ? 41 : 37);
		result = prime * result + (ed448 ? 41 : 37);
		result = prime * result + (strongEncryption ? 41 : 37);
		result = prime * result + (ec ? 41 : 37);
		result = prime * result + (rsa ? 41 : 37);
		result = prime * result + (useBc ? 41 : 37);
		result = prime * result + providerVersion.hashCode();
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		JceProviderUtil other = (JceProviderUtil) obj;
		if (ed25519 != other.ed25519)
			return false;
		if (ed448 != other.ed448)
			return false;
		if (strongEncryption != other.strongEncryption)
			return false;
		if (ec != other.ec)
			return false;
		if (rsa != other.rsa)
			return false;
		if (useBc != other.useBc)
			return false;
		if (!providerVersion.equals(other.providerVersion))
			return false;
		return true;
	}
}
