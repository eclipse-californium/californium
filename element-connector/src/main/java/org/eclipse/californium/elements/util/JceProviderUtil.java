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
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

import javax.crypto.Cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JCE provider util.
 * <p>
 * Initialize JCE provider.
 * <p>
 * To support EdDSA, either java 15, or java 11 with
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
 * With version 3.0 an experimental support for using Bouncy Castle (version
 * 1.69) as JCE is available. On class startup, the default JCE is checked for
 * providing EdDSA. If that fails, ed25519-java is tested and, on success, added
 * as provider. To use Bouncy Castle or if the JCE provider should not be used,
 * the environment variable "CALIFORNIUM_JCE_PROVIDER" is used. Configure that
 * with one of the values "SYSTEM" (keep the providers configured externally),
 * "BC" (load and insert the Bouncy Castle provider), "I2P" (load
 * net.i2p.crypto.eddsa ed25519-java and use that for EdDSA).
 * <p>
 * Though Bouncy Castle uses JUL for logging, jul2slf4j2 is added when using BC.
 * That requires {@code org.slf4j.bridge.SLF4JBridgeHandler} in the classpath.
 * The bridge is only activated, if "CALIFORNIUM_JCE_PROVIDER" is set to "BC"
 * and Bouncy Castle is not already set as security provider.
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
	 * Name of environment variable to specify JCE,.
	 */
	private static final String CALIFORNIUM_JCE_PROVIDER = "CALIFORNIUM_JCE_PROVIDER";
	/**
	 * Value for {@link #CALIFORNIUM_JCE_PROVIDER} to use only the provided JCE.
	 */
	private static final String JCE_PROVIDER_SYSTEM = "SYSTEM";
	/**
	 * Value for {@link #CALIFORNIUM_JCE_PROVIDER} to use Bouncy Castle as JCE.
	 */
	private static final String JCE_PROVIDER_BOUNCY_CASTLE = "BC";
	/**
	 * Value for {@link #CALIFORNIUM_JCE_PROVIDER} to use ed25519-java as JCE
	 * for EdDSA.
	 */
	private static final String JCE_PROVIDER_NET_I2P_CRYPTO = "I2P";
	/**
	 * Value to use Bouncy Castle as JSSE (TLS only).
	 */
	private static final String JSSE_PROVIDER_BOUNCY_CASTLE = "BCJSSE";

	/**
	 * Cipher name to check for strong encryption.
	 */
	private static final String AES = "AES";

	private final boolean useBc;
	private final boolean rsa;
	private final boolean ec;
	private final boolean ed25519;
	private final boolean ed448;
	private final boolean strongEncryption;

	static {
		setupJce();
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
		return provider != null && provider.getName().equals(JCE_PROVIDER_BOUNCY_CASTLE);
	}

	/**
	 * Configure provider, if Bouncy Castle is used.
	 * 
	 * @param provider provider to configure. If not Bouncy Castle, leave it
	 *            unchanged.
	 */
	private static void configureBouncyCastle(Provider provider) {
		if (isBouncyCastle(provider)) {
			// Bouncy Castle support: add OIDs to KeyFactory
			configure(provider, "Alg.Alias.KeyFactory." + Asn1DerDecoder.OID_ED25519, Asn1DerDecoder.ED25519);
			configure(provider, "Alg.Alias.KeyFactory." + Asn1DerDecoder.OID_ED448, Asn1DerDecoder.ED448);
		}
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
			LOGGER.info("Loaded {}", clzName);
			return provider;
		} catch (Throwable e) {
			LOGGER.trace("Loading {} failed!", clzName, e);
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
		} catch (Throwable e) {
			LOGGER.warn("Setup BC logging failed!", e);
		}
	}

	/**
	 * Setup JCE.
	 * 
	 * Prepare and check, if EdDSA is supported.
	 * 
	 * @since 3.0
	 */
	private static void setupJce() {
		boolean tryJce = true;
		boolean tryBc = false;
		boolean tryEd25519Java = true;
		String jce = StringUtil.getConfiguration(CALIFORNIUM_JCE_PROVIDER);
		if (jce != null && !jce.isEmpty()) {
			LOGGER.info("JCE setup: {}", jce);
			if (JCE_PROVIDER_SYSTEM.equalsIgnoreCase(jce)) {
				tryBc = false;
				tryEd25519Java = false;
			} else if (JCE_PROVIDER_BOUNCY_CASTLE.equalsIgnoreCase(jce)) {
				tryBc = true;
				tryJce = false;
				tryEd25519Java = false;
			} else if (JCE_PROVIDER_NET_I2P_CRYPTO.equalsIgnoreCase(jce)) {
				tryJce = false;
				tryBc = false;
			}
		}
		boolean found = false;
		Provider provider = null;
		try {
			KeyFactory factory = KeyFactory.getInstance(Asn1DerDecoder.EDDSA);
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
				Provider newProvider = loadProvider(BOUNCY_CASTLE_JCE_PROVIDER);
				if (newProvider != null) {
					try {
						KeyFactory.getInstance(Asn1DerDecoder.EDDSA, newProvider);
						Security.removeProvider(newProvider.getName());
						Security.insertProviderAt(newProvider, 1);
						provider = newProvider;
						found = true;
						LOGGER.trace("EdDSA from BC");
					} catch (SecurityException e) {
					} catch (NoSuchAlgorithmException e) {
					}
				}
				if (found && Security.getProvider(JSSE_PROVIDER_BOUNCY_CASTLE) == null) {
					// support netty.io TLS
					newProvider = loadProvider(BOUNCY_CASTLE_JSSE_PROVIDER);
					if (newProvider != null) {
						Security.setProperty("ssl.KeyManagerFactory.algorithm","PKIX");
						Security.setProperty("ssl.TrustManagerFactory.algorithm","PKIX");
						try {
							Security.insertProviderAt(newProvider, 2);
							LOGGER.info("TLS from BC");
						} catch (SecurityException e) {
						}
					}
				}
			}
		}
		if (!found && tryEd25519Java) {
			if (provider != null && provider.getClass().getName().equals(NET_I2P_CRYPTO_EDDSA_PROVIDER)) {
				found = true;
				LOGGER.trace("EdDSA from {}", NET_I2P_CRYPTO_EDDSA);
			} else {
				Provider newProvider = loadProvider(NET_I2P_CRYPTO_EDDSA_PROVIDER);
				if (newProvider != null) {
					try {
						KeyFactory.getInstance(Asn1DerDecoder.ED25519, newProvider);
						Security.removeProvider(newProvider.getName());
						Security.addProvider(newProvider);
						provider = newProvider;
						found = true;
						LOGGER.trace("EdDSA from {}", NET_I2P_CRYPTO_EDDSA);
					} catch (SecurityException e) {
					} catch (NoSuchAlgorithmException e) {
					}
				}
			}
		}
		boolean strongEncryption = false;
		try {
			strongEncryption = Cipher.getMaxAllowedKeyLength(AES) >= 256;
		} catch (NoSuchAlgorithmException ex) {
		}
		boolean ec = false;
		boolean rsa = false;
		try {
			KeyFactory.getInstance(Asn1DerDecoder.RSA);
			rsa = true;
		} catch (NoSuchAlgorithmException e) {
		}
		try {
			KeyFactory.getInstance(Asn1DerDecoder.EC);
			ec = true;
		} catch (NoSuchAlgorithmException e) {
		}
		LOGGER.debug("RSA: {}, EC: {}, strong encryption: {}", rsa, ec, strongEncryption);
		boolean ed25519 = false;
		boolean ed448 = false;
		if (found && provider != null) {
			configureBouncyCastle(provider);
			try {
				KeyFactory.getInstance(Asn1DerDecoder.ED25519);
				ed25519 = true;
			} catch (NoSuchAlgorithmException e) {
			}
			try {
				KeyFactory.getInstance(Asn1DerDecoder.ED448);
				ed448 = true;
			} catch (NoSuchAlgorithmException e) {
			}
			LOGGER.debug("EdDSA supported by {}, Ed25519: {}, Ed448: {}", provider.getName(),
					ed25519, ed448);
		} else {
			provider = null;
			LOGGER.debug("EdDSA not supported!");
		}
		JceProviderUtil newSupport = new JceProviderUtil(isBouncyCastle(provider), rsa, ec, ed25519, ed448, strongEncryption);
		if (!newSupport.equals(features)) {
			features = newSupport;
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
	 * Checks, whether the JCE support strong encryption or not.
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
	 * Check, if key algorithm is supported.
	 * 
	 * @param algorithm key algorithm
	 * @return {@code true}, if supported, {@code false}, otherwise.
	 */
	public static boolean isSupported(String algorithm) {
		if (Asn1DerDecoder.EC.equalsIgnoreCase(algorithm)) {
			return features.ec;
		} else if (Asn1DerDecoder.RSA.equalsIgnoreCase(algorithm)) {
			return features.rsa;
		} else {
			String oid = Asn1DerDecoder.getEdDsaStandardAlgorithmName(algorithm, null);
			if (Asn1DerDecoder.OID_ED25519.equals(oid)) {
				return features.ed25519;
			} else if (Asn1DerDecoder.OID_ED448.equals(oid)) {
				return features.ed448;
			} else if (Asn1DerDecoder.EDDSA.equalsIgnoreCase(algorithm)) {
				return features.ed25519 || features.ed448;
			}
		}
		return false;
	}

	private JceProviderUtil(boolean useBc, boolean rsa, boolean ec, boolean ed25519, boolean ed448, boolean strongEncryption) {
		this.useBc = useBc;
		this.rsa = rsa;
		this.ec = ec;
		this.ed25519 = ed25519;
		this.ed448 = ed448;
		this.strongEncryption = strongEncryption;
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
		return true;
	}
}
