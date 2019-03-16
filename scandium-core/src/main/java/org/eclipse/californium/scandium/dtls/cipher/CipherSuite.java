/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - adapt name of NULL cipher to match
 *               official IANA name
 *    Kai Hudalla (Bosch Software Innovations GmbH) - Add getters for conveniently accessing
 *               a cipher suite's underlying security parameters, add definitions for CBC based
 *               cipher suites mandatory for LW M2M servers
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add method for checking if suite requires
 *               sending of a CERTIFICATE message to the client
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - add containsEccBasedCipherSuite
 *                                                    support for certificate-based,
 *                                                    none ECC-based cipher suites is
 *                                                    still missing!
 *    Vikram (University of Rostock) - added CipherSuite TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 
 *    Achim Kraus (Bosch Software Innovations GmbH) - add TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
 *                                                    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, and
 *                                                    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;


/**
 * A cipher suite defines a key exchange algorithm, a bulk cipher algorithm, a
 * MAC algorithm, a pseudo random number (PRF) algorithm and a cipher type.
 * 
 * See <a href="http://tools.ietf.org/html/rfc5246#appendix-A.6">RFC 5246</a>
 * for details.
 * See <a href="http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml">
 * Transport Layer Security Parameters</a> for the official codes for the cipher
 * suites.
 */
public enum CipherSuite {

	// Cipher suites //////////////////////////////////////////////////

	// Cipher suites order is based on those statements : 
	// - ECDHE is preferred  as it provides perfect forward secrecy.
	// - AES_128 preferred over AES_192/256 because it's secure enough & faster.
	//      source:https://www.quora.com/Is-AES256-more-secure-than-AES128-Whats-the-different
	//      source:https://security.stackexchange.com/questions/14068/why-most-people-use-256-bit-encryption-instead-of-128-bit#19762
	// - GCM >= CCM_8 ~= CCM >> CBC
	//      source:https://en.wikipedia.org/wiki/Transport_Layer_Security#Cipher
	//      source:https://crypto.stackexchange.com/questions/63796/why-does-tls-1-3-support-two-ccm-variants/64809#64809
	// - SHA sounds secure enough and so smaller SHA is preferred.
	//      source:https://security.stackexchange.com/questions/84304/why-were-cbc-sha256-ciphersuites-like-tls-rsa-with-aes-128-cbc-sha256-defined
	//      source:https://crypto.stackexchange.com/questions/20572/sha1-ssl-tls-cipher-suite
	// See more:
	//      https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices
	//
	// /!\ CBC should be avoid /!\  because :
	// - Implementing authenticated decryption (checking padding and mac) without any side channel is hard (see Lucky 13 attack and its variants).
	//   The solution is to use the encrypt then mac extension defined in RFC 7366, which is recommended. (from LWM2M 1.0.2 specification)
	// - Currently Scandium does not support RFC 7366.

	// PSK cipher suites, ordered by default preference, see getPskCiperSuites ///
	TLS_PSK_WITH_AES_128_GCM_SHA256(0x00A8, CertificateKeyAlgorithm.NONE, KeyExchangeAlgorithm.PSK, Cipher.AES_128_GCM, MACAlgorithm.NULL, true),
	TLS_PSK_WITH_AES_128_CCM_8(0xC0A8, CertificateKeyAlgorithm.NONE, KeyExchangeAlgorithm.PSK, Cipher.AES_128_CCM_8, MACAlgorithm.NULL, false),
	TLS_PSK_WITH_AES_256_CCM_8(0xC0A9, CertificateKeyAlgorithm.NONE, KeyExchangeAlgorithm.PSK, Cipher.AES_256_CCM_8, MACAlgorithm.NULL, true),
	TLS_PSK_WITH_AES_128_CCM(0xC0A4, CertificateKeyAlgorithm.NONE, KeyExchangeAlgorithm.PSK, Cipher.AES_128_CCM, MACAlgorithm.NULL, true),
	TLS_PSK_WITH_AES_256_CCM(0xC0A5, CertificateKeyAlgorithm.NONE, KeyExchangeAlgorithm.PSK, Cipher.AES_256_CCM, MACAlgorithm.NULL, true),
	/**See <a href="https://tools.ietf.org/html/rfc5489#section-3.2">RFC 5489</a> for details*/
	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256(0xC037, CertificateKeyAlgorithm.NONE, KeyExchangeAlgorithm.ECDHE_PSK, Cipher.AES_128_CBC, MACAlgorithm.HMAC_SHA256, true),
	TLS_PSK_WITH_AES_128_CBC_SHA256(0x00AE, CertificateKeyAlgorithm.NONE, KeyExchangeAlgorithm.PSK, Cipher.AES_128_CBC, MACAlgorithm.HMAC_SHA256, false),

	// Certificate cipher suites, ordered by default preference, see getCertificateCipherSuites or getEcdsaCipherSuites ///
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(0xc02b, CertificateKeyAlgorithm.EC, KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, Cipher.AES_128_GCM, MACAlgorithm.NULL, true),
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8(0xC0AE, CertificateKeyAlgorithm.EC, KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, Cipher.AES_128_CCM_8, MACAlgorithm.NULL, false),
	TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8(0xC0AF, CertificateKeyAlgorithm.EC, KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, Cipher.AES_256_CCM_8, MACAlgorithm.NULL, true),
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM(0xC0AC, CertificateKeyAlgorithm.EC, KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, Cipher.AES_128_CCM, MACAlgorithm.NULL, true),
	TLS_ECDHE_ECDSA_WITH_AES_256_CCM(0xC0AD, CertificateKeyAlgorithm.EC, KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, Cipher.AES_256_CCM, MACAlgorithm.NULL, true),
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA(0xC00A, CertificateKeyAlgorithm.EC, KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, Cipher.AES_256_CBC, MACAlgorithm.HMAC_SHA1, true),
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256(0xC023, CertificateKeyAlgorithm.EC, KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, Cipher.AES_128_CBC, MACAlgorithm.HMAC_SHA256, false),
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384(0xC024, CertificateKeyAlgorithm.EC, KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, Cipher.AES_256_CBC, MACAlgorithm.HMAC_SHA384, true, PRFAlgorithm.TLS_PRF_SHA384),

	// Null cipher suite ///
	TLS_NULL_WITH_NULL_NULL(0x0000, CertificateKeyAlgorithm.NONE, KeyExchangeAlgorithm.NULL, Cipher.NULL, MACAlgorithm.NULL, true),
	;

	// DTLS-specific constants ////////////////////////////////////////
	public static final int CIPHER_SUITE_BITS = 16;

	// Logging ////////////////////////////////////////////////////////
	private static final Logger LOGGER = LoggerFactory.getLogger(CipherSuite.class.getCanonicalName());

	// Members ////////////////////////////////////////////////////////
	private static int overallMaxCipherTextExpansion = 0;

	/**
	 * 16 bit identification, i.e. 0x0000 for SSL_NULL_WITH_NULL_NULL, see <a
	 * href="http://tools.ietf.org/html/rfc5246#appendix-A.5">RFC 5246</a>.
	 */
	private final int code;
	private final CertificateKeyAlgorithm certificateKeyAlgorithm;
	private final KeyExchangeAlgorithm keyExchange;
	private final Cipher cipher;
	private final MACAlgorithm macAlgorithm;
	private final PRFAlgorithm pseudoRandomFunction;
	private final int maxCipherTextExpansion;
	private boolean extendedCipherSuite;

	// Constructor ////////////////////////////////////////////////////

	private CipherSuite(int code, CertificateKeyAlgorithm certificate, KeyExchangeAlgorithm keyExchange, Cipher cipher, MACAlgorithm macAlgorithm, boolean extendedCipherSuite) {
		this(code, certificate, keyExchange, cipher, macAlgorithm, extendedCipherSuite, PRFAlgorithm.TLS_PRF_SHA256);
	}

	private CipherSuite(int code, CertificateKeyAlgorithm certificate, KeyExchangeAlgorithm keyExchange, Cipher cipher, MACAlgorithm macAlgorithm, boolean extendedCipherSuite, PRFAlgorithm prf) {
		this.code = code;
		this.certificateKeyAlgorithm = certificate;
		this.keyExchange = keyExchange;
		this.cipher = cipher;
		this.macAlgorithm = macAlgorithm;
		this.extendedCipherSuite = extendedCipherSuite;
		this.pseudoRandomFunction = prf;
		switch(this.cipher.getType()) {
		case BLOCK:
			maxCipherTextExpansion =
				cipher.getRecordIvLength() // IV
					+ macAlgorithm.getOutputLength() // MAC
					+ cipher.getRecordIvLength() // max padding (block size)
					+ 1; // padding length
			break;
		case AEAD:
			maxCipherTextExpansion =
				cipher.getRecordIvLength() // explicit nonce
					+ cipher.getMacLength();
			break;
		default:
			maxCipherTextExpansion = 0;
		}
	}

	// Getters ////////////////////////////////////////////////////////

	/**
	 * Get maximum expansion of cipher text using this cipher suite.
	 * 
	 * Includes MAC, explicit nonce, and padding.
	 * 
	 * @return maxnium expansion of this cipher suite
	 * @see  #getMacLength()
	 * @see  #getRecordIvLength()
	 */
	public int getMaxCiphertextExpansion() {
		return maxCipherTextExpansion;
	}

	/**
	 * Gets the Java Cryptography Architecture <em>transformation</em> corresponding
	 * to the suite's underlying cipher algorithm.
	 * 
	 * The name can be used to instantiate a <code>javax.crypto.Cipher</code> object
	 * (if a security provider is available in the JVM supporting the transformation).
	 * See <a href="http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Cipher">
	 * Java Security Documentation</a>.
	 * 
	 * @return the transformation
	 */
	public String getTransformation() {
		return cipher.getTransformation();
	}

	/**
	 * Gets the 16-bit IANA assigned identification code of the cipher suite.
	 * 
	 * See <a href="http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4">
	 * TLS Cipher Suite Registry</a>.
	 * 
	 * @return the identification code
	 */
	public int getCode() {
		return code;
	}

	/**
	 * Gets the certificate key algorithm of the cipher suite.
	 * 
	 * @return the algorithm
	 */
	public CertificateKeyAlgorithm getCertificateKeyAlgorithm() {
		return certificateKeyAlgorithm;
	}

	/**
	 * Gets the key exchange algorithm the cipher suite employs to
	 * generate a pre-master secret.
	 * 
	 * @return the algorithm
	 */
	public KeyExchangeAlgorithm getKeyExchange() {
		return keyExchange;
	}

	/**
	 * Checks whether this cipher suite requires the server
	 * to send a <em>CERTIFICATE</em> message during the handshake.
	 * 
	 * @return {@code true} if the message is required
	 */
	public boolean requiresServerCertificateMessage() {
		return !CertificateKeyAlgorithm.NONE.equals(certificateKeyAlgorithm);
	}

	/**
	 * Checks whether this cipher suite use <em>PSK<em> key exchange.

	 * @return {@code true} if <em>PSK<em> key exchange is used
	 */
	public boolean isPskBased() {
		return KeyExchangeAlgorithm.PSK.equals(keyExchange) || KeyExchangeAlgorithm.ECDHE_PSK.equals(keyExchange);
	}

	/**
	 * Checks whether this cipher suite uses elliptic curve cryptography (ECC).
	 * 
	 * @return {@code true} if ECC is used
	 */
	public boolean isEccBased() {
		return CertificateKeyAlgorithm.EC.equals(certificateKeyAlgorithm)
				|| KeyExchangeAlgorithm.ECDHE_PSK.equals(keyExchange)
				|| KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN.equals(keyExchange);
	}

	/**
	 * Checks whether this cipher suite is supported by the jvm implementation.
	 * 
	 * @return {@code true} if cipher suite is supported
	 */
	public boolean isSupported() {
		return pseudoRandomFunction.getMacAlgorithm().isSupported() && macAlgorithm.isSupported()
				&& cipher.isSupported();
	}

	/**
	 * Gets the output length of the cipher suite's MAC algorithm.
	 *  
	 * @return the length in bytes
	 */
	public int getMacLength() {
		if (macAlgorithm == MACAlgorithm.NULL) {
			return cipher.getMacLength();
		} else {
			return macAlgorithm.getOutputLength();
		}
	}

	/**
	 * Gets the key length of the cipher suite's MAC algorithm.
	 *  
	 * @return the length in bytes
	 */
	public int getMacKeyLength() {
		return macAlgorithm.getKeyLength();
	}

	/**
	 * Gets the name of the cipher suite's MAC algorithm.
	 * 
	 * The name can be used to instantiate a <code>javax.crypto.Mac</code>
	 * instance.
	 * 
	 * See <a href="http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Mac">
	 * Java Security Documentation</a>.
	 * 
	 * @return the name or <code>null</code> for the <em>NULL</em> MAC
	 */
	public String getMacName() {
		return macAlgorithm.getName();
	}

	/**
	 * Gets the amount of data needed to be generated for the cipher's
	 * initialization vector.
	 * 
	 * Zero for stream ciphers; equal to the block size for block ciphers
	 * (this is equal to SecurityParameters.record_iv_length).
	 * 
	 * @return the length in bytes
	 */
	public int getRecordIvLength() {
		return cipher.getRecordIvLength();
	}

	/**
	 * Gets the length of the fixed initialization vector (IV) of
	 * the cipher suite's bulk cipher algorithm.
	 * 
	 * This is only relevant for AEAD based cipher suites.
	 * 
	 * @return the length in bytes
	 */
	public int getFixedIvLength() {
		return cipher.getFixedIvLength();
	}

	/**
	 * Gets the pseudo-random function used by the cipher suite
	 * to create (pseudo-)random data from a seed.
	 * 
	 * @return the function
	 */
	public String getPseudoRandomFunctionMacName() {
		return pseudoRandomFunction.getMacAlgorithm().getName();
	}

	/**
	 * Gets the pseudo-random hash function used by the cipher suite
	 * to create the hash over the handshake messages.
	 * 
	 * @return the hash function
	 */
	public String getPseudoRandomFunctionHashName() {
		return pseudoRandomFunction.getMacAlgorithm().getHashName();
	}

	/**
	 * Gets the type of cipher used for encrypting data.
	 * 
	 * @return the type
	 */
	public CipherType getCipherType() {
		return cipher.getType();
	}

	/**
	 * Gets the length of the bulk cipher algorithm's encoding key.
	 * 
	 * @return the length in bytes
	 */
	public int getEncKeyLength() {
		return cipher.getKeyLength();
	}

	/**
	 * Get the overall maximum ciphertext expansion for all cipher suite.
	 * 
	 * @return overall maximum ciphertext expansion.
	 */
	public static int getOverallMaxCiphertextExpansion() {
		if (overallMaxCipherTextExpansion == 0) {
			int overall = 0;
			for (CipherSuite suite : values()) {
				if (suite.isSupported()) {
					overall = Math.max(overall, suite.getMaxCiphertextExpansion());
				}
			}
			overallMaxCipherTextExpansion = overall;
		}
		return overallMaxCipherTextExpansion;
	}

	/**
	 * Get a list of all supported PSK cipher suites.
	 * 
	 * @param extendedCipherSuites use also extended cipher suites
	 * @return list of all supported PSK cipher suites. Ordered by their definition above.
	 */
	public static List<CipherSuite> getPskCipherSuites(boolean extendedCipherSuites, boolean ecdhePsk) {
		List<CipherSuite> list = new ArrayList<>();
		for (CipherSuite suite : values()) {
			if (suite.isSupported()) {
				if (KeyExchangeAlgorithm.PSK.equals(suite.keyExchange)
						|| (ecdhePsk && KeyExchangeAlgorithm.ECDHE_PSK.equals(suite.keyExchange))) {
					if (extendedCipherSuites || !suite.extendedCipherSuite) {
						list.add(suite);
					}
				}
			}
		}
		return list;
	}

	/**
	 * Get a list of all supported ECDSA cipher suites.
	 * 
	 * @param extendedCipherSuites use also extended cipher suites
	 * @return list of all supported ECDSA cipher suites. Ordered by their definition above.
	 */
	public static List<CipherSuite> getEcdsaCipherSuites(boolean extendedCipherSuites) {
		return getCertificateCipherSuites(CertificateKeyAlgorithm.EC.name(), extendedCipherSuites);
	}

	/**
	 * Get a list of all supported cipher suites with the provided key
	 * algorithm.
	 * 
	 * Note: currently only ECDSA is supported. There are no plans to support
	 * other key algorithm
	 * 
	 * @param keyAlgorithm name of key algorithm. e.g. "EC"
	 * @param extendedCipherSuites use also extended cipher suites
	 * @return list of all supported cipher suites with the provided key
	 *         algorithm. Ordered by their definition above.
	 */
	public static List<CipherSuite> getCertificateCipherSuites(String keyAlgorithm, boolean extendedCipherSuites) {
		List<CipherSuite> list = new ArrayList<>();
		for (CipherSuite suite : values()) {
			if (suite.isSupported()) {
				if (suite.certificateKeyAlgorithm.name().equals(keyAlgorithm)) {
					if (extendedCipherSuites || !suite.extendedCipherSuite) {
						list.add(suite);
					}
				}
			}
		}
		return list;
	}

	/**
	 * Gets a cipher suite by its numeric code.
	 * 
	 * @param code the cipher's
	 *    <a href="http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4">
	 *    IANA assigned code</a>
	 * @return the cipher suite or <code>null</code> if the code is unknown
	 */
	public static CipherSuite getTypeByCode(int code) {
		for (CipherSuite suite : values()) {
			if (suite.code == code) {
				return suite;
			}
		}
		if (LOGGER.isTraceEnabled()) {
			LOGGER.trace("Cannot resolve cipher suite code [{}]", Integer.toHexString(code));
		}
		return null;
	}

	/**
	 * Gets a cipher suite by its (official) name.
	 * 
	 * @param name the cipher's
	 *    <a href="http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4">
	 *    IANA assigned name</a>
	 * @return the cipher suite or <code>null</code> if the name is unknown
	 */
	public static CipherSuite getTypeByName(String name) {
		for (CipherSuite suite : values()) {
			if (suite.name().equals(name)) {
				return suite;
			}
		}
		if (LOGGER.isTraceEnabled()) {
			LOGGER.trace("Cannot resolve cipher suite code [{}]", name);
		}
		return null;
	}

	/**
	 * Checks if a list of cipher suite contains an ECC based cipher.
	 * 
	 * @param cipherSuites The cipher suites to check.
	 * @return {@code true} if the list contains an ECC based cipher suite,
	 *         {@code false} otherwise.
	 * 
	 */
	public static boolean containsEccBasedCipherSuite(List<CipherSuite> cipherSuites) {
		if (cipherSuites != null) {
			for (CipherSuite cipherSuite : cipherSuites) {
				if (cipherSuite.isEccBased()) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Checks if a list of cipher suite contains a cipher suite that requires
	 * the exchange of certificates.
	 * 
	 * @param cipherSuites The cipher suites to check.
	 * @return {@code true} if any of the cipher suites requires the exchange of certificates,
	 *         {@code false} otherwise.
	 * 
	 */
	public static boolean containsCipherSuiteRequiringCertExchange(List<CipherSuite> cipherSuites) {
		if (cipherSuites != null) {
			for (CipherSuite cipherSuite : cipherSuites) {
				if (cipherSuite.requiresServerCertificateMessage()) {
					return true;
				}
			}
		}
		return false;
	}

	// Serialization //////////////////////////////////////////////////

	/**
	 * Transform a list of cipher suites into the appropriate bit-format.
	 * 
	 * @param cipherSuites
	 *            the cipher suites
	 * @return the byte[]
	 */
	public static byte[] listToByteArray(List<CipherSuite> cipherSuites) {

		DatagramWriter writer = new DatagramWriter();
		for (CipherSuite cipherSuite : cipherSuites) {
			writer.write(cipherSuite.getCode(), CIPHER_SUITE_BITS);
		}

		return writer.toByteArray();
	}

	public static List<CipherSuite> listFromByteArray(byte[] byteArray, int numElements) {
		List<CipherSuite> cipherSuites = new ArrayList<CipherSuite>();
		DatagramReader reader = new DatagramReader(byteArray);

		for (int i = 0; i < numElements; i++) {
			int code = reader.read(CIPHER_SUITE_BITS);
			CipherSuite cipher = CipherSuite.getTypeByCode(code);
			// simply ignore unknown cipher suites as mandated by
			// RFC 5246, Section 7.4.1.2 Client Hello
			if (cipher != null) {
				cipherSuites.add(cipher);
			}
		}
		return cipherSuites;
	}

	// Algorithm Enums ////////////////////////////////////////////////

	/**
	 * See http://tools.ietf.org/html/rfc5246#appendix-A.6
	 */
	private enum MACAlgorithm {
		NULL(null, null, 0),
		HMAC_MD5("HmacMD5", "MD5",16),
		HMAC_SHA1("HmacSHA1", "SHA-1", 20),
		HMAC_SHA256("HmacSHA256", "SHA-256", 32),
		HMAC_SHA384("HmacSHA384", "SHA-384", 48),
		HMAC_SHA512("HmacSHA512", "SHA-512", 64);

		private final String name;
		private final String hashName;
		private final int outputLength;
		private final boolean supported;

		private MACAlgorithm(String name, String hashName, int outputLength) {
			this.name = name;
			this.hashName = hashName;
			this.outputLength = outputLength;
			if (name == null && hashName == null) {
				this.supported = true;
			} else {
				this.supported = PseudoRandomFunction.isSupported(name, hashName);
			}
		}

		/**
		 * Gets the MAC's name.
		 * 
		 * The name can be used to instantiate a <code>javax.crypto.Mac</code>
		 * instance.
		 * 
		 * See <a href="http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Mac">
		 * Java Security Documentation</a>.
		 * 
		 * @return the name or <code>null</code> for the {@link #NULL} MAC
		 */
		public String getName() {
			return name;
		}

		/**
		 * Gets the hash name.
		 * 
		 * The name can be used to instantiate a <code>java.security.MessageDigest</code>
		 * instance.
		 * 
		 * See <a href="http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#MessageDigest">
		 * Java Security Documentation</a>.
		 * 
		 * @return the name or <code>null</code> for the {@link #NULL} MAC
		 */
		public String getHashName() {
			return hashName;
		}

		/**
		 * Gets the length of the MAC output.
		 * 
		 * @return the length in bytes
		 */
		public int getOutputLength() {
			return outputLength;
		}

		/**
		 * Gets the length of the key material to use with the MAC algorithm.
		 * 
		 * This is the same as the MAC's output length for all HMAC algorithms
		 * used with TLS.
		 * 
		 * @return the length in bytes
		 */
		public int getKeyLength() {
			return outputLength;
		}

		/**
		 * checks, if MAC algorithm is supported.
		 * @return
		 */
		public boolean isSupported() {
			return supported;
		}
	}

	private enum Cipher {
		// key_length & record_iv_length as documented in RFC 5426, Appendix C
		// see http://tools.ietf.org/html/rfc5246#appendix-C
		NULL("NULL", CipherType.NULL, 0, 0, 0),
		B_3DES_EDE_CBC("DESede/CBC/NoPadding", CipherType.BLOCK, 24, 4, 8), // don't know
		AES_128_CBC("AES/CBC/NoPadding", CipherType.BLOCK, 16, 4, 16), // http://www.ietf.org/mail-archive/web/tls/current/msg08445.html
		AES_256_CBC("AES/CBC/NoPadding", CipherType.BLOCK, 32, 4, 16),
		AES_128_CCM_8(AeadBlockCipher.AES_CCM, CipherType.AEAD, 16, 4, 8, 8), // explicit nonce (record IV) length = 8
		AES_256_CCM_8(AeadBlockCipher.AES_CCM, CipherType.AEAD, 32, 4, 8, 8), // explicit nonce (record IV) length = 8
		AES_128_CCM(AeadBlockCipher.AES_CCM, CipherType.AEAD, 16, 4, 8, 16), // explicit nonce (record IV) length = 8
		AES_256_CCM(AeadBlockCipher.AES_CCM, CipherType.AEAD, 32, 4, 8, 16), // explicit nonce (record IV) length = 8
		AES_128_GCM("AES/GCM/NoPadding", CipherType.AEAD, 16, 4, 8, 16); // requires jvm implementation of AES/GCM

		/**
		 * The <em>transformation</em> string of the corresponding Java Cryptography Architecture
		 * <code>Cipher</code>
		 */
		private final String transformation;
		private final CipherType type;
		// values in octets!
		private final int keyLength;
		private final int fixedIvLength;
		private final int recordIvLength;
		private final int macLength;
		private final boolean supported;

		private Cipher(String transformation, CipherType type, int keyLength, int fixedIvLength, int recordIvLength) {
			this(transformation, type, keyLength, fixedIvLength, recordIvLength, 0);
		}

		private Cipher(String transformation, CipherType type, int keyLength, int fixedIvLength, int recordIvLength,
				int macLength) {
			this.transformation = transformation;
			this.type = type;
			this.keyLength = keyLength;
			this.fixedIvLength = fixedIvLength;
			this.recordIvLength = recordIvLength;
			this.macLength = macLength;
			if (type == CipherType.AEAD || type == CipherType.BLOCK) {
				this.supported = AeadBlockCipher.isSupported(transformation, keyLength);
			} else {
				this.supported = true;
			}
		}

		/**
		 * Gets the Java Cryptography Architecture <em>transformation</em> corresponding
		 * to the suite's underlying cipher algorithm.
		 * 
		 * The name can be used to instantiate a <code>javax.crypto.Cipher</code> object
		 * (if a security provider is available in the JVM supporting the transformation).
		 * See <a href="http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Cipher">
		 * Java Security Documentation</a>.
		 * 
		 * @return the transformation
		 */
		private String getTransformation() {
			return transformation;
		}

		private CipherType getType() {
			return type;
		}

		private int getKeyLength() {
			return keyLength;
		}

		private int getFixedIvLength() {
			return fixedIvLength;
		}

		/**
		 * Gets the length of the cipher's initialization vector.
		 * <p>
		 * For stream ciphers the length is zero, for block ciphers this is equal to
		 * the cipher's block size and for AEAD ciphers this is the length of the
		 * explicit nonce.
		 * 
		 * @return the length in bytes
		 */
		private int getRecordIvLength() {
			return recordIvLength;
		}

		private int getMacLength() {
			return macLength;
		}
	
		private boolean isSupported() {
			return supported;
		}
	}

	/**
	 * Known key exchange algorithm names.
	 *
	 */
	public enum KeyExchangeAlgorithm {
		NULL, DHE_DSS, DHE_RSA, DH_ANON, RSA, DH_DSS, DH_RSA, PSK, ECDHE_PSK, EC_DIFFIE_HELLMAN;
	}

	private enum PRFAlgorithm {
		TLS_PRF_SHA256(MACAlgorithm.HMAC_SHA256),
		TLS_PRF_SHA384(MACAlgorithm.HMAC_SHA384);

		private final MACAlgorithm mac;

		private PRFAlgorithm(MACAlgorithm mac) {
			this.mac = mac;
		}
		
		public MACAlgorithm getMacAlgorithm() {
			return mac;
		}
	}

	/**
	 * Known cipher types.
	 *
	 */
	public enum CipherType {
		NULL, STREAM, BLOCK, AEAD;
	}

	/**
	 * Known certificate key algorithm.
	 */
	public enum CertificateKeyAlgorithm {
		NONE, DSA, RSA, EC;
	}
}
