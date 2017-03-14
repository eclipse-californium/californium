/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

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
	
	TLS_NULL_WITH_NULL_NULL(0x0000, KeyExchangeAlgorithm.NULL, Cipher.NULL, MACAlgorithm.NULL),
	TLS_PSK_WITH_AES_128_CBC_SHA256(0x00AE, KeyExchangeAlgorithm.PSK, Cipher.AES_128_CBC, MACAlgorithm.HMAC_SHA256),
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256(0xC023, KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, Cipher.AES_128_CBC, MACAlgorithm.HMAC_SHA256),
	TLS_PSK_WITH_AES_128_CCM_8(0xC0A8, KeyExchangeAlgorithm.PSK, Cipher.AES_128_CCM_8, MACAlgorithm.NULL),
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8(0xC0AE, KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, Cipher.AES_128_CCM_8, MACAlgorithm.NULL);

	// DTLS-specific constants ////////////////////////////////////////

	public static final int CIPHER_SUITE_BITS = 16;

	// Logging ////////////////////////////////////////////////////////

	private static final Logger LOGGER = Logger.getLogger(CipherSuite.class.getCanonicalName());

	// Members ////////////////////////////////////////////////////////

	/**
	 * 16 bit identification, i.e. 0x0000 for SSL_NULL_WITH_NULL_NULL, see <a
	 * href="http://tools.ietf.org/html/rfc5246#appendix-A.5">RFC 5246</a>.
	 */
	private int code;
	private KeyExchangeAlgorithm keyExchange;
	private Cipher cipher;
	private MACAlgorithm macAlgorithm;
	private PRFAlgorithm pseudoRandomFunction;
	private int maxCipherTextExpansion;

	// Constructor ////////////////////////////////////////////////////

	private CipherSuite(int code, KeyExchangeAlgorithm keyExchange, Cipher cipher, MACAlgorithm macAlgorithm) {
		this(code, keyExchange, cipher, macAlgorithm, PRFAlgorithm.TLS_PRF_SHA256);
	}

	private CipherSuite(int code, KeyExchangeAlgorithm keyExchange, Cipher cipher, MACAlgorithm macAlgorithm, PRFAlgorithm prf) {
		this.code = code;
		this.keyExchange = keyExchange;
		this.cipher = cipher;
		this.macAlgorithm = macAlgorithm;
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
					+ cipher.getCiphertextExpansion();
			break;
		default:
			maxCipherTextExpansion = 0;
		}
	}

	// Getters ////////////////////////////////////////////////////////

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
	 * @return <code>true</code> if the message is required
	 */
	public boolean requiresServerCertificateMessage() {
		return !(KeyExchangeAlgorithm.DH_ANON.equals(keyExchange) ||
				KeyExchangeAlgorithm.PSK.equals(keyExchange) ||
				KeyExchangeAlgorithm.NULL.equals(keyExchange));
	}

	/**
	 * Checks whether this cipher suite uses elliptic curve cryptography (ECC).
	 * 
	 * @return <code>true</code> if ECC is used
	 */
	public boolean isEccBased() {
		return KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN.equals(keyExchange);
	}

	/**
	 * Gets the output length of the cipher suite's MAC algorithm.
	 *  
	 * @return the length in bytes
	 */
	public int getMacLength() {
		return macAlgorithm.getOutputLength();
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
	public PRFAlgorithm getPseudoRandomFunction() {
		return pseudoRandomFunction;
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
	 * Gets a cipher suite by its numeric code.
	 * 
	 * @param code the cipher's
	 *    <a href="http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4">
	 *    IANA assigned code</a>
	 * @return the cipher suite or <code>null</code> if the code is unknown
	 */
	public static CipherSuite getTypeByCode(int code) {
		for (CipherSuite cipher : values()) {
			if (cipher.code == code) {
				return cipher;
			}
		}
		if (LOGGER.isLoggable(Level.FINEST)) {
			LOGGER.log(Level.FINEST,
					"Cannot resolve cipher suite code [{0}]",
					Integer.toHexString(code));
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
		return null;
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
		NULL(null, 0),
		HMAC_MD5("HmacMD5", 16),
		HMAC_SHA1("HmacSHA1", 20),
		HMAC_SHA256("HmacSHA256", 32),
		HMAC_SHA384("HmacSHA384", 48),
		HMAC_SHA512("HmacSHA512", 64);

		private String name;
		private int outputLength;

		private MACAlgorithm(String name, int outputLength) {
			this.name = name;
			this.outputLength = outputLength;
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
	}

	private enum Cipher {
		// key_length & record_iv_length as documented in RFC 5426, Appendic C
		// see http://tools.ietf.org/html/rfc5246#appendix-C
		NULL("NULL", CipherType.NULL, 0, 0, 0),
		B_3DES_EDE_CBC("DESede/CBC/NoPadding", CipherType.BLOCK, 24, 4, 8), // don't know
		AES_128_CBC("AES/CBC/NoPadding", CipherType.BLOCK, 16, 4, 16), // http://www.ietf.org/mail-archive/web/tls/current/msg08445.html
		AES_256_CBC("AES/CBC/NoPadding", CipherType.BLOCK, 32, 4, 16),
		AES_128_CCM_8("CCM", CipherType.AEAD, 16, 4, 8, 8); // explicit nonce (record IV) length = 8

		/**
		 * The <em>transformation</em> string of the corresponding Java Cryptography Architecture
		 * <code>Cipher</code>
		 */
		private String transformation;
		// values in octets!
		private int keyLength;
		private int fixedIvLength;
		private int recordIvLength;
		private CipherType type;
		private int ciphertextExpansion;


		private Cipher(String transformation, CipherType type, int keyLength, int fixedIvLength, int recordIvLength) {
			this.transformation = transformation;
			this.type = type;
			this.keyLength = keyLength;
			this.fixedIvLength = fixedIvLength;
			this.recordIvLength = recordIvLength;
		}

		private Cipher(String transformation, CipherType type, int keyLength, int fixedIvLength, int recordIvLength,
				int ciphertextExpansion) {
			this(transformation, type, keyLength, fixedIvLength, recordIvLength);
			this.ciphertextExpansion = ciphertextExpansion;
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

		private int getCiphertextExpansion() {
			return ciphertextExpansion;
		}
	}

	public enum KeyExchangeAlgorithm {
		NULL, DHE_DSS, DHE_RSA, DH_ANON, RSA, DH_DSS, DH_RSA, PSK, EC_DIFFIE_HELLMAN;
	}
	
	private enum PRFAlgorithm {
		TLS_PRF_SHA256;
	}

	public enum CipherType {
		NULL, STREAM, BLOCK, AEAD;
	}
}
