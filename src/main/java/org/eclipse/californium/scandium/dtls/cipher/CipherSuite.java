/*******************************************************************************
 * Copyright (c) 2014, 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.scandium.util.DatagramReader;
import org.eclipse.californium.scandium.util.DatagramWriter;


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
	
	TLS_NULL_WITH_NULL_NULL("NULL", 0x0000, KeyExchangeAlgorithm.NULL, BulkCipherAlgorithm.NULL, MACAlgorithm.NULL, PRFAlgorithm.TLS_PRF_SHA256, CipherType.NULL),
	TLS_PSK_WITH_AES_128_CBC_SHA256("AES/CBC/NoPadding", 0x00AE, KeyExchangeAlgorithm.PSK, BulkCipherAlgorithm.AES_128, MACAlgorithm.HMAC_SHA256, PRFAlgorithm.TLS_PRF_SHA256, CipherType.BLOCK),
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256("AES/CBC/NoPadding", 0xC023, KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, BulkCipherAlgorithm.AES_128, MACAlgorithm.HMAC_SHA256, PRFAlgorithm.TLS_PRF_SHA256, CipherType.BLOCK),
	TLS_PSK_WITH_AES_128_CCM_8("CCM", 0xC0A8, KeyExchangeAlgorithm.PSK, BulkCipherAlgorithm.AES_128, MACAlgorithm.NULL, PRFAlgorithm.TLS_PRF_SHA256, CipherType.AEAD),
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8("CCM", 0xC0AE, KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, BulkCipherAlgorithm.AES_128, MACAlgorithm.NULL, PRFAlgorithm.TLS_PRF_SHA256, CipherType.AEAD);
	// Logging ////////////////////////////////////////////////////////

	private static final Logger LOGGER = Logger.getLogger(CipherSuite.class.getCanonicalName());

	// DTLS-specific constants ////////////////////////////////////////

	private static final int CIPHER_SUITE_BITS = 16;

	// Members ////////////////////////////////////////////////////////

	/** The <em>transformation</em> string of the corresponding Java Cryptography Architecture
	 * <code>Cipher</code> */
	private String transformation;

	/**
	 * 16 bit identification, i.e. 0x0000 for SSL_NULL_WITH_NULL_NULL, see <a
	 * href="http://tools.ietf.org/html/rfc5246#appendix-A.5">RFC 5246</a>.
	 */
	private int code;

	private KeyExchangeAlgorithm keyExchange;
	private BulkCipherAlgorithm bulkCipher;
	private MACAlgorithm macAlgorithm;
	private PRFAlgorithm pseudoRandomFunction;
	private CipherType cipherType;

	// Constructor ////////////////////////////////////////////////////

	private CipherSuite(String transformation, int code, KeyExchangeAlgorithm keyExchange,
			BulkCipherAlgorithm bulkCipher, MACAlgorithm macAlgorithm, PRFAlgorithm prf, CipherType cipherType) {
		this.transformation = transformation;
		this.code = code;
		this.keyExchange = keyExchange;
		this.bulkCipher = bulkCipher;
		this.macAlgorithm = macAlgorithm;
		this.pseudoRandomFunction = prf;
		this.cipherType = cipherType;
	}
	
	// Getters ////////////////////////////////////////////////////////

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
		return transformation;
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
	 * Gets the cipher suite's underlying bulk cipher algorithm used
	 * to encrypt data.
	 * 
	 * @return the algorithm
	 */
	public BulkCipherAlgorithm getBulkCipher() {
		return bulkCipher;
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
	 * @return the name or <code>null</code> for the {@link MACAlgorithm#NULL} MAC
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
		return bulkCipher.getRecordIvLength();
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
		return bulkCipher.getFixedIvLength();
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
		return cipherType;
	}

	/**
	 * Gets the length of the bulk cipher algorithm's encoding key.
	 * 
	 * @return the length in bytes
	 */
	public int getEncKeyLength() {
		return bulkCipher.getKeyLength();
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
		switch (code) {
		case 0x0000:
			return CipherSuite.TLS_NULL_WITH_NULL_NULL;
		case 0x00AE:
			return CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256;
		case 0xC023:
			return CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256;
		case 0xC0A8:
			return CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		case 0xC0AE:
			return CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;

		default:
			if (LOGGER.isLoggable(Level.FINE)) {
				LOGGER.log(Level.FINE,
						"Cannot resolve cipher suite code [{0}]",
						Integer.toHexString(code));
			}
			return null;
		}
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
	
	/*
	 * See http://tools.ietf.org/html/rfc5246#appendix-A.6
	 */

	public enum MACAlgorithm {
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

	public enum BulkCipherAlgorithm {
		// key_length & record_iv_length as documented in RFC 5426, Appendic C
		// see http://tools.ietf.org/html/rfc5246#appendix-C
		NULL(0, 0, 0),
		B_3DES(24, 4, 8), // don't know
		AES_128(16, 4, 16); // http://www.ietf.org/mail-archive/web/tls/current/msg08445.html
		
		// values in octets!
		private int keyLength;
		private int fixedIvLength;
		private int recordIvLength;
		
		private BulkCipherAlgorithm(int key_length, int fixed_iv_length, int recordIvLength) {
			this.keyLength = key_length;
			this.fixedIvLength = fixed_iv_length;
			this.recordIvLength = recordIvLength;
		}

		public int getKeyLength() {
			return keyLength;
		}

		public int getFixedIvLength() {
			return fixedIvLength;
		}

		/**
		 * Gets the length of the cipher's initialization vector.
		 * 
		 * For stream ciphers the length is zero. For block ciphers this is equal to
		 * the cipher's block size.
		 * 
		 * @return the length in bytes
		 */
		public int getRecordIvLength() {
			return recordIvLength;
		}
	}

	public enum KeyExchangeAlgorithm {
		NULL, DHE_DSS, DHE_RSA, DH_ANON, RSA, DH_DSS, DH_RSA, PSK, EC_DIFFIE_HELLMAN;
	}
	
	public enum PRFAlgorithm {
		TLS_PRF_SHA256;
	}

	public enum CipherType {
		NULL, STREAM, BLOCK, AEAD;
	}

}
