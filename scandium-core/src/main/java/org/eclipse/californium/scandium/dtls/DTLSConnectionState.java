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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - turn into an immutable, reduce visibility
 *                                                    to improve encapsulation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add toString()
 *    Kai Hudalla (Bosch Software Innovations GmbH) - improve JavaDocs, add method for retrieving
 *                                                    maximum ciphertext expansion of cipher suite
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

/**
 * A set of algorithms and corresponding security parameters that together
 * represent the <em>current read</em> or <em>write state</em> of a TLS connection.
 * <p>
 * According to the <a href="http://tools.ietf.org/html/rfc5246#section-6.1">TLS 1.2</a>
 * specification, a connection state <em>specifies a compression algorithm, an encryption
 * algorithm, and a MAC algorithm.  In addition, the parameters for these algorithms are
 * known: the MAC key and the bulk encryption keys for the connection in both the read and
 * the write directions.</em>
 * <p>
 * This class is immutable and thus only appropriate to reflect a <em>current</em> read or
 * write state whose properties have been negotiated/established already.
 */
class DTLSConnectionState {

	// Members ////////////////////////////////////////////////////////

	private CipherSuite cipherSuite;
	private CompressionMethod compressionMethod;
	private SecretKey encryptionKey;
	private IvParameterSpec iv;
	private SecretKey macKey;

	// Constructors ///////////////////////////////////////////////////

	/**
	 * Convenience constructor for creating an instance representing
	 * the initial connection state.
	 * 
	 * Simply invokes 
	 * {@link #DTLSConnectionState(CipherSuite, CompressionMethod, SecretKey, IvParameterSpec, SecretKey)}
	 * with the default {@link CipherSuite#TLS_NULL_WITH_NULL_NULL} and default
	 * {@link CompressionMethod#NULL} and <code>null</code> for all other parameters.
	 */
	DTLSConnectionState() {
		this(CipherSuite.TLS_NULL_WITH_NULL_NULL, CompressionMethod.NULL, null, null, null);
	}

	/**
	 * Initializes all fields with given values.
	 * 
	 * @param cipherSuite
	 *            the cipher and MAC algorithm to use for encrypting message content
	 * @param compressionMethod
	 *            the algorithm to use for compressing message content
	 * @param encryptionKey
	 *            the secret key to use for encrypting message content
	 * @param iv
	 *            the initialization vector to use for encrypting message content
	 * @param macKey
	 *            the key to use for creating/verifying message authentication codes (MAC)
	 * @throws NullPointerException if any of cipher suite or compression method is <code>null</code>
	 */
	DTLSConnectionState(CipherSuite cipherSuite, CompressionMethod compressionMethod, SecretKey encryptionKey,
			IvParameterSpec iv, SecretKey macKey) {
		if (cipherSuite == null) {
			throw new NullPointerException("Cipher suite must not be null");
		} else if (compressionMethod == null) {
			throw new NullPointerException("Compression method must not be null");
		}
		this.cipherSuite = cipherSuite;
		this.compressionMethod = compressionMethod;
		this.encryptionKey = encryptionKey;
		this.iv = iv;
		this.macKey = macKey;
	}

	// Getters ////////////////////////////////////////////

	CipherSuite getCipherSuite() {
		return cipherSuite;
	}

	/**
	 * Checks whether the cipher suite is not the <em>NULL_CIPHER</em>.
	 * 
	 * @return {@code true} if the suite is not {@link CipherSuite#TLS_NULL_WITH_NULL_NULL}.
	 */
	public boolean hasValidCipherSuite() {
		return !CipherSuite.TLS_NULL_WITH_NULL_NULL.equals(cipherSuite);
	}

	/**
	 * Gets the algorithm used for reducing the size of <em>plaintext</em> data to
	 * be exchanged with a peer by means of TLS <em>APPLICATION_DATA</em> messages.
	 * 
	 * @return the algorithm identifier
	 */
	CompressionMethod getCompressionMethod() {
		return compressionMethod;
	}

	/**
	 * Gets the cipher algorithm key.
	 * 
	 * @return the key
	 */
	SecretKey getEncryptionKey() {
		return encryptionKey;
	}

	/**
	 * Gets the fixed initialization vector for use with AEAD based cipher suites.
	 * 
	 * @return the initialization vector
	 */
	IvParameterSpec getIv() {
		return iv;
	}

	SecretKey getMacKey() {
		return macKey;
	}

	/**
	 * Gets the output length of the MAC algorithm.
	 *  
	 * @return the length in bytes
	 */
	int getMacLength() {
		return cipherSuite.getMacLength();
	}

	/**
	 * Gets the key length of the MAC algorithm.
	 *  
	 * @return the length in bytes
	 */
	int getMacKeyLength() {
		return cipherSuite.getMacKeyLength();
	}

	/**
	 * Gets the length of the cipher algorithm's initialization vector.
	 * 
	 * For block ciphers (e.g. AES) this is the same as the cipher's
	 * block size.
	 * 
	 * @return the length in bytes
	 */
	int getRecordIvLength() {
		return cipherSuite.getRecordIvLength();
	}

	/**
	 * Gets the maximum number of bytes a <em>DTLSPlaintext.fragment</em> gets expanded
	 * by when transforming it to a <em>DTLSCiphertext.fragment</em> using the cipher
	 * algorithm held in this session's <em>current write state</em>.
	 * <p>
	 * The amount of expansion introduced depends on multiple factors like the bulk cipher
	 * algorithm's block size, the MAC length and other parameters determined by the cipher
	 * suite.
	 * <p>
	 * Clients can use this information to determine an upper boundary for the required
	 * size of a datagram to hold the overall <em>DTLSCiphertext</em> structure created for
	 * a given <em>DTLSPlaintext</em> structure like this:
	 * <p>
	 * <pre>
	 *    size(DTLSCiphertext) <= DTLSPlaintext.length // length of the DTLSPlaintext.fragment
	 *                               + ciphertext_expansion
	 *                               + 13 // record headers
	 *                               + 12 // message headers
	 *                               + 8 // UDP headers
	 *                               + 20 // IP headers
	 * </pre>
	 * 
	 * @return the number of bytes
	 */
	final int getMaxCiphertextExpansion() {
		return cipherSuite.getMaxCiphertextExpansion();
	}

	@Override
	public final String toString() {
		StringBuilder b = new StringBuilder("DTLSConnectionState:");
		b.append(System.lineSeparator()).append("\tCipher suite: ").append(cipherSuite);
		b.append(System.lineSeparator()).append("\tCompression method: ").append(compressionMethod);
		b.append(System.lineSeparator()).append("\tIV: ").append(iv == null ? "null" : "not null");
		b.append(System.lineSeparator()).append("\tMAC key: ").append(macKey == null ? "null" : "not null");
		b.append(System.lineSeparator()).append("\tEncryption key: ").append(encryptionKey == null ? "null" : "not null");
		return b.toString();
	}
}
