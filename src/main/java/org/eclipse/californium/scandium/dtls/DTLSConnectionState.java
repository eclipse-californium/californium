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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - turn into an immutable, reduce visibility
 *                                                    to improve encapsulation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add toString()
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

/**
 * Represents the state of a DTLS connection.
 * 
 * For each DTLS connection four states are maintained:
 * <ul>
 * <li>current read state</li>
 * <li>current write state</li>
 * <li>pending read state</li>
 * <li>pending write state</li>
 * </ul>
 * 
 * A connection state specifies a compression algorithm, an encryption algorithm
 * and a MAC algorithm. All records are processed under the <em>current</em>
 * read and write states.
 * See <a href="http://tools.ietf.org/html/rfc5246#section-6.1">RFC 5246</a> for
 * details.
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
	 *            the cipher suite used
	 * @param compressionMethod
	 *            the compression used
	 * @param encryptionKey
	 *            the secret encryption key used
	 * @param iv
	 *            the initialization vector used
	 * @param macKey
	 *            the MAC key used
	 * @throws NullPointerException if either cipher suite or compression method are <code>null</code>
	 */
	DTLSConnectionState(CipherSuite cipherSuite, CompressionMethod compressionMethod, SecretKey encryptionKey, IvParameterSpec iv, SecretKey macKey) {
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
	 * Gets the length of the cipher algorithms's initialization vector.
	 * 
	 * For block ciphers (e.g. AES) this is the same as the cipher's
	 * block size.
	 * 
	 * @return the length in bytes
	 */
	int getRecordIvLength() {
		return cipherSuite.getBulkCipher().getRecordIvLength();
	}
	
	@Override
	public String toString() {
		StringBuffer b = new StringBuffer("DTLSConnectionState:");
		b.append("\n\tCipher suite: ").append(cipherSuite);
		b.append("\n\tCompression method: ").append(compressionMethod);
		b.append("\n\tIV: ").append(iv == null ? "null" : "not null");
		b.append("\n\tMAC key: ").append(macKey == null ? "null" : "not null");
		b.append("\n\tEncryption key: ").append(encryptionKey == null ? "null" : "not null");
		return b.toString();
	}
}
