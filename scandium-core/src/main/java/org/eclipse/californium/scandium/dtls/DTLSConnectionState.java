/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - turn into an immutable, reduce visibility
 *                                                    to improve encapsulation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add toString()
 *    Kai Hudalla (Bosch Software Innovations GmbH) - improve JavaDocs, add method for retrieving
 *                                                    maximum ciphertext expansion of cipher suite
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.util.SecretIvParameterSpec;

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
public abstract class DTLSConnectionState implements Destroyable {

	public static final DTLSConnectionState NULL = new DTLSConnectionState(CipherSuite.TLS_NULL_WITH_NULL_NULL,
			CompressionMethod.NULL) {

		@Override
		public byte[] encrypt(Record record, byte[] fragment) {
			return fragment;
		}

		@Override
		public byte[] decrypt(Record record, byte[] fragment) {
			return fragment;
		}

		@Override
		public final String toString() {
			StringBuilder b = new StringBuilder("DtlsNullConnectionState:");
			b.append(StringUtil.lineSeparator()).append("\tCipher suite: ").append(cipherSuite);
			b.append(StringUtil.lineSeparator()).append("\tCompression method: ").append(compressionMethod);
			return b.toString();
		}

		@Override
		public void destroy() throws DestroyFailedException {
		}

		@Override
		public boolean isDestroyed() {
			return false;
		}

	};

	/**
	 * Create connection state and initializes all fields with given values.
	 * 
	 * @param cipherSuite the cipher and MAC algorithm to use for encrypting
	 *            message content
	 * @param compressionMethod the algorithm to use for compressing message
	 *            content
	 * @param encryptionKey the secret key to use for encrypting message content
	 * @param iv the initialization vector to use for encrypting message content
	 * @param macKey the key to use for creating/verifying message
	 *            authentication codes (MAC)
	 * @return created connection state.
	 * @throws NullPointerException if any of the parameter is {@code null}
	 */
	public static DTLSConnectionState create(CipherSuite cipherSuite, CompressionMethod compressionMethod,
			SecretKey encryptionKey, SecretIvParameterSpec iv, SecretKey macKey) {
		switch (cipherSuite.getCipherType()) {
		case NULL:
			return NULL;
		case BLOCK:
			return new DtlsBlockConnectionState(cipherSuite, compressionMethod, encryptionKey, macKey);
		case AEAD:
			return new DtlsAeadConnectionState(cipherSuite, compressionMethod, encryptionKey, iv);
		default:
			throw new IllegalArgumentException("cipher type " + cipherSuite.getCipherType() + " not supported!");
		}
	}
	// Members ////////////////////////////////////////////////////////

	protected final CipherSuite cipherSuite;
	protected final CompressionMethod compressionMethod;

	// Constructors ///////////////////////////////////////////////////

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
	 * @throws NullPointerException if any of the parameter is {@code null}
	 */
	DTLSConnectionState(CipherSuite cipherSuite, CompressionMethod compressionMethod) {
		if (cipherSuite == null) {
			throw new NullPointerException("Cipher suite must not be null");
		} else if (compressionMethod == null) {
			throw new NullPointerException("Compression method must not be null");
		}
		this.cipherSuite = cipherSuite;
		this.compressionMethod = compressionMethod;
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
	 * Encrypt fragment for provided record.
	 * 
	 * @param record record to encrypt fragment for
	 * @param fragment fragment to encrypt
	 * @return encrypted fragment
	 * @throws GeneralSecurityException if an error occured during encryption
	 */
	public abstract byte[] encrypt(Record record, byte[] fragment) throws GeneralSecurityException;

	/**
	 * Decrypt fragment for provided record.
	 * 
	 * @param record record to decrypt fragment for
	 * @param ciphertextFragment encrypted fragment
	 * @return fragment
	 * @throws GeneralSecurityException if an error occurred during decryption
	 */
	public abstract byte[] decrypt(Record record, byte[] ciphertextFragment) throws GeneralSecurityException;

	/**
	 * Gets the algorithm used for reducing the size of <em>plaintext</em> data
	 * to be exchanged with a peer by means of TLS <em>APPLICATION_DATA</em>
	 * messages.
	 * 
	 * @return the algorithm identifier
	 */
	CompressionMethod getCompressionMethod() {
		return compressionMethod;
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
	 * For block ciphers (e.g. AES) this is the same as the cipher's block size.
	 * 
	 * @return the length in bytes
	 */
	int getRecordIvLength() {
		return cipherSuite.getRecordIvLength();
	}
}
