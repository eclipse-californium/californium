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
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.util.DatagramReader;
import org.eclipse.californium.scandium.util.DatagramWriter;

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

	private static final String KEY_ALGORITHM_NAME = "AES";
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
		StringBuffer b = new StringBuffer("DTLSConnectionState:");
		b.append(System.lineSeparator()).append("\tCipher suite: ").append(cipherSuite);
		b.append(System.lineSeparator()).append("\tCompression method: ").append(compressionMethod);
		b.append(System.lineSeparator()).append("\tIV: ").append(iv == null ? "null" : "not null");
		b.append(System.lineSeparator()).append("\tMAC key: ").append(macKey == null ? "null" : "not null");
		b.append(System.lineSeparator()).append("\tEncryption key: ").append(encryptionKey == null ? "null" : "not null");
		return b.toString();
	}

	final void serialize(DatagramWriter writer) {
		writer.write(cipherSuite.getCode(), CipherSuite.CIPHER_SUITE_BITS);
		writer.write(compressionMethod.getCode(), CompressionMethod.COMPRESSION_METHOD_BITS);
		writeSecretKey(encryptionKey, writer);
		if (cipherSuite.getFixedIvLength() > 0) {
			writer.writeBytes(iv.getIV());
		}
		if (cipherSuite.getMacKeyLength() > 0) {
			writeSecretKey(macKey, writer);
		}
	}

	static final DTLSConnectionState deserialize(DatagramReader reader) {
		CipherSuite cipher = CipherSuite.getTypeByCode(reader.read(CipherSuite.CIPHER_SUITE_BITS));
		CompressionMethod compressionMethod = CompressionMethod.getMethodByCode(reader.read(CompressionMethod.COMPRESSION_METHOD_BITS));
		SecretKey encryptionKey = readSecretKey(reader);
		IvParameterSpec iv = null;
		if (cipher.getFixedIvLength() > 0) {
			iv = new IvParameterSpec(reader.readBytes(cipher.getFixedIvLength()));
		}
		SecretKey macKey = null;
		if (cipher.getMacKeyLength() > 0) {
			macKey = readSecretKey(reader);
		}
		return new DTLSConnectionState(cipher, compressionMethod, encryptionKey, iv, macKey);
	}

	private static void writeSecretKey(SecretKey key, DatagramWriter writer) {
		byte[] encodedKey = key.getEncoded();
		writer.write(encodedKey.length, 16);
		writer.writeBytes(encodedKey);
	}

	private static SecretKey readSecretKey(DatagramReader reader) {
		int length = reader.read(16);
		return new SecretKeySpec(reader.readBytes(length), KEY_ALGORITHM_NAME);
	}
}
