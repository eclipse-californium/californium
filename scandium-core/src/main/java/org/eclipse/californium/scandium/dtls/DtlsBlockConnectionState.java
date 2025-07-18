/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.cipher.CbcBlockCipher;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.util.SecretSerializationUtil;
import org.eclipse.californium.scandium.util.SecretUtil;

/**
 * DTLS connection state for block cipher.
 */
public class DtlsBlockConnectionState extends DTLSConnectionState {

	private final SecretKey encryptionKey;
	private final SecretKey macKey;

	/**
	 * Initializes all fields with given values.
	 * 
	 * @param cipherSuite the cipher and MAC algorithm to use for encrypting
	 *            message content
	 * @param compressionMethod the algorithm to use for compressing message
	 *            content
	 * @param encryptionKey the secret key to use for encrypting message content
	 * @param macKey the key to use for creating/verifying message
	 *            authentication codes (MAC)
	 * @throws NullPointerException if any of the parameter is {@code null}
	 */
	DtlsBlockConnectionState(CipherSuite cipherSuite, CompressionMethod compressionMethod, SecretKey encryptionKey,
			SecretKey macKey) {
		super(cipherSuite, compressionMethod);
		if (encryptionKey == null) {
			throw new NullPointerException("Encryption key must not be null!");
		}
		if (macKey == null) {
			throw new NullPointerException("MAC key must not be null!");
		}
		this.encryptionKey = SecretUtil.create(encryptionKey);
		this.macKey = SecretUtil.create(macKey);
	}

	@Override
	public void destroy() throws DestroyFailedException {
		SecretUtil.destroy(encryptionKey);
		SecretUtil.destroy(macKey);
	}

	@Override
	public boolean isDestroyed() {
		return SecretUtil.isDestroyed(macKey) && SecretUtil.isDestroyed(encryptionKey);
	}

	@Override
	public byte[] encrypt(Record record, byte[] fragment) throws GeneralSecurityException {
		/*
		 * See http://tools.ietf.org/html/rfc5246#section-6.2.3.2 for
		 * explanation
		 */
		// additional data for MAC
		byte[] additionalData = record.generateAdditionalData(fragment.length);
		return CbcBlockCipher.encrypt(cipherSuite, encryptionKey, macKey, additionalData, fragment);
	}

	@Override
	public byte[] decrypt(Record record, byte[] ciphertextFragment) throws GeneralSecurityException {
		/*
		 * See http://tools.ietf.org/html/rfc5246#section-6.2.3.2 for
		 * explanation
		 */
		if (ciphertextFragment == null) {
			throw new NullPointerException("Ciphertext must not be null");
		} else if (ciphertextFragment.length % cipherSuite.getRecordIvLength() != 0) {
			throw new GeneralSecurityException("Ciphertext doesn't fit block size!");
		} else if (ciphertextFragment.length < cipherSuite.getRecordIvLength() + cipherSuite.getMacLength() + 1) {
			throw new GeneralSecurityException("Ciphertext too short!");
		}
		// additional data for MAC, use length 0
		// and overwrite it after decryption
		byte[] additionalData = record.generateAdditionalData(0);
		return CbcBlockCipher.decrypt(cipherSuite, encryptionKey, macKey, additionalData, ciphertextFragment);
	}

	/**
	 * Initialize Mac with {@link #macKey}.
	 * 
	 * @param mac Mac to initialize
	 * @throws InvalidKeyException if the {@link #macKey} is inappropriate for
	 *             initializing this MAC.
	 * @since 4.0
	 */
	void initMac(Mac mac) throws InvalidKeyException {
		mac.init(macKey);
	}

	/**
	 * Get Mac key length.
	 * 
	 * @return mac key length
	 * @since 4.0
	 */
	int getMacKeyLength() {
		byte[] encoded = macKey.getEncoded();
		Bytes.clear(encoded);
		return encoded.length;
	}

	@Override
	public final String toString() {
		StringBuilder b = new StringBuilder("DtlsBlockConnectionState:").append(StringUtil.lineSeparator());
		String indentation = StringUtil.indentation(1);
		b.append(indentation).append("Cipher suite: ").append(cipherSuite).append(StringUtil.lineSeparator());
		b.append(indentation).append("Compression method: ").append(compressionMethod)
				.append(StringUtil.lineSeparator());
		b.append(indentation).append("MAC key: ").append(macKey == null ? "null" : "not null")
				.append(StringUtil.lineSeparator());
		b.append(indentation).append("Encryption key: ").append(encryptionKey == null ? "null" : "not null")
				.append(StringUtil.lineSeparator());
		return b.toString();
	}

	@Override
	public void writeTo(DatagramWriter writer) {
		SecretSerializationUtil.write(writer, macKey);
		SecretSerializationUtil.write(writer, encryptionKey);
	}

	/**
	 * Create connection state and read specific connection state from provided
	 * reader
	 * 
	 * @param cipherSuite cipher suite
	 * @param compressionMethod compression method
	 * @param reader reader with serialized keys
	 * @since 3.0
	 */
	DtlsBlockConnectionState(CipherSuite cipherSuite, CompressionMethod compressionMethod, DatagramReader reader) {
		super(cipherSuite, compressionMethod);
		macKey = SecretSerializationUtil.readSecretKey(reader);
		encryptionKey = SecretSerializationUtil.readSecretKey(reader);
	}

}
