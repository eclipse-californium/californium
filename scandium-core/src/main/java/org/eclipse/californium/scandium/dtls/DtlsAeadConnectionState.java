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
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.cipher.AeadBlockCipher;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.util.SecretIvParameterSpec;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * DTLS connection state for AEAD cipher.
 */
public class DtlsAeadConnectionState extends DTLSConnectionState {

	private static final Logger LOGGER = LoggerFactory.getLogger(DtlsAeadConnectionState.class);

	private final SecretKey encryptionKey;
	private final SecretIvParameterSpec iv;

	/**
	 * Initializes all fields with given values.
	 * 
	 * @param cipherSuite the cipher and MAC algorithm to use for encrypting
	 *            message content
	 * @param compressionMethod the algorithm to use for compressing message
	 *            content
	 * @param encryptionKey the secret key to use for encrypting message content
	 * @param iv the initialization vector to use for encrypting message content
	 *            authentication codes (MAC)
	 * @throws NullPointerException if any of the parameter is {@code null}
	 */
	DtlsAeadConnectionState(CipherSuite cipherSuite, CompressionMethod compressionMethod, SecretKey encryptionKey,
			SecretIvParameterSpec iv) {
		super(cipherSuite, compressionMethod);
		if (encryptionKey == null) {
			throw new NullPointerException("Encryption key must not be null!");
		}
		if (iv == null) {
			throw new NullPointerException("IV must not be null!");
		}
		this.encryptionKey = SecretUtil.create(encryptionKey);
		this.iv = SecretUtil.createIv(iv);
	}

	@Override
	public void destroy() throws DestroyFailedException {
		SecretUtil.destroy(encryptionKey);
		SecretUtil.destroy(iv);
	}

	@Override
	public boolean isDestroyed() {
		return SecretUtil.isDestroyed(iv) && SecretUtil.isDestroyed(encryptionKey);
	}

	@Override
	public byte[] encrypt(Record record, byte[] fragment) throws GeneralSecurityException {
		/*
		 * See http://tools.ietf.org/html/rfc5246#section-6.2.3.3 for
		 * explanation of additional data or
		 * http://tools.ietf.org/html/rfc5116#section-2.1
		 */
		/*
		 * http://tools.ietf.org/html/draft-mcgrew-tls-aes-ccm-ecc-03#section-2:
		 * 
		 * <pre> 
		 * struct { 
		 * case client: uint32 client_write_IV; // low order 32-bits 
		 * case server: uint32 server_write_IV; // low order 32-bits
		 * uint64 seq_num; 
		 * } CCMNonce. 
		 * </pre>
		 * 
		 * @param iv the write IV (either client or server).
		 * 
		 * @return the 12 bytes nonce.
		 */
		byte[] explicitNonce = record.generateExplicitNonce();
		byte[] nonce = iv.getIV(explicitNonce);
		byte[] additionalData = record.generateAdditionalData(fragment.length);

		if (LOGGER.isTraceEnabled()) {
			LOGGER.trace("encrypt: {} bytes", fragment.length);
			LOGGER.trace("nonce: {}", StringUtil.byteArray2HexString(nonce));
			LOGGER.trace("adata: {}", StringUtil.byteArray2HexString(additionalData));
		}
		byte[] encryptedFragment = AeadBlockCipher.encrypt(explicitNonce.length, cipherSuite, encryptionKey, nonce,
				additionalData, fragment);
		Bytes.clear(nonce);

		/*
		 * Prepend the explicit nonce as specified in
		 * http://tools.ietf.org/html/rfc5246#section-6.2.3.3 and
		 * http://tools.ietf.org/html/draft-mcgrew-tls-aes-ccm-04#section-3
		 */
		System.arraycopy(explicitNonce, 0, encryptedFragment, 0, explicitNonce.length);
		LOGGER.trace("==> {} bytes", encryptedFragment.length);

		return encryptedFragment;
	}

	@Override
	public byte[] decrypt(Record record, byte[] ciphertextFragment) throws GeneralSecurityException {
		if (ciphertextFragment == null) {
			throw new NullPointerException("Ciphertext must not be null");
		} else if (ciphertextFragment.length < getRecordIvLength() + getMacLength()) {
			throw new GeneralSecurityException("Ciphertext too short!");
		}
		/*
		 * See http://tools.ietf.org/html/rfc5246#section-6.2.3.3 and
		 * http://tools.ietf.org/html/rfc5116#section-2.1 for an explanation of
		 * "additional data" and its structure
		 * 
		 * The decrypted message is always 16/24 bytes shorter than the cipher
		 * (8/16 for the authentication tag and 8 for the explicit nonce).
		 */
		int applicationDataLength = ciphertextFragment.length - cipherSuite.getRecordIvLength()
				- cipherSuite.getMacLength();
		byte[] additionalData = record.generateAdditionalData(applicationDataLength);

		// retrieve actual explicit nonce as contained in GenericAEADCipher
		// struct (8 bytes long)
		byte[] nonce = iv.getIV(ciphertextFragment, 0, cipherSuite.getRecordIvLength());

		if (LOGGER.isTraceEnabled()) {
			LOGGER.trace("decrypt: {} bytes", applicationDataLength);
			LOGGER.trace("nonce: {}", StringUtil.byteArray2HexString(nonce));
			LOGGER.trace("adata: {}", StringUtil.byteArray2HexString(additionalData));
		}
		if (LOGGER.isDebugEnabled() && AeadBlockCipher.AES_CCM.equals(cipherSuite.getTransformation())) {
			// create explicit nonce from values provided in DTLS record
			byte[] explicitNonceUsed = Arrays.copyOf(ciphertextFragment, cipherSuite.getRecordIvLength());
			// retrieve actual explicit nonce as contained in GenericAEADCipher
			// struct (8 bytes long)
			byte[] explicitNonce = record.generateExplicitNonce();
			if (!Arrays.equals(explicitNonce, explicitNonceUsed)) {
				StringBuilder b = new StringBuilder(
						"The explicit nonce used by the sender does not match the values provided in the DTLS record");
				b.append(StringUtil.lineSeparator()).append("Used    : ")
						.append(StringUtil.byteArray2HexString(explicitNonceUsed));
				b.append(StringUtil.lineSeparator()).append("Expected: ")
						.append(StringUtil.byteArray2HexString(explicitNonce));
				LOGGER.debug(b.toString());
			}
		}
		byte[] payload = AeadBlockCipher.decrypt(cipherSuite, encryptionKey, nonce, additionalData, ciphertextFragment,
				cipherSuite.getRecordIvLength(), ciphertextFragment.length - cipherSuite.getRecordIvLength());
		Bytes.clear(nonce);
		return payload;
	}

	@Override
	public final String toString() {
		StringBuilder b = new StringBuilder("DtlsAeadConnectionState:");
		b.append(StringUtil.lineSeparator()).append("\tCipher suite: ").append(cipherSuite);
		b.append(StringUtil.lineSeparator()).append("\tCompression method: ").append(compressionMethod);
		b.append(StringUtil.lineSeparator()).append("\tIV: ").append(iv == null ? "null" : "not null");
		b.append(StringUtil.lineSeparator()).append("\tEncryption key: ")
				.append(encryptionKey == null ? "null" : "not null");
		return b.toString();
	}

}
