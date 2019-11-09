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
 *    Bosch Software Innovations GmbH - initial API and implementation
 *                                      split from Record
 *    Achim Kraus (Bosch Software Innovations GmbH) - reduce timing side channel
 *******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.Record;

/**
 * A cbc block cipher.
 */
public class CbcBlockCipher {

	// byte used to fill-up plaintext for extra message digest compression
	private static final byte[] FILLUP = Bytes.createBytes(new SecureRandom(), 256);

	// Static methods /////////////////////////////////////////////////

	/**
	 * Converts a given TLSCiphertext.fragment to a TLSCompressed.fragment
	 * structure as defined by
	 * <a href="http://tools.ietf.org/html/rfc5246#section-6.2.3.2"> RFC 5246,
	 * section 6.2.3.2</a>:
	 * 
	 * <pre>
	 * struct {
	 *    opaque IV[SecurityParameters.record_iv_length];
	 *    block-ciphered struct {
	 *       opaque content[TLSCompressed.length];
	 *       opaque MAC[SecurityParameters.mac_length];
	 *       uint8 padding[GenericBlockCipher.padding_length];
	 *       uint8 padding_length;
	 *    };
	 * } GenericBlockCipher;
	 * </pre>
	 * 
	 * The particular cipher to use is determined from the negotiated cipher
	 * suite in the <em>current</em> DTLS connection state.
	 * 
	 * @param suite used cipher suite
	 * @param key encryption key
	 * @param macKey mac key
	 * @param additionalData additional data. Note: the TLSCompressed.length is
	 *            not available before decryption. Therefore the last two bytes
	 *            will be modified with that length after the decryption.
	 * @param ciphertext encrypted message including initial vector
	 * @return decrypted and authenticated payload.
	 * @throws InvalidMacException if message authentication failed
	 * @throws GeneralSecurityException if the ciphertext could not be decrypted
	 */
	public static byte[] decrypt(CipherSuite suite, SecretKey key, SecretKey macKey, byte[] additionalData,
			byte[] ciphertext) throws GeneralSecurityException {
		/*
		 * See http://tools.ietf.org/html/rfc5246#section-6.2.3.2 for explanation
		 */
		// extend/oversize the plaintext for MAC compensation and 256 padding checks 
		byte[] plaintextOversized = new byte[ciphertext.length + Math.max(suite.getMacMessageBlockLength(), 256)];
		int ivlength = suite.getRecordIvLength();
		Cipher blockCipher = suite.getThreadLocalCipher();
		blockCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ciphertext, 0, ivlength));
		int plaintextLength = blockCipher.doFinal(ciphertext, ivlength, ciphertext.length - ivlength,
				plaintextOversized);
		// fill up plaintext for MAC compensation
		System.arraycopy(FILLUP, 0, plaintextOversized, plaintextLength, suite.getMacMessageBlockLength());
		int macLength = suite.getMacLength();
		// last byte contains padding length
		int paddingLength = plaintextOversized[plaintextLength - 1] & 0xff;
		// -1 := padding length byte
		int fullLength = plaintextLength - macLength - 1;
		int leftLength = fullLength - paddingLength;
		int fragmentLength;
		if (leftLength < 0) {
			// padding length byte wrong
			fragmentLength = fullLength;
			paddingLength = 0;
		} else {
			fragmentLength = leftLength;
		}
		if (!checkPadding(paddingLength, plaintextOversized, fragmentLength + macLength)) {
			fragmentLength = fullLength;
			paddingLength = 0;
		}
		// adjust fragment length
		int additionalIndex = additionalData.length - (Record.LENGTH_BITS / 8);
		additionalData[additionalIndex] = (byte) ((fragmentLength >> 8) & 0xff);
		additionalData[additionalIndex+1] = (byte)(fragmentLength & 0xff);

		MessageDigest md = suite.getThreadLocalMacMessageDigest();
		md.reset();
		byte[] mac = getBlockCipherMac(suite.getThreadLocalMac(), macKey, additionalData, plaintextOversized,
				fragmentLength);

		// estimate additional MAC Hash compressions to decouple calculation
		// times from padding. The MAC Hash compressions are done in blocks,
		// appending the message length as extra data.
		int macMessageLengthBytes = suite.getMacMessageLengthBytes();
		int macMessageBlockLength = suite.getMacMessageBlockLength();
		// add all bytes passed to MAC
		int macBytes = additionalData.length + fragmentLength + macMessageLengthBytes;
		// MAC blocks for all bytes including padding
		int macBlocks1 = (macBytes + paddingLength) / macMessageBlockLength;
		// MAC blocks for all bytes without padding
		int macBlocks2 = macBytes / macMessageBlockLength;
		int blocks = (macBlocks1 - macBlocks2);
		// calculate extra compression to compensate timing differences
		// caused by different padding
		// extra byte, to ensure, that the final compression is triggered
		md.update(plaintextOversized, fragmentLength, (blocks * macMessageBlockLength) + 1);
		md.reset();
		byte[] macFromMessage = Arrays.copyOfRange(plaintextOversized, fragmentLength, fragmentLength + macLength);
		boolean ok = MessageDigest.isEqual(macFromMessage, mac);
		Bytes.clear(mac);
		Bytes.clear(macFromMessage);
		byte[] payload = null;
		if (ok) {
			payload = Arrays.copyOf(plaintextOversized, fragmentLength);
		}
		Bytes.clear(plaintextOversized);
		if (!ok) {
			throw new InvalidMacException();
		}
		return payload;
	}

	/**
	 * Converts a given TLSCompressed.fragment to a TLSCiphertext.fragment
	 * structure as defined by
	 * <a href="http://tools.ietf.org/html/rfc5246#section-6.2.3.2"> RFC 5246,
	 * section 6.2.3.2</a>
	 * 
	 * <pre>
	 * struct {
	 *    opaque IV[SecurityParameters.record_iv_length];
	 *    block-ciphered struct {
	 *       opaque content[TLSCompressed.length];
	 *       opaque MAC[SecurityParameters.mac_length];
	 *       uint8 padding[GenericBlockCipher.padding_length];
	 *       uint8 padding_length;
	 *    };
	 * } GenericBlockCipher;
	 * </pre>
	 * 
	 * The particular cipher to use is determined from the negotiated cipher
	 * suite in the <em>current</em> DTLS connection state.
	 * 
	 * @param suite used cipher suite
	 * @param key encryption key
	 * @param macKey mac key
	 * @param additionalData additional data
	 * @param payload message to encrypt
	 * @return encrypted message including initial vector
	 * @throws GeneralSecurityException if the plaintext could not be encrypted
	 */
	public static byte[] encrypt(CipherSuite suite, SecretKey key, SecretKey macKey, byte[] additionalData,
			byte[] payload) throws GeneralSecurityException {
		/*
		 * See http://tools.ietf.org/html/rfc5246#section-6.2.3.2 for
		 * explanation
		 */
		DatagramWriter plainMessage = new DatagramWriter(true);
		plainMessage.writeBytes(payload);

		// add MAC
		byte[] mac = getBlockCipherMac(suite.getThreadLocalMac(), macKey, additionalData, payload, payload.length);
		plainMessage.writeBytes(mac);
		Bytes.clear(mac);

		// determine padding length
		int ciphertextLength = payload.length + suite.getMacLength() + 1;
		int blocksize = suite.getRecordIvLength();
		int lastBlockBytes = ciphertextLength % blocksize;
		int paddingLength = lastBlockBytes > 0 ? blocksize - lastBlockBytes : 0;

		// create padding
		byte[] padding = new byte[paddingLength + 1];
		Arrays.fill(padding, (byte) paddingLength);
		plainMessage.writeBytes(padding);
		Bytes.clear(padding);

		Cipher blockCipher = suite.getThreadLocalCipher();
		blockCipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] iv = blockCipher.getIV();
		byte[] plaintext = plainMessage.toByteArray();
		plainMessage.close();

		byte[] message = Arrays.copyOf(iv,  iv.length+  plaintext.length);
		blockCipher.doFinal(plaintext, 0,  plaintext.length, message, iv.length);
		return message;
	}

	/**
	 * Calculates a MAC for use with CBC block ciphers as specified by
	 * <a href="http://tools.ietf.org/html/rfc5246#section-6.2.3.2"> RFC 5246,
	 * section 6.2.3.2</a>.
	 * 
	 * @param hmac mac function
	 * @param macKey mac key
	 * @param additionalData additional data
	 * @param content payload
	 * @param length length of payload to be used
	 * @return mac bytes
	 * @throws InvalidKeyException if the mac keys doesn't fit the mac
	 */
	public static byte[] getBlockCipherMac(Mac hmac, SecretKey macKey, byte[] additionalData, byte[] content,
			int length) throws InvalidKeyException {
		hmac.init(macKey);
		hmac.update(additionalData);
		hmac.update(content, 0, length);
		byte[] mac = hmac.doFinal();
		hmac.reset();
		return mac;
	}

	/**
	 * Check padding.
	 * 
	 * The check is implemented using a "time constant" approach by always
	 * comparing 256 bytes.
	 * 
	 * @param padding padding to be checked
	 * @param data data to be checked. Must contain at least 256 + 1 bytes from the
	 *            offset on. The value of the last byte will be changed!
	 * @param offset offset of the padding field.
	 * @return {@code true}, if padding bytes in data from the offset on
	 *         contains the value of the padding byte.
	 * @throws IllegalArgumentException if the data array doesn't contain
	 *             257 bytes after the offset.
	 */
	public static boolean checkPadding(int padding, byte[] data, int offset) {
		if (data.length < offset + 257) {
			throw new IllegalArgumentException("data must contain 257 bytes from offset on!");
		}
		byte result1 = 0;
		byte result2 = 0;
		byte pad = (byte) padding;
		for (int index = 0; index <= padding; ++index) {
			result1 |= pad ^ data[offset + index];
		}
		for (int index = padding + 1; index < 256; ++index) {
			result2 |= pad ^ data[offset + index];
		}
		// apply result2 at the "oversize" dummy data to ensure,
		// that the dummy loop is not skipped by optimization
		data[data.length - 1] ^= result2;
		return result1 == 0;
	}
}
