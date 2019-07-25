/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial API and implementation
 *                                      split from Record
 *******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.Record;

/**
 * A cbc block cipher.
 */
public class CbcBlockCipher {

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
		 * See http://tools.ietf.org/html/rfc5246#section-6.2.3.2 for
		 * explanation
		 */
		DatagramReader reader = new DatagramReader(ciphertext);
		byte[] iv = reader.readBytes(suite.getRecordIvLength());
		Cipher blockCipher = suite.getThreadLocalCipher();
		blockCipher.init(Cipher.DECRYPT_MODE,
				key,
				new IvParameterSpec(iv));
		byte[] plaintext = blockCipher.doFinal(reader.readBytesLeft());
		// last byte contains padding length
		int macLength = suite.getMacLength();
		int paddingLength = plaintext[plaintext.length - 1] & 0xff;
		int fragmentLength = plaintext.length
				- 1 // paddingLength byte
				- paddingLength
				- macLength;
		if (fragmentLength < 0) {
			throw new InvalidMacException();
		}
		for (int index = fragmentLength + macLength; index < plaintext.length; ++index) {
			if (plaintext[index] != (byte) paddingLength) {
				throw new InvalidMacException();
			}
		}
		byte[] content = Arrays.copyOf(plaintext, fragmentLength);
		byte[] macFromMessage = Arrays.copyOfRange(plaintext, fragmentLength, fragmentLength + macLength);

		// adjust fragment length
		int additionalIndex = additionalData.length - (Record.LENGTH_BITS / Byte.SIZE);
		additionalData[additionalIndex] = (byte) ((fragmentLength >> Byte.SIZE) & 0xff);
		additionalData[additionalIndex+1] = (byte)(fragmentLength & 0xff);
		byte[] mac = getBlockCipherMac(suite.getThreadLocalMac(), macKey, additionalData, plaintext, fragmentLength);
		if (Arrays.equals(macFromMessage, mac)) {
			return content;
		} else {
			throw new InvalidMacException(mac, macFromMessage);
		}
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
	 * @param plaintext message to encrypt
	 * @return encrypted message including initial vector
	 * @throws GeneralSecurityException if the plaintext could not be encrypted
	 */
	public static byte[] encrypt(CipherSuite suite, SecretKey key, SecretKey macKey, byte[] additionalData,
			byte[] plaintext) throws GeneralSecurityException {
		/*
		 * See http://tools.ietf.org/html/rfc5246#section-6.2.3.2 for
		 * explanation
		 */
		DatagramWriter message = new DatagramWriter();
		message.writeBytes(plaintext);

		// add MAC
		message.writeBytes(
				getBlockCipherMac(suite.getThreadLocalMac(), macKey, additionalData, plaintext, plaintext.length));

		// determine padding length
		int ciphertextLength = plaintext.length + suite.getMacLength() + 1;
		int blocksize = suite.getRecordIvLength();
		int lastBlockBytes = ciphertextLength % blocksize;
		int paddingLength = lastBlockBytes > 0 ? blocksize - lastBlockBytes : 0;

		// create padding
		byte[] padding = new byte[paddingLength + 1];
		Arrays.fill(padding, (byte) paddingLength);
		message.writeBytes(padding);
		Cipher blockCipher = suite.getThreadLocalCipher();
		blockCipher.init(Cipher.ENCRYPT_MODE, key);

		// create GenericBlockCipher structure
		DatagramWriter result = new DatagramWriter();
		result.writeBytes(blockCipher.getIV());
		result.writeBytes(blockCipher.doFinal(message.toByteArray()));
		return result.toByteArray();
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
		return hmac.doFinal();
	}
}
