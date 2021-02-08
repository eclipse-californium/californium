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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * A generic Authenticated Encryption with Associated Data block cipher mode.
 */
public class AeadBlockCipher {

	/**
	 * Support java prior 1.7, aes-ccm is a non-java-vm transformation and
	 * handled as special transformation.
	 * 
	 * @see CCMBlockCipher
	 */
	public static final String AES_CCM = "AES/CCM";

	/**
	 * Test, if cipher is supported.
	 * 
	 * @param transformation name of cipher
	 * @param keyLength key length in bytes
	 * @return {@code true}, if supported
	 */
	public final static boolean isSupported(String transformation, int keyLength) {
		try {
			// check, if java-vm supports transformation
			Cipher cipher;
			if (AES_CCM.equals(transformation)) {
				cipher = CCMBlockCipher.CIPHER.current();
			} else {
				cipher = Cipher.getInstance(transformation);
			}
			if (cipher != null) {
				int maxAllowedKeyLengthBits = Cipher.getMaxAllowedKeyLength(cipher.getAlgorithm());
				return keyLength * 8 <= maxAllowedKeyLengthBits;
			}
		} catch (GeneralSecurityException ex) {
		}
		return false;
	}

	/**
	 * Decrypt with AEAD cipher.
	 * 
	 * @param cipherSuite the cipher suite
	 * @param key the encryption key K.
	 * @param nonce the nonce N.
	 * @param additionalData the additional authenticated data a.
	 * @param crypted the encrypted and authenticated message c.
	 * @param cryptedOffset the offset within crypted.
	 * @param cryptedLength the length within crypted.
	 * @return the decrypted message
	 * 
	 * @throws GeneralSecurityException if the message could not be de-crypted,
	 *             e.g. because the ciphertext's block size is not correct
	 * @throws InvalidMacException if the message could not be authenticated
	 */
	public final static byte[] decrypt(CipherSuite cipherSuite, SecretKey key, byte[] nonce, byte[] additionalData, byte[] crypted, int cryptedOffset, int cryptedLength)
			throws GeneralSecurityException {
		if (AES_CCM.equals(cipherSuite.getTransformation())) {
			return CCMBlockCipher.decrypt(key, nonce, additionalData, crypted, cryptedOffset, cryptedLength, cipherSuite.getMacLength());
		} else {
			return jreDecrypt(cipherSuite, key, nonce, additionalData, crypted, cryptedOffset, cryptedLength);
		}
	}

	/**
	 * Encrypt with AEAD cipher.
	 * 
	 * @param cipherSuite the cipher suite
	 * @param key the encryption key K.
	 * @param nonce the nonce N.
	 * @param additionalData the additional authenticated data a.
	 * @param message the message to authenticate and encrypt.
	 * @return the encrypted and authenticated message.
	 * @throws GeneralSecurityException if the data could not be encrypted, e.g.
	 *             because the JVM does not support the AES cipher algorithm
	 */
	public final static byte[] encrypt(CipherSuite cipherSuite, SecretKey key, byte[] nonce,
			byte[] additionalData, byte[] message) throws GeneralSecurityException {
		if (AES_CCM.equals(cipherSuite.getTransformation())) {
			return CCMBlockCipher.encrypt(cipherSuite.getRecordIvLength(), key, nonce, additionalData, message, cipherSuite.getMacLength());
		} else {
			return jreEncrypt(cipherSuite.getRecordIvLength(), cipherSuite, key, nonce, additionalData, message);
		}
	}

	/**
	 * Decrypt with jre AEAD cipher.
	 * 
	 * @param suite the cipher suite
	 * @param key the encryption key K.
	 * @param nonce the nonce N.
	 * @param additionalData the additional authenticated data a.
	 * @param crypted the encrypted and authenticated message c.
	 * @param cryptedOffset offset within crypted
	 * @param cryptedLength length within crypted
	 * @return the decrypted message
	 * 
	 * @throws GeneralSecurityException if the message could not be de-crypted,
	 *             e.g. because the ciphertext's block size is not correct
	 * @throws InvalidMacException if the message could not be authenticated
	 */
	private final static byte[] jreDecrypt(CipherSuite suite, SecretKey key, byte[] nonce, byte[] additionalData,
			byte[] crypted, int cryptedOffset, int cryptedLength) throws GeneralSecurityException {

		Cipher cipher = suite.getThreadLocalCipher();
		GCMParameterSpec parameterSpec = new GCMParameterSpec(suite.getMacLength() * 8, nonce);
		cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
		cipher.updateAAD(additionalData);
		return cipher.doFinal(crypted, cryptedOffset, cryptedLength);
	}

	/**
	 * Encrypt with jre AEAD cipher.
	 * 
	 * @param outputOffset offset of the encrypted message within the resulting
	 *            byte array. Leaves space for the explicit nonce.
	 * @param suite the cipher suite
	 * @param key the encryption key K.
	 * @param nonce the nonce N.
	 * @param additionalData the additional authenticated data a.
	 * @param message the message to authenticate and encrypt.
	 * @return the encrypted and authenticated message.
	 * @throws GeneralSecurityException if the data could not be encrypted, e.g.
	 *             because the JVM does not support the AES cipher algorithm
	 */
	private final static byte[] jreEncrypt(int outputOffset, CipherSuite suite, SecretKey key, byte[] nonce,
			byte[] additionalData, byte[] message) throws GeneralSecurityException {
		Cipher cipher = suite.getThreadLocalCipher();
		GCMParameterSpec parameterSpec = new GCMParameterSpec(suite.getMacLength() * 8, nonce);
		cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
		cipher.updateAAD(additionalData);
		int length = cipher.getOutputSize(message.length);
		byte[] result = new byte[length + outputOffset];
		cipher.doFinal(message, 0, message.length, result, outputOffset);
		return result;
	}
}
