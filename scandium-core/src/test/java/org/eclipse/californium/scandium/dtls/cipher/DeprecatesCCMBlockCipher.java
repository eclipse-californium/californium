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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - throw GeneralSecurityException instead
 *            of HandshakeException to indicate problems with en-/decryption
 *    Achim Kraus (Bosch Software Innovations GmbH) - move previous CCMBlockCipher to
 *                                                    test mark it as deprecated
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.util.ByteArrayUtils;


/**
 * A generic authenticated encryption block cipher mode which uses the 128-bit
 * block cipher AES. See <a href="http://tools.ietf.org/html/rfc3610">RFC
 * 3610</a> for details.
 * @deprecated replaced by more efficient implementation and kept only for tests
 */
@Deprecated
public final class DeprecatesCCMBlockCipher {

	// Members ////////////////////////////////////////////////////////

	/**
	 * CCM is only defined for use with 128-bit block ciphers, such as AES
	 * (http://tools.ietf.org/html/rfc3610).
	 */
	private static final int BLOCK_SIZE = 16;

	/**
	 * The underlying block cipher.
	 */
	private static final String BLOCK_CIPHER = "AES";

	// Static methods /////////////////////////////////////////////////

	/**
	 * See <a href="http://tools.ietf.org/html/rfc3610#section-2.5">RFC 3610</a>
	 * for details.
	 * 
	 * @param key
	 *            the encryption key K.
	 * @param nonce
	 *            the nonce N.
	 * @param a
	 *            the additional authenticated data a.
	 * @param c
	 *            the encrypted and authenticated message c.
	 * @param numAuthenticationBytes
	 *            Number of octets in authentication field.
	 * @return the decrypted message
	 * 
	 * @throws GeneralSecurityException if the message could not be de-crypted, e.g.
	 *             because the ciphertext's block size is not correct
	 * @throws InvalidMacException
	 *             if the message could not be authenticated
	 */
	public static byte[] decrypt(byte[] key, byte[] nonce, byte[] a, byte[] c, int numAuthenticationBytes)
			throws GeneralSecurityException {
		byte[] T;
		byte[] m;
		byte[] mac;
		/*
		 * http://tools.ietf.org/html/draft-mcgrew-tls-aes-ccm-04#section-6.1:
		 * "AEAD_AES_128_CCM_8 ciphertext is exactly 8 octets longer than
		 * its corresponding plaintext"
		 */
		long lengthM = c.length - numAuthenticationBytes;

		// instantiate the underlying block cipher
		Cipher cipher = Cipher.getInstance(BLOCK_CIPHER);
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, BLOCK_CIPHER));

		/*
		 * Decryption starts by recomputing the key stream to recover the
		 * message m and the MAC value T.
		 */
		List<byte[]> S_i = generateKeyStreamBlocks(lengthM, nonce, cipher);
		byte[] S_0 = S_i.get(0);
		byte[] concatenatedS_i = generateConcatenatedKeyStream(S_i, lengthM);

		// extract the encrypted message (cut of authentication value)
		byte[] encryptedM = ByteArrayUtils.truncate(c, (int) lengthM);

		/*
		 * The message is decrypted by XORing the octets of message m with
		 * the first l(m) octets of the concatenation of S_1, S_2, S_3
		 */
		m = ByteArrayUtils.xorArrays(encryptedM, concatenatedS_i);

		// extract the authentication value from the cipher text
		byte[] encryptedT = new byte[numAuthenticationBytes];
		System.arraycopy(c, (int) lengthM, encryptedT, 0, numAuthenticationBytes);

		// T := U XOR first-M-bytes( S_0 )
		T = ByteArrayUtils.xorArrays(encryptedT, ByteArrayUtils.truncate(S_0, numAuthenticationBytes));

		/*
		 * The message and additional authentication data is then used to
		 * recompute the CBC-MAC value and check T.
		 */
		mac = computeCbcMac(nonce, m, a, cipher, numAuthenticationBytes);

		/*
		 * If the T value is not correct, the receiver MUST NOT reveal any
		 * information except for the fact that T is incorrect. The receiver
		 * MUST NOT reveal the decrypted message, the value T, or any other
		 * information.
		 */
		if (Arrays.equals(T, mac)) {
			return m;
		} else {
			throw new InvalidMacException(mac, T);
		}

	}

	/**
	 * See <a href="http://tools.ietf.org/html/rfc3610#section-2.2">RFC 3610</a>
	 * for details.
	 * 
	 * @param key
	 *            the encryption key K.
	 * @param nonce
	 *            the nonce N.
	 * @param a
	 *            the additional authenticated data a.
	 * @param m
	 *            the message to authenticate and encrypt.
	 * @param numAuthenticationBytes
	 *            Number of octets in authentication field.
	 * @return the encrypted and authenticated message.
	 * @throws GeneralSecurityException if the data could not be encrypted, e.g. because
	 *            the JVM does not support the AES cipher algorithm
	 */
	public static byte[] encrypt(byte[] key, byte[] nonce, byte[] a, byte[] m, int numAuthenticationBytes)
		throws GeneralSecurityException {
		long lengthM = m.length;

		// instantiate the cipher
		Cipher cipher = Cipher.getInstance(BLOCK_CIPHER);
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, BLOCK_CIPHER));

		/*
		 * First, authentication:
		 * http://tools.ietf.org/html/rfc3610#section-2.2
		 */

		// compute the authentication field T
		byte[] T = computeCbcMac(nonce, m, a, cipher, numAuthenticationBytes);

		/*
		 * Second, encryption http://tools.ietf.org/html/rfc3610#section-2.3
		 */

		List<byte[]> S_i = generateKeyStreamBlocks(lengthM, nonce, cipher);
		byte[] S_0 = S_i.get(0);
		byte[] concatenatedS_i = generateConcatenatedKeyStream(S_i, lengthM);

		/*
		 * The message is encrypted by XORing the octets of message m with
		 * the first l(m) octets of the concatenation of S_1, S_2, S_3, ...
		 * . Note that S_0 is not used to encrypt the message.
		 */
		byte[] encryptedMessage = ByteArrayUtils.xorArrays(m, concatenatedS_i);

		// U := T XOR first-M-bytes( S_0 )
		byte[] U = ByteArrayUtils.xorArrays(T, ByteArrayUtils.truncate(S_0, numAuthenticationBytes));

		/*
		 * The final result c consists of the encrypted message followed by
		 * the encrypted authentication value U.
		 */
		byte[] c = ByteArrayUtils.concatenate(encryptedMessage, U);

		return c;
	}

	// Helper methods /////////////////////////////////////////////////

	/**
	 * Computes CBC-MAC. See <a
	 * href="http://tools.ietf.org/html/rfc3610#section-2.2">RFC 3610 -
	 * Authentication</a> for details.
	 * 
	 * @param nonce
	 *            the nonce.
	 * @param m
	 *            the message to authenticate and encrypt.
	 * @param a
	 *            the additional authenticated data.
	 * @param cipher
	 *            the cipher.
	 * @param authenticationBytes
	 *            Number of octets in authentication field.
	 * @return the CBC-MAC
	 * @throws GeneralSecurityException
	 *             if cipher can not be realized.
	 */
	private static byte[] computeCbcMac(byte[] nonce, byte[] m, byte[] a, Cipher cipher, int authenticationBytes)
			throws GeneralSecurityException {
		long lengthM = m.length;
		long lengthA = a.length;
		int L = 15 - nonce.length;

		// build first block B_0

		/*
		 * Octet Number	Contents
		 * ------------	---------
		 * 0 			Flags
		 * 1 ... 15-L 	Nonce N
		 * 16-L ... 15 	l(m)
		 */
		byte[] b0 = new byte[BLOCK_SIZE];

		int adata = 0;
		// The Adata bit is set to zero if l(a)=0, and set to one if l(a)>0
		if (lengthA > 0) {
			adata = 1;
		}
		// M' field is set to (M-2)/2
		int mPrime = (authenticationBytes - 2) / 2;
		// L' = L-1 (the zero value is reserved)
		int lPrime = L - 1;

		/*
		 * Bit Number	Contents
		 * ----------	----------------------
		 * 7 			Reserved (always zero)
		 * 6 			Adata
		 * 5 ... 3 		M'
		 * 2 ... 0 		L'
		 */

		// Flags = 64*Adata + 8*M' + L'
		b0[0] = (byte) (64 * adata + 8 * mPrime + lPrime);

		// 1 ... 15-L Nonce N
		System.arraycopy(nonce, 0, b0, 1, nonce.length);

		long value = lengthM;
		b0[15] = (byte) (value);
		b0[14] = (byte) (value >>>= 8);
		if (nonce.length < 13) {
			// support message up to 16M bytes
			b0[13] = (byte) (value >>>= 8);
		}
		if ((value >>>= 8) != 0) {
			throw new IllegalArgumentException("length " + lengthM + " doesn't fit for nonce " + nonce.length);
		}

		List<byte[]> blocks = new ArrayList<byte[]>();

		// If l(a)>0 (as indicated by the Adata field), then one or more blocks
		// of authentication data are added.
		if (lengthA > 0) {

			/*
			 * First two octets		Followed by			Comment
			 * -----------------	----------------	-------------------------------
			 * 0x0000				Nothing				Reserved
			 * 0x0001 ... 0xFEFF	Nothing				For 0 < l(a) < (2^16 - 2^8)
			 * 0xFF00 ... 0xFFFD	Nothing				Reserved
			 * 0xFFFE				4 octets of l(a)	For (2^16 - 2^8) <= l(a) < 2^32
			 * 0xFFFF				8 octets of l(a)	For 2^32 <= l(a) < 2^64
			 */

			// 2^16 - 2^8
			final int first = 65280;
			// 2^32
			final long second = 4294967296L;

			/*
			 * The blocks encoding a are formed by concatenating this string
			 * that encodes l(a) with a itself, and splitting the result into
			 * 16-octet blocks, and then padding the last block with zeroes if
			 * necessary.
			 */

			DatagramWriter writer = new DatagramWriter();
			if (lengthA > 0 && lengthA < first) {
				// 2 bytes (0x0001 ... 0xFEFF)
				writer.writeLong(lengthA, 16);

			} else if (lengthA >= first && lengthA < second) {
				// 2 bytes (0xFFFE) + 4 octets of l(a)
				int field = 0xFFFE;
				writer.write(field, 16);
				writer.writeLong(lengthA, 32);

			} else {
				// 2 bytes (0xFFFF) + 8 octets of l(a)
				int field = 0xFFFF;
				writer.write(field, 16);
				writer.writeLong(lengthA, 64);
			}
			writer.writeBytes(a);

			byte[] aEncoded = writer.toByteArray();
			blocks.addAll(ByteArrayUtils.splitAndPad(aEncoded, BLOCK_SIZE));
		}
		/*
		 * After the (optional) additional authentication blocks have been
		 * added, we add the message blocks. The message blocks are formed by
		 * splitting the message m into 16-octet blocks, and then padding the
		 * last block with zeroes if necessary. If the message m consists of the
		 * empty string, then no blocks are added in this step.
		 */
		blocks.addAll(ByteArrayUtils.splitAndPad(m, BLOCK_SIZE));

		byte[] X_i;
		// X_1 := E( K, B_0 )
		X_i = ByteArrayUtils.truncate(cipher.doFinal(b0), BLOCK_SIZE);

		// X_i+1 := E( K, X_i XOR B_i ) for i=1, ..., n
		for (byte[] block : blocks) {
			byte[] xor = ByteArrayUtils.xorArrays(block, X_i);
			X_i = ByteArrayUtils.truncate(cipher.doFinal(xor), BLOCK_SIZE);
		}

		// T := first-M-bytes( X_n+1 )
		byte[] T = ByteArrayUtils.truncate(X_i, authenticationBytes);

		return T;
	}

	/**
	 * See <a href="http://tools.ietf.org/html/rfc3610#section-2.3">RFC 3610 -
	 * Key Stream Blocks</a> for details.
	 * 
	 * @param lengthM
	 *            the length of the message.
	 * @param nonce
	 *            the nonce.
	 * @param cipher
	 *            the cipher.
	 * @return the key stream blocks.
	 * @throws GeneralSecurityException
	 *             if the cipher can not be realized.
	 */
	private static List<byte[]> generateKeyStreamBlocks(long lengthM, byte[] nonce, Cipher cipher) throws GeneralSecurityException {
		int L = 15 - nonce.length;

		List<byte[]> S_i = new ArrayList<byte[]>();

		/*
		 * Compute the material needed according to the message length and add
		 * one more round to compute S_0 which is needed elsewhere.
		 */
		int numRounds = (int) (Math.ceil(lengthM / (double) BLOCK_SIZE) + 1);

		// S_i := E( K, A_i ) for i=0, 1, 2, ...
		for (int i = 0; i < numRounds; i++) {
			DatagramWriter writer = new DatagramWriter();

			/*
			 * Octet Number	Contents
			 * ------------	---------
			 * 0			Flags
			 * 1 ... 15-L	Nonce N
			 * 16-L ... 15	Counter i
			 */

			// Octet Number Contents
			// ------------ ---------
			// 0 			Flags
			// 1 ... 15-L 	Nonce N
			// 16-L ... 15 	Counter i

			int flag = L - 1;

			// write the first byte: Flags
			writer.write(flag, 8);

			// the Nonce N
			writer.writeBytes(nonce);

			// writer the Counter i (L bytes)
			writer.writeLong(i, L * 8);
			byte[] S = writer.toByteArray();

			// S_i := E( K, A_i )
			S_i.add(ByteArrayUtils.truncate(cipher.doFinal(S), BLOCK_SIZE));
		}

		return S_i;
	}

	/**
	 * Generates the concatenated key stream which is used to encrypt / decrypt
	 * the message by XORing it with this key stream. Therefore, the message
	 * length needs to be known.
	 * 
	 * @param S_i
	 *            the list of key stream blocks.
	 * @param lengthM
	 *            the length of the message m.
	 * @return the concatenated key stream which is long enough to cover the
	 *         message.
	 */
	private static byte[] generateConcatenatedKeyStream(List<byte[]> S_i, long lengthM) {
		byte[] concatenatedS_i = new byte[0];

		// determine, how much "material" needed, to cover whole message
		int numRounds = (int) (Math.ceil(lengthM / (double) BLOCK_SIZE));

		// S_0 is not used to encrypt the message, therefore start with i = 1
		for (int i = 1; i <= numRounds; i++) {
			concatenatedS_i = ByteArrayUtils.concatenate(concatenatedS_i, S_i.get(i));
		}

		return concatenatedS_i;
	}
}
