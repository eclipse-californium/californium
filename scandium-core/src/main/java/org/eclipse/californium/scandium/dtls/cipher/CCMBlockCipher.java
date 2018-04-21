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
 *    Achim Kraus (Bosch Software Innovations GmbH) - redesigned implementation
 *                                                    to improve performance
 *    Achim Kraus (Bosch Software Innovations GmbH) - use NoPadding for android support
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.scandium.util.ByteArrayUtils;

/**
 * A generic authenticated encryption block cipher mode which uses the 128-bit
 * block cipher AES. See <a href="http://tools.ietf.org/html/rfc3610">RFC
 * 3610</a> for details.
 */
public class CCMBlockCipher {

	// Members ////////////////////////////////////////////////////////

	/**
	 * CCM is only defined for use with 128-bit block ciphers, such as AES
	 * (http://tools.ietf.org/html/rfc3610).
	 */

	/**
	 * The underlying block cipher.
	 */
	private static final String CIPHER_NAME = "AES/ECB/NoPadding";
	/**
	 * Key type for cipher.
	 */
	private static final String KEY_TYPE = "AES";

	private static abstract class Block {

		protected final int blockSize;
		protected final byte[] block;

		protected Block(int blockSize) {
			this.blockSize = blockSize;
			this.block = new byte[blockSize];
		}

		/**
		 * Set integer at the end of the block.
		 * 
		 * Lowest byte at the end.
		 * 
		 * <pre>
		 * block[end] = number & 0xff;
		 * block[end - 1] = (number >>= 8) & 0xff;
		 * block[end - 2] = (number >>= 8) & 0xff;
		 * block[offset] = (number >>= 8) & 0xff;
		 * </pre>
		 * 
		 * Return remaining bytes in number.
		 * 
		 * <pre>
		 * blockSize = 16;
		 * number = 0x20103
		 * left = updateBlock(14, number); // write number to two bytes
		 * left == 2 // highest third byte 0x2 will be left
		 * </pre>
		 * 
		 * @param offset offset at which the number will be written, right
		 *            padded with 0
		 * @param number number to write
		 * @return left bytes of the number, if number is too large, 0, if the
		 *         complete number could be set.
		 */
		protected int setIntAtEnd(int offset, int number) {
			int backOffset = blockSize;
			while (backOffset > offset) {
				block[--backOffset] = (byte) number;
				number >>>= 8;
			}
			return number;
		}

	}

	private static class BlockCipher extends Block {

		private final Cipher cipher;
		private final byte[] xblock;
		private final int nonceL;

		private BlockCipher(Cipher cipher, byte[] nonce) {
			super(cipher == null ? 0 : cipher.getBlockSize());
			this.cipher = cipher;
			this.nonceL = nonce.length;
			int L = blockSize - 1 - nonceL;
			if (L < 2 || L > 8) {
				throw new IllegalArgumentException("Nonce length " + nonceL + " invalid for blocksize " + blockSize
						+ " (valid length [" + (blockSize - 9) + "-" + (blockSize - 3) + "])");
			}

			xblock = new byte[blockSize];
			// Octet Number Contents
			// ------------ ---------
			// 0 Flags
			// 1 ... 15-L Nonce N
			// 16-L ... 15 Counter i

			// write the first byte: Flags
			block[0] = (byte) (L - 1);
			// the Nonce N
			System.arraycopy(nonce, 0, block, 1, nonceL);
		}

		private byte[] updateBlock(int index) throws ShortBufferException {
			// writer the Counter i (L bytes)
			if (setIntAtEnd(nonceL + 1, index) != 0) {
				throw new IllegalArgumentException("Index " + index + " too large for nonce " + nonceL
						+ " and blocksize " + blockSize + " bytes.");
			}

			cipher.update(block, 0, blockSize, xblock);
			return xblock;
		}
	}

	private static class MacCipher extends Block {

		private final Cipher cipher;
		private final byte[] mac;

		/**
		 * Computes CBC-MAC. See
		 * <a href="http://tools.ietf.org/html/rfc3610#section-2.2">RFC 3610 -
		 * Authentication</a> for details.
		 * 
		 * @param cipher the cipher.
		 * @param nonce the nonce.
		 * @param a the additional authenticated data.
		 * @param m the message to authenticate and encrypt.
		 * @param numAuthenticationBytes Number of octets in authentication
		 *            field.
		 * @throws ShortBufferException if cipher can not be realized.
		 */
		private MacCipher(Cipher cipher, byte[] nonce, byte[] a, byte[] m, int numAuthenticationBytes)
				throws ShortBufferException {
			super(cipher == null ? 0 : cipher.getBlockSize());
			this.cipher = cipher;
			int lengthM = m.length;
			int lengthA = a.length;
			int nonceL = nonce.length;
			int L = blockSize - 1 - nonceL;

			if (L < 2 || L > 8) {
				throw new IllegalArgumentException("Nonce length " + nonceL + " invalid for blocksize " + blockSize
						+ " (valid length [" + (blockSize - 9) + "-" + (blockSize - 3) + "])");
			}

			// build first block B_0

			// Octet Number Contents
			// ------------ ---------
			// 0 Flags
			// 1 ... 15-L Nonce N
			// 16-L ... 15 l(m)

			int adata = 0;
			// The Adata bit is set to zero if l(a)=0, and set to one if l(a)>0
			if (lengthA > 0) {
				adata = 1;
			}
			// M' field is set to (M-2)/2
			int mPrime = (numAuthenticationBytes - 2) / 2;
			// L' = L-1 (the zero value is reserved)
			int lPrime = L - 1;

			// Bit Number Contents
			// ---------- ----------------------
			// 7 Reserved (always zero)
			// 6 Adata
			// 5 ... 3 M'
			// 2 ... 0 L'

			// Flags = 64*Adata + 8*M' + L'
			block[0] = (byte) (64 * adata + 8 * mPrime + lPrime);

			// 1 ... 15-L Nonce N
			System.arraycopy(nonce, 0, block, 1, nonceL);

			// writer the length (L bytes)
			if (setIntAtEnd(nonceL + 1, lengthM) != 0) {
				throw new IllegalArgumentException("Length " + lengthM + " too large for nonce " + nonceL
						+ " and blocksize " + blockSize + " bytes.");
			}

			cipher.update(block, 0, blockSize, block);

			// If l(a)>0 (as indicated by the Adata field), then one or more
			// blocks
			// of authentication data are added.
			if (lengthA > 0) {

				// First two octets Followed by Comment
				// ----------------- ----------------
				// -------------------------------
				// 0x0000 Nothing Reserved
				// 0x0001 ... 0xFEFF Nothing For 0 < l(a) < (2^16 - 2^8)
				// 0xFF00 ... 0xFFFD Nothing Reserved
				// 0xFFFE 4 octets of l(a) For (2^16 - 2^8) <= l(a) < 2^32
				// 0xFFFF 8 octets of l(a) For 2^32 <= l(a) < 2^64

				// 2^16 - 2^8
				final int first = 65280;

				final int offset;
				/*
				 * The blocks encoding a are formed by concatenating this string
				 * that encodes l(a) with a itself, and splitting the result
				 * into 16-octet blocks, and then padding the last block with
				 * zeroes if necessary.
				 */
				if (lengthA > 0 && lengthA < first) {
					// 2 bytes (0x0001 ... 0xFEFF)
					xorInt(0, 2, lengthA);
					offset = 2;
				} else {
					// 2 bytes (0xFFFE) + 4 octets of l(a)
					xorInt(0, 2, 0xfffe);
					xorInt(2, 6, lengthA);
					offset = 6;
				}

				update(a, offset);
			}
			update(m, 0);
			mac = ByteArrayUtils.truncate(block, numAuthenticationBytes);
		}

		private void update(byte[] data, int initialBlockOffset) throws ShortBufferException {
			int length = data.length;
			for (int i = 0; i < length;) {
				int blockEnd = i + blockSize - initialBlockOffset;
				if (blockEnd > length) {
					blockEnd = length;
				}
				for (int j = initialBlockOffset; i < blockEnd; ++i, ++j) {
					block[j] ^= data[i];
				}
				initialBlockOffset = 0;
				cipher.update(block, 0, blockSize, block);
			}
		}

		private byte[] getMac() {
			return mac;
		}

		protected int xorInt(int offset, int end, int number) {
			while (end > offset) {
				block[--end] ^= (byte) number;
				number >>>= 8;
			}
			return number;
		}

	}
	// Static methods /////////////////////////////////////////////////

	/**
	 * See <a href="http://tools.ietf.org/html/rfc3610#section-2.5">RFC 3610</a>
	 * for details.
	 * 
	 * @param key the encryption key K.
	 * @param nonce the nonce N.
	 * @param a the additional authenticated data a.
	 * @param c the encrypted and authenticated message c.
	 * @param numAuthenticationBytes Number of octets in authentication field.
	 * @return the decrypted message
	 * 
	 * @throws GeneralSecurityException if the message could not be de-crypted,
	 *             e.g. because the ciphertext's block size is not correct
	 * @throws InvalidMacException if the message could not be authenticated
	 */
	public final static byte[] decrypt(byte[] key, byte[] nonce, byte[] a, byte[] c, int numAuthenticationBytes)
			throws GeneralSecurityException {
		/*
		 * http://tools.ietf.org/html/draft-mcgrew-tls-aes-ccm-04#section-6.1:
		 * "AEAD_AES_128_CCM_8 ciphertext is exactly 8 octets longer than its
		 * corresponding plaintext"
		 */

		// instantiate the underlying block cipher
		Cipher cipher = CipherManager.getInstance(CIPHER_NAME);
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, KEY_TYPE));

		int lengthM = c.length - numAuthenticationBytes;
		int blockSize = cipher.getBlockSize();

		// decrypted data without MAC
		byte[] decrypted = new byte[lengthM];
		// separate MAC
		byte[] T = new byte[numAuthenticationBytes];

		BlockCipher blockCiper = new BlockCipher(cipher, nonce);
		// block 0 for MAC
		int blockNo = 0;
		byte[] block = blockCiper.updateBlock(blockNo++);
		for (int i = 0; i < numAuthenticationBytes; ++i) {
			T[i] = (byte) (c[lengthM + i] ^ block[i]);
		}

		for (int i = 0; i < lengthM;) {
			block = blockCiper.updateBlock(blockNo++);
			int blockEnd = i + blockSize;
			if (blockEnd > lengthM) {
				blockEnd = lengthM;
			}
			for (int j = 0; i < blockEnd; ++i, ++j) {
				decrypted[i] = (byte) (c[i] ^ block[j]);
			}
		}

		/*
		 * The message and additional authentication data is then used to
		 * recompute the CBC-MAC value and check T.
		 */
		MacCipher macCipher = new MacCipher(cipher, nonce, a, decrypted, numAuthenticationBytes);
		byte[] mac = macCipher.getMac();

		/*
		 * If the T value is not correct, the receiver MUST NOT reveal any
		 * information except for the fact that T is incorrect. The receiver
		 * MUST NOT reveal the decrypted message, the value T, or any other
		 * information.
		 */
		if (Arrays.equals(T, mac)) {
			return decrypted;
		} else {
			throw new InvalidMacException(mac, T);
		}

	}

	/**
	 * See <a href="http://tools.ietf.org/html/rfc3610#section-2.2">RFC 3610</a>
	 * for details.
	 * 
	 * @param key the encryption key K.
	 * @param nonce the nonce N.
	 * @param a the additional authenticated data a.
	 * @param m the message to authenticate and encrypt.
	 * @param numAuthenticationBytes Number of octets in authentication field.
	 * @return the encrypted and authenticated message.
	 * @throws GeneralSecurityException if the data could not be encrypted, e.g.
	 *             because the JVM does not support the AES cipher algorithm
	 */
	public final static byte[] encrypt(byte[] key, byte[] nonce, byte[] a, byte[] m, int numAuthenticationBytes)
			throws GeneralSecurityException {

		// instantiate the cipher
		Cipher cipher = CipherManager.getInstance(CIPHER_NAME);
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, KEY_TYPE));
		int blockSize = cipher.getBlockSize();
		int lengthM = m.length;

		/*
		 * First, authentication: http://tools.ietf.org/html/rfc3610#section-2.2
		 */
		// compute the authentication field T
		MacCipher macCipher = new MacCipher(cipher, nonce, a, m, numAuthenticationBytes);
		byte[] mac = macCipher.getMac();

		/*
		 * Second, encryption http://tools.ietf.org/html/rfc3610#section-2.3
		 */
		// encrypted data with MAC
		byte[] encrypted = new byte[lengthM + numAuthenticationBytes];
		BlockCipher blockCiper = new BlockCipher(cipher, nonce);
		// block 0 for MAC
		int blockNo = 0;
		byte[] block = blockCiper.updateBlock(blockNo++);
		for (int i = 0; i < numAuthenticationBytes; ++i) {
			encrypted[i + lengthM] = (byte) (mac[i] ^ block[i]);
		}
		for (int i = 0; i < lengthM;) {
			block = blockCiper.updateBlock(blockNo++);
			int blockEnd = i + blockSize;
			if (blockEnd > lengthM) {
				blockEnd = lengthM;
			}
			for (int j = 0; i < blockEnd; ++i, ++j) {
				encrypted[i] = (byte) (m[i] ^ block[j]);
			}
		}

		return encrypted;
	}
}
