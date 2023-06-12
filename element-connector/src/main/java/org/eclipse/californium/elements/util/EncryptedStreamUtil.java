/*******************************************************************************
 * Copyright (c) 2022 Contributors to the Eclipse Foundation.
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
 ******************************************************************************/

package org.eclipse.californium.elements.util;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility for encrypted streams.
 * 
 * Since 3.9 the used cipher definition (algorithm + key size) is contained in
 * the encrypted stream.
 * 
 * Format:
 * 
 * <pre>
 * - 2 bytes cipher definition code
 * - 1 bytes nonce length
 * - n bytes nonce
 * - p bytes encrypted payload
 * - m bytes mac (depending on the selected cipher)
 * </pre>
 * 
 * @since 3.7
 */
public class EncryptedStreamUtil {

	/**
	 * Default cipher.
	 * 
	 * Since 3.9, the default cipher is "AES/GCM/NoPadding", if supported by the
	 * JCE, otherwise "AES/CBC/PKCS5Padding" (mandatory supported by Java 7).
	 * 
	 * @deprecated use {@link #setDefaultWriteCipher()}
	 */
	@Deprecated
	public static final String DEFAULT_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
	/**
	 * Default key size in bits.
	 */
	public static final int DEFAULT_KEY_SIZE_BITS = 128;

	private static final Logger LOGGER = LoggerFactory.getLogger(EncryptedStreamUtil.class);

	/**
	 * Hmac algorithm to generate AES key out of the password.
	 */
	private static final String HMAC_ALGORITHM = "HmacSHA256";
	/**
	 * Label to generate AES key out of the password.
	 */
	private static final byte[] EXPANSION_LABEL = "key expansion".getBytes();

	private static final int NONCE_SIZE = 16;

	/**
	 * Cipher definition
	 * 
	 * @since 3.9
	 */
	private static final class CipherDefinition {

		private final int id;
		private final String spec;
		private final String algorithm;
		private final int keySizeBits;
		private final boolean gcm;
		private final boolean supported;

		private CipherDefinition(int id, String algorithm, int keySizeBits) {
			String[] parts = algorithm.split("/");
			this.spec = parts[0] + "/" + parts[1] + "/" + keySizeBits;
			this.id = id;
			this.algorithm = algorithm;
			this.keySizeBits = keySizeBits;
			this.gcm = algorithm.contains("/GCM/");
			boolean supported = false;
			try {
				Cipher.getInstance(algorithm);
				supported = keySizeBits <= Cipher.getMaxAllowedKeyLength(algorithm);
			} catch (NoSuchAlgorithmException e) {
			} catch (NoSuchPaddingException e) {
			}
			this.supported = supported;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((algorithm == null) ? 0 : algorithm.hashCode());
			result = prime * result + id;
			result = prime * result + keySizeBits;
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			CipherDefinition other = (CipherDefinition) obj;
			if (id != other.id)
				return false;
			if (keySizeBits != other.keySizeBits)
				return false;
			if (algorithm == null) {
				if (other.algorithm != null)
					return false;
			} else if (!algorithm.equals(other.algorithm))
				return false;
			return true;
		}
	}

	/**
	 * Map of cipher definitions.
	 * 
	 * @since 3.9
	 */
	private static final Map<Integer, CipherDefinition> CIPHER_DEFINITIONS = new HashMap<>();

	/**
	 * Default cipher definition.
	 * 
	 * "AES/GCM/128", if supported by the JCE, or "AES/CBC/128", if
	 * "AES/GCM/128" is not supported.
	 * 
	 * @since 3.9
	 */
	private static final CipherDefinition DEFAULT_CIPHER_DEFINITION;

	/**
	 * Add cipher internal.
	 * 
	 * @param id persistent id
	 * @param algorithm cipher algorithm
	 * @param bits key size in bits
	 * @return {@code true}, if cipher was added, {@code false}, if cipher is
	 *         not supported
	 * @since 3.9
	 */
	private static boolean addInternal(int id, String algorithm, int bits) {
		CipherDefinition definition = new CipherDefinition(id, algorithm, bits);
		CIPHER_DEFINITIONS.put(id, new CipherDefinition(id, algorithm, bits));
		return definition.supported;
	}

	static {
		// in order to support backwards compatibility to the old format,
		// the id must not be 0x00xx, 0x10xx, nor 0xffxx
		addInternal(0x201, "AES/CBC/PKCS5Padding", 128);
		addInternal(0x202, "AES/CBC/PKCS5Padding", 256);
		addInternal(0x301, "AES/GCM/NoPadding", 128);
		addInternal(0x302, "AES/GCM/NoPadding", 256);
		addInternal(0x401, "ARIA/GCM/NoPadding", 128);
		addInternal(0x402, "ARIA/GCM/NoPadding", 256);
		CipherDefinition def = CIPHER_DEFINITIONS.get(0x301);
		if (def == null || !def.supported) {
			def = CIPHER_DEFINITIONS.get(0x201);
		}
		DEFAULT_CIPHER_DEFINITION = def;
	}

	/**
	 * Get cipher definition for provided algorithm and key size.
	 * 
	 * @param cipherAlgorithm cipher algorithm
	 * @param keySizeBits key size in bits
	 * @return cipher definition, or {@code null}, if not available.
	 * @since 3.9
	 */
	private static CipherDefinition getCipherDefinition(String cipherAlgorithm, int keySizeBits) {
		for (CipherDefinition definition : CIPHER_DEFINITIONS.values()) {
			if (definition.algorithm.equals(cipherAlgorithm) && definition.keySizeBits == keySizeBits) {
				return definition;
			}
		}
		return null;
	}

	/**
	 * Get cipher definition for provided algorithm and key size.
	 * 
	 * @param spec cipher specification (algorithm + key size)
	 * @return cipher definition, or {@code null}, if not available.
	 * @since 3.9
	 */
	private static CipherDefinition getCipherDefinition(String spec) {
		for (CipherDefinition definition : CIPHER_DEFINITIONS.values()) {
			if (definition.spec.equals(spec)) {
				return definition;
			}
		}
		return null;
	}

	/**
	 * Add cipher.
	 * 
	 * Adding ciphers is limited. Ciphers may require specific parameters and
	 * fail for that reason.
	 * 
	 * @param id persistent id. Custom id must be in range
	 *            {@code 0xf000-0xfeff}.
	 * @param algorithm cipher algorithm
	 * @param bits key size in bits
	 * @since 3.9
	 * @return {@code true}, if cipher is supported, {@code false}, if cipher is
	 *         not supported
	 * @throws IllegalArgumentException if id or algorithm and bits are already
	 *             added or the id is not in custom range.
	 * @since 3.9
	 */
	public static boolean add(int id, String algorithm, int bits) {
		CipherDefinition definitionId = CIPHER_DEFINITIONS.get(id);
		CipherDefinition definitionParam = getCipherDefinition(algorithm, bits);
		if (definitionId != null) {
			if (definitionId.equals(definitionParam)) {
				return definitionId.supported;
			} else {
				throw new IllegalArgumentException("0x" + Integer.toHexString(id) + " already in use for "
						+ definitionId.algorithm + "/" + definitionId.keySizeBits + "!");
			}
		} else if (definitionParam != null) {
			throw new IllegalArgumentException(definitionParam.algorithm + "/" + definitionParam.keySizeBits
					+ " already defined as 0x" + Integer.toHexString(id) + "!");
		}
		if (id < 0xf000 || id > 0xfeff) {
			throw new IllegalArgumentException(
					"0x" + Integer.toHexString(id) + " is not in custom range [0xf000-0xfeff]!");
		}
		return addInternal(id, algorithm, bits);
	}

	/**
	 * Cipher algorithm for writing.
	 * 
	 * @since 3.9
	 */
	private CipherDefinition writeCipherDefinition;
	/**
	 * Cipher algorithm for reading.
	 * 
	 * @since 3.9
	 */
	private CipherDefinition readCipherDefinition;

	/**
	 * Create encrypted serialization utility using the default cipher.
	 * 
	 * @see #DEFAULT_CIPHER_DEFINITION
	 */
	public EncryptedStreamUtil() {
		setDefaultWriteCipher();
	}

	/**
	 * Create encrypted serialization utility with provided cipher
	 * specification.
	 * 
	 * @param spec cipher specification (algorithm + key size). e.g.
	 *            "AES/GCM/128".
	 * @throws IllegalArgumentException if cipher specification is not supported
	 * @since 3.9
	 */
	public EncryptedStreamUtil(String spec) {
		setWriteCipher(spec);
	}

	/**
	 * Create encrypted serialization utility with provided algorithm and key
	 * size.
	 * 
	 * @param cipherAlgorithm cipher algorithm
	 * @param keySizeBits key size in bits
	 * @throws IllegalArgumentException if cipher and key size is not supported
	 *             (since 3.9).
	 */
	public EncryptedStreamUtil(String cipherAlgorithm, int keySizeBits) {
		setWriteCipher(cipherAlgorithm, keySizeBits);
	}

	/**
	 * Get write cipher specification.
	 * 
	 * @return cipher specification (algorithm + key size). e.g. "AES/GCM/128".
	 * @since 3.9
	 */
	public String getWriteCipher() {
		return writeCipherDefinition.spec;
	}

	/**
	 * Get read cipher specification.
	 * 
	 * @return cipher specification (algorithm + key size). e.g. "AES/GCM/128". {@code null}, if 
	 * @since 3.9
	 */
	public String getReadCipher() {
		return readCipherDefinition == null ? null : readCipherDefinition.spec;
	}

	/**
	 * Set algorithm and key size.
	 * 
	 * @param cipherAlgorithm cipher algorithm
	 * @param keySizeBits key size in bits
	 * @deprecated use {@link #setWriteCipher(String, int)} instead
	 */
	@Deprecated
	public void setCipher(String cipherAlgorithm, int keySizeBits) {
		try {
			setWriteCipher(cipherAlgorithm, keySizeBits);
		} catch (IllegalArgumentException ex) {

		}
	}

	/**
	 * Set cipher to default cipher.
	 * 
	 * "AES/GCM/128", if supported by the JCE, or "AES/CBC/128", if
	 * "AES/GCM/128" is not supported.
	 * 
	 * @since 3.9
	 */
	public void setDefaultWriteCipher() {
		writeCipherDefinition = DEFAULT_CIPHER_DEFINITION;
	}

	/**
	 * Set algorithm and key size.
	 * 
	 * @param cipherAlgorithm cipher algorithm
	 * @param keySizeBits key size in bits
	 * @throws IllegalArgumentException if cipher and key size is not supported
	 * @since 3.9
	 */
	public void setWriteCipher(String cipherAlgorithm, int keySizeBits) {
		CipherDefinition definition = getCipherDefinition(cipherAlgorithm, keySizeBits);
		if (definition == null || !definition.supported) {
			throw new IllegalArgumentException(cipherAlgorithm + "/" + keySizeBits + " is not supported!");
		}
		this.writeCipherDefinition = definition;
	}

	/**
	 * Set algorithm and key size.
	 * 
	 * @param spec cipher specification (algorithm + key size). e.g.
	 *            "AES/GCM/128".
	 * @throws IllegalArgumentException if cipher and key size is not supported
	 * @since 3.9
	 */
	public void setWriteCipher(String spec) {
		CipherDefinition definition = getCipherDefinition(spec);
		if (definition == null || !definition.supported) {
			throw new IllegalArgumentException(spec + " is not supported!");
		}
		this.writeCipherDefinition = definition;
	}

	/**
	 * Initialize cipher.
	 * 
	 * @param mode mode for
	 *            {@link Cipher#init(int, java.security.Key, AlgorithmParameterSpec)}.
	 *            {@link Cipher#DECRYPT_MODE} or {@link Cipher#ENCRYPT_MODE}
	 * @param password password
	 * @param seed seed. Either randomly generated when saving, or read from
	 *            persistence, when loading.
	 * @return initialized cipher
	 */
	private Cipher init(int mode, SecretKey password, byte[] seed) {
		CipherDefinition defintion = null;

		if (mode == Cipher.ENCRYPT_MODE) {
			defintion = writeCipherDefinition;
		} else if (mode == Cipher.DECRYPT_MODE) {
			if (readCipherDefinition == null) {
				throw new IllegalArgumentException("Read cipher definition not available!");
			}
			defintion = readCipherDefinition;
		}
		if (defintion == null) {
			throw new IllegalArgumentException("Invalid mode!");
		}

		try {
			Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
			hmac.init(password);
			int ivSize = NONCE_SIZE;
			int keySizeBytes = (defintion.keySizeBits + Byte.SIZE - 1) / Byte.SIZE;
			byte[] data = doExpansion(hmac, EXPANSION_LABEL, seed, keySizeBytes + ivSize);
			SecretKey key = new SecretKeySpec(data, 0, keySizeBytes, "AES");
			AlgorithmParameterSpec parameterSpec;
			if (defintion.gcm) {
				parameterSpec = new GCMParameterSpec(128, data, keySizeBytes, ivSize);
			} else {
				parameterSpec = new IvParameterSpec(data, keySizeBytes, ivSize);
			}
			Bytes.clear(data);
			Cipher cipher = Cipher.getInstance(defintion.algorithm);
			cipher.init(mode, key, parameterSpec);
			return cipher;
		} catch (GeneralSecurityException ex) {
			LOGGER.warn("encryption error:", ex);
			return null;
		}
	}

	/**
	 * Read seed from input stream.
	 * 
	 * Since 3.9 reads also cipher definition.
	 * 
	 * @param in input stream
	 * @return read seed, or {@code null}, if missing.
	 * @see #prepare(byte[], InputStream, SecretKey)
	 * @since 3.8
	 */
	public byte[] readSeed(InputStream in) {
		DataStreamReader reader = new DataStreamReader(in);
		int b = reader.read(Byte.SIZE);
		if (b == 0) {
			// no encryption
			return Bytes.EMPTY;
		} else if (b == NONCE_SIZE) {
			// deprecated format, default encryption
			readCipherDefinition = getCipherDefinition("AES/CBC/128");
			return reader.readBytes(b);
		}
		int b2 = reader.read(Byte.SIZE);
		int id = b << 8 | b2;
		CipherDefinition definition = CIPHER_DEFINITIONS.get(id);
		if (definition == null) {
			LOGGER.warn("Cipher {} is not available!", Integer.toHexString(id));
			// return empty nonce to fail
			return Bytes.EMPTY;
		} else if (!definition.supported) {
			LOGGER.warn("Cipher {}/{} is not supported!", Integer.toHexString(id), definition.spec);
			// return empty nonce to fail
			return Bytes.EMPTY;
		}
		readCipherDefinition = definition;
		return reader.readVarBytes(Byte.SIZE);
	}

	/**
	 * Prepare input stream.
	 * 
	 * @param in input stream to read data from
	 * @param password password for decryption. If {@code null}, the input
	 *            stream must be not encrypted, but starts with an empty seed
	 *            (byte 0).
	 * @return prepared input stream. If a "seed" is found at the head and
	 *         password is provided, a {@link CipherInputStream}. If that
	 *         doesn't {@link InputStream#markSupported()}, wrapped with a
	 *         {@link BufferedInputStream}. If a "seed" is found, but the
	 *         password is missing or the cipher algorithm isn't supported, a
	 *         empty input stream is returned and no items are loaded.
	 */
	public InputStream prepare(InputStream in, SecretKey password) {
		return prepare(readSeed(in), in, password);
	}

	/**
	 * Prepare input stream.
	 * 
	 * Provided seed must be read using {@link #readSeed(InputStream)} before.
	 * 
	 * @param seed seed to decrypt data. If {@code null}, don't decrypt.
	 * @param in input stream to read data from
	 * @param password password for decryption. If {@code null}, the input
	 *            stream must be not encrypted, and the seed must be [@link
	 *            null} or empty.
	 * @return prepared input stream. If a seed is provided and password is
	 *         provided, a {@link CipherInputStream}. If that doesn't
	 *         {@link InputStream#markSupported()}, wrapped with a
	 *         {@link BufferedInputStream}. If a seed is provided, but the
	 *         password is missing or the cipher algorithm isn't supported, a
	 *         empty input stream is returned and no items are loaded.
	 * @see #readSeed(InputStream)
	 * @since 3.8
	 */
	public InputStream prepare(byte[] seed, InputStream in, SecretKey password) {
		if (seed != null && seed.length > 0) {
			if (password == null) {
				LOGGER.warn("missing password!");
				return new ByteArrayInputStream(Bytes.EMPTY);
			}
			Cipher cipher = init(Cipher.DECRYPT_MODE, password, seed);
			if (cipher == null) {
				LOGGER.warn("crypto error!");
				return new ByteArrayInputStream(Bytes.EMPTY);
			}
			in = new CipherInputStream(in, cipher);
			if (!in.markSupported()) {
				in = new BufferedInputStream(in);
			}
		}
		return in;
	}

	/**
	 * Prepare output stream.
	 * 
	 * Writes random seed, if password is provided, or {@link Bytes#EMPTY}, if
	 * no password is provided.
	 * 
	 * @param out output stream to write data to
	 * @param password password for encryption. If {@code null}, the output
	 *            stream is not encrypted, but starts with an empty seed (byte
	 *            0).
	 * @return prepared output stream, {@link CipherOutputStream}, if a password
	 *         is provided.
	 * @throws IOException if an i/o-error occurred or no new random seed could
	 *             be generated.
	 */
	public OutputStream prepare(OutputStream out, SecretKey password) throws IOException {
		return prepare(null, out, password);
	}

	/**
	 * Prepare output stream.
	 * 
	 * Writes random seed, if password is provided, or {@link Bytes#EMPTY}, if
	 * no password is provided.
	 * 
	 * @param seed seed the current/last written/read data is using. Ensure, a
	 *            new seed is used to write. {@code null}, if not available.
	 * @param out output stream to write data to
	 * @param password password for encryption. If {@code null}, the output
	 *            stream is not encrypted, but starts with an empty seed (byte
	 *            0).
	 * @return prepared output stream, {@link CipherOutputStream}, if a password
	 *         is provided.
	 * @throws IOException if an i/o-error occurred or no new random seed could
	 *             be generated.
	 * @since 3.8
	 */
	public OutputStream prepare(byte[] seed, OutputStream out, SecretKey password) throws IOException {
		DatagramWriter writer = new DatagramWriter();
		if (password != null) {
			byte[] newSeed = new byte[seed == null ? NONCE_SIZE : seed.length];
			SecureRandom random = new SecureRandom();
			int count = 0;
			random.nextBytes(newSeed);
			while (seed != null && Arrays.equals(seed, newSeed)) {
				++count;
				if (count > 5) {
					throw new IOException("Random seed failed!");
				}
				random.nextBytes(newSeed);
			}
			if (seed != null) {
				System.arraycopy(newSeed, 0, seed, 0, seed.length);
			}
			Cipher cipher = init(Cipher.ENCRYPT_MODE, password, newSeed);
			if (cipher != null) {
				writer.write(writeCipherDefinition.id, Short.SIZE);
				writer.writeVarBytes(newSeed, Byte.SIZE);
				writer.writeTo(out);
				out = new CipherOutputStream(out, cipher);
			} else {
				LOGGER.warn("crypto error!");
				password = null;
			}
		}
		if (password == null) {
			writer.writeVarBytes(Bytes.EMPTY, Byte.SIZE);
			writer.writeTo(out);
		}
		return out;
	}

	/**
	 * Performs the secret expansion as described in
	 * <a href="https://tools.ietf.org/html/rfc5246#section-5" target=
	 * "_blank">RFC 5246</a>.
	 * 
	 * Note: This function is copied from Scandium / PseudoRandomFunction,
	 * otherwise this would either create a dependency or a critical crypto
	 * function must be moved outside Scandium.
	 * 
	 * @param hmac the cryptographic hash function to use for expansion.
	 * @param label the label to use for creating the original data
	 * @param seed the seed to use for creating the original data
	 * @param length the number of bytes to expand the data to.
	 * @return the expanded data.
	 */
	private static final byte[] doExpansion(Mac hmac, byte[] label, byte[] seed, int length) {
		/*
		 * RFC 5246, chapter 5, page 15
		 * 
		 * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
		 * HMAC_hash(secret, A(2) + seed) + HMAC_hash(secret, A(3) + seed) + ...
		 * where + indicates concatenation.
		 * 
		 * A() is defined as: A(0) = seed, A(i) = HMAC_hash(secret, A(i-1))
		 */

		int offset = 0;
		final int macLength = hmac.getMacLength();
		final byte[] aAndSeed = new byte[macLength + label.length + seed.length];
		final byte[] expansion = new byte[length];
		try {
			// copy appended seed to buffer end
			System.arraycopy(label, 0, aAndSeed, macLength, label.length);
			System.arraycopy(seed, 0, aAndSeed, macLength + label.length, seed.length);
			// calculate A(n) from A(0)
			hmac.update(label);
			hmac.update(seed);
			while (true) {
				// write result to "A(n) + seed"
				hmac.doFinal(aAndSeed, 0);
				// calculate HMAC_hash from "A(n) + seed"
				hmac.update(aAndSeed);
				final int nextOffset = offset + macLength;
				if (nextOffset > length) {
					// too large for expansion!
					// write HMAC_hash result temporary to "A(n) + seed"
					hmac.doFinal(aAndSeed, 0);
					// write head of result from temporary "A(n) + seed" to
					// expansion
					System.arraycopy(aAndSeed, 0, expansion, offset, length - offset);
					break;
				} else {
					// write HMAC_hash result to expansion
					hmac.doFinal(expansion, offset);
					if (nextOffset == length) {
						break;
					}
				}
				offset = nextOffset;
				// calculate A(n+1) from "A(n) + seed" head ("A(n)")
				hmac.update(aAndSeed, 0, macLength);
			}
		} catch (ShortBufferException e) {
			e.printStackTrace();
		}
		Bytes.clear(aAndSeed);
		return expansion;
	}

}
