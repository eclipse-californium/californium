/*******************************************************************************
 * Copyright (c) 2022 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/

package org.eclipse.californium.core.server;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DataStreamReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Encrypted serialization and file based persistence for {@link CoapServer}s.
 * 
 * {@link #add(CoapServer)} all {@link CoapServer} and call
 * {@link #loadAndRegisterShutdown(String, char[], long)} before starting them.
 * 
 * @since 3.3
 */
public class EncryptedServersSerializationUtil extends ServersSerializationUtil {

	/**
	 * Default cipher.
	 * 
	 * Mandatory supported by Java 7. Know attacks, e.g. "lucky 13" are based in
	 * time and 13 bytes "additional data" for the MAC. Both doesn't apply here.
	 */
	public static final String DEFAULT_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
	/**
	 * Default key size in bits.
	 */
	public static final int DEFAULT_KEY_SIZE_BITS = 128;

	private static final Logger LOGGER = LoggerFactory.getLogger(EncryptedServersSerializationUtil.class);

	/**
	 * Hmac algorithm to generate AES key out of the password.
	 */
	private static final String HMAC_ALGORITHM = "HmacSHA256";
	/**
	 * Label to generate AES key out of the password.
	 */
	private static final byte[] EXPANSION_LABEL = "key expansion".getBytes();

	/**
	 * Cipher algorithm.
	 */
	private String cipherAlgorithm;
	/**
	 * Key size in bits.
	 */
	private int keySizeBits;

	/**
	 * Create encrypted serialization utility with
	 * {@link #DEFAULT_CIPHER_ALGORITHM} and {@link #DEFAULT_KEY_SIZE_BITS}.
	 */
	public EncryptedServersSerializationUtil() {
		this(DEFAULT_CIPHER_ALGORITHM, DEFAULT_KEY_SIZE_BITS);
	}

	/**
	 * Create encrypted serialization utility with provided algorithm and key
	 * size.
	 * 
	 * @param cipherAlgorithm cipher algorithm
	 * @param keySizeBits key size in bits
	 */
	public EncryptedServersSerializationUtil(String cipherAlgorithm, int keySizeBits) {
		setCipher(cipherAlgorithm, keySizeBits);
	}

	/**
	 * Set algorithm and key size.
	 * 
	 * @param cipherAlgorithm cipher algorithm
	 * @param keySizeBits key size in bits
	 */
	public void setCipher(String cipherAlgorithm, int keySizeBits) {
		this.cipherAlgorithm = cipherAlgorithm;
		this.keySizeBits = keySizeBits;
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
		try {
			Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
			hmac.init(password);
			int ivSize = 16;
			int keySizeBytes = (keySizeBits + Byte.SIZE - 1) / Byte.SIZE;
			byte[] data = doExpansion(hmac, EXPANSION_LABEL, seed, keySizeBytes + ivSize);
			SecretKey key = new SecretKeySpec(data, 0, keySizeBytes, "AES");
			AlgorithmParameterSpec parameterSpec = new IvParameterSpec(data, keySizeBytes, ivSize);
			Bytes.clear(data);
			Cipher cipher = Cipher.getInstance(cipherAlgorithm);
			cipher.init(mode, key, parameterSpec);
			return cipher;
		} catch (GeneralSecurityException ex) {
			LOGGER.warn("encryption error:", ex);
			return null;
		}
	}

	/**
	 * Load all added servers from input stream.
	 * 
	 * The coap-servers must not be {@link CoapServer#start()}ed before loading.
	 * 
	 * @param in input stream to read data from
	 * @param password password for decryption. If {@code null}, the input
	 *            stream must not be encrypted.
	 */
	public void loadServers(InputStream in, SecretKey password) {
		DataStreamReader reader = new DataStreamReader(in);
		byte[] seed = reader.readVarBytes(Byte.SIZE);
		if (seed != null && seed.length > 0) {
			if (password == null) {
				LOGGER.warn("missing password!");
				return;
			}
			Cipher cipher = init(Cipher.DECRYPT_MODE, password, seed);
			if (cipher == null) {
				LOGGER.warn("crypto error!");
				return;
			}
			in = new CipherInputStream(in, cipher);
		}
		super.loadServers(in);
	}

	/**
	 * Save all added servers to output stream.
	 * 
	 * The coap-servers are {@link CoapServer#stop()}ed before saving.
	 * 
	 * Note: without password the stream will contain not encrypted critical
	 * credentials. It is required to protect this data before exporting it.
	 * 
	 * @param out output stream to write data to
	 * @param password password for encryption. If {@code null}, the output
	 *            stream is not encrypted.
	 * @param maxQuietPeriodInSeconds maximum quiet period of the connections in
	 *            seconds. Connections without traffic for that time are skipped
	 *            during serialization.
	 * @throws IOException if an i/o-error occurred
	 */
	public void saveServers(OutputStream out, SecretKey password, long maxQuietPeriodInSeconds) throws IOException {
		OutputStream serversOut = out;
		DatagramWriter writer = new DatagramWriter();
		if (password != null) {
			byte[] seed = new byte[16];
			new SecureRandom().nextBytes(seed);
			Cipher cipher = init(Cipher.ENCRYPT_MODE, password, seed);
			if (cipher != null) {
				writer.writeVarBytes(seed, Byte.SIZE);
				writer.writeTo(out);
				serversOut = new CipherOutputStream(out, cipher);
			} else {
				LOGGER.warn("crypto error!");
				password = null;
			}
		}
		if (password == null) {
			writer.writeVarBytes(Bytes.EMPTY, Byte.SIZE);
			writer.writeTo(out);
		}
		saveServers(serversOut, maxQuietPeriodInSeconds);
		if (serversOut != out) {
			// close CipherOutputStream to append padding
			serversOut.close();
		}
	}

	/**
	 * Load all added servers from file and register shutdown handler to store
	 * them on exit in that file.
	 * 
	 * @param file file name. The file to read the persistent data from, if
	 *            available. The file will be deleted after reading and used for
	 *            writing on shutdown.
	 * @param password64 password in base 64 encoding. If {@code null}, the
	 *            input file must not be encrypted and output file will not be
	 *            encrypted as well.
	 * @param maxQuietPeriodInSeconds maximum quiet period of the connections in
	 *            seconds. Connections without traffic for that time are skipped
	 *            during serialization.
	 */
	public void loadAndRegisterShutdown(String file, char[] password64, final long maxQuietPeriodInSeconds) {
		SecretKey tempKey = null;
		if (password64 != null) {
			byte[] secret = StringUtil.base64ToByteArray(password64);
			tempKey = new SecretKeySpec(secret, "PW");
			Bytes.clear(secret);
		}
		final SecretKey key = tempKey;
		final File store = new File(file);
		if (store.exists()) {
			try {
				FileInputStream in = new FileInputStream(store);
				try {
					loadServers(in, key);
				} finally {
					in.close();
				}
				LOGGER.info("Server state read.");
				store.delete();
			} catch (IOException ex) {
				LOGGER.warn("Reading server state failed!", ex);
			} catch (IllegalArgumentException ex) {
				LOGGER.warn("Reading server state failed!", ex);
			}
		}

		Runtime.getRuntime().addShutdownHook(new Thread("SHUTDOWN") {

			@Override
			public void run() {
				LOGGER.info("Shutdown ...");
				if (store != null) {
					store.delete();
					try {
						FileOutputStream out = new FileOutputStream(store);
						try {
							saveServers(out, key, maxQuietPeriodInSeconds);
						} finally {
							out.close();
						}
					} catch (IOException ex) {
						LOGGER.warn("Saving server state failed!", ex);
						store.delete();
					}
				}
				LOGGER.info("Shutdown.");
			}
		});
	}

	/**
	 * Performs the secret expansion as described in
	 * <a href="https://tools.ietf.org/html/rfc5246#section-5" target=
	 * "_blank">RFC 5246</a>.
	 * 
	 * Note: This function is copied from Scandium / PseudoRandomFunction,
	 * otherwise this would either create a dependency or a important crypto
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
