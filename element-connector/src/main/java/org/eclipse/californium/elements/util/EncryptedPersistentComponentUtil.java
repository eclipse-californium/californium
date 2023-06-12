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

package org.eclipse.californium.elements.util;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.elements.PersistentComponent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Encrypted serialization and file based persistence for
 * {@link PersistentComponent}s.
 * 
 * {@link #add(org.eclipse.californium.elements.PersistentComponent)} all
 * {@link PersistentComponent} and call
 * {@link #loadAndRegisterShutdown(String, char[], long, Runnable)} before
 * starting them.
 * 
 * @since 3.4
 */
public class EncryptedPersistentComponentUtil extends PersistentComponentUtil {

	/**
	 * Default cipher.
	 * 
	 * Mandatory supported by Java 7. Know attacks, e.g. "lucky 13" are based on
	 * timing and 13 bytes "additional data" for the MAC. Both doesn't apply
	 * here.
	 * 
	 * @deprecated use {@link EncryptedStreamUtil#DEFAULT_CIPHER_ALGORITHM}
	 *             instead
	 */
	@Deprecated
	public static final String DEFAULT_CIPHER_ALGORITHM = EncryptedStreamUtil.DEFAULT_CIPHER_ALGORITHM;
	/**
	 * Default key size in bits.
	 * 
	 * @deprecated use {@link EncryptedStreamUtil#DEFAULT_KEY_SIZE_BITS} instead
	 */
	@Deprecated
	public static final int DEFAULT_KEY_SIZE_BITS = EncryptedStreamUtil.DEFAULT_KEY_SIZE_BITS;

	private static final Logger LOGGER = LoggerFactory.getLogger(EncryptedPersistentComponentUtil.class);

	private final EncryptedStreamUtil encryptionUtility = new EncryptedStreamUtil();

	/**
	 * Create encrypted serialization utility with default algorithm and key
	 * size.
	 */
	public EncryptedPersistentComponentUtil() {
	}

	/**
	 * Create encrypted serialization utility with provided cipher specification.
	 * 
	 * @param spec cipher specification (algorithm + key size). e.g.
	 *            "AES/GCM/128".
	 * @throws IllegalArgumentException if cipher and key size is not supported
	 * @since 3.9
	 */
	public EncryptedPersistentComponentUtil(String spec) {
		setWriteCipher(spec);
	}

	/**
	 * Create encrypted serialization utility with provided algorithm and key
	 * size.
	 * 
	 * @param cipherAlgorithm cipher algorithm
	 * @param keySizeBits key size in bits
	 * @throws IllegalArgumentException if cipher and key size is not supported (since 3.9)
	 */
	public EncryptedPersistentComponentUtil(String cipherAlgorithm, int keySizeBits) {
		setWriteCipher(cipherAlgorithm, keySizeBits);
	}

	/**
	 * Get write cipher specification.
	 * 
	 * @return cipher specification (algorithm + key size). e.g. "AES/GCM/128".
	 * @since 3.9
	 */
	public String getWriteCipher() {
		return encryptionUtility.getWriteCipher();
	}

	/**
	 * Get read cipher specification.
	 * 
	 * @return cipher specification (algorithm + key size). e.g. "AES/GCM/128". {@code null}, if 
	 * @since 3.9
	 */
	public String getReadCipher() {
		return encryptionUtility.getReadCipher();
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
		encryptionUtility.setCipher(cipherAlgorithm, keySizeBits);
	}

	/**
	 * Set cipher to default cipher.
	 * 
	 * @see EncryptedStreamUtil#setDefaultWriteCipher()
	 * @since 3.9
	 */
	public void setDefaultWriteCipher() {
		encryptionUtility.setDefaultWriteCipher();
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
		encryptionUtility.setWriteCipher(cipherAlgorithm, keySizeBits);
	}

	/**
	 * Set cipher specification.
	 * 
	 * @param spec cipher specification (algorithm + key size). e.g.
	 *            "AES/GCM/128".
	 * @throws IllegalArgumentException if cipher and key size is not supported
	 * @since 3.9
	 */
	public void setWriteCipher(String spec) {
		encryptionUtility.setWriteCipher(spec);
	}

	/**
	 * Prepare input stream.
	 * 
	 * @param in input stream to read data from
	 * @param password password for decryption. If {@code null}, the input
	 *            stream must not be encrypted.
	 * @return prepared input stream. If a "seed" is found at the head and
	 *         password is provided, a {@link CipherInputStream}. If that
	 *         doesn't {@link InputStream#markSupported()}, wrapped with a
	 *         {@link BufferedInputStream}. If a "seed" is found, but the
	 *         password is missing or the cipher algorithm isn't supported, a
	 *         empty input stream is returned and no items are loaded.
	 */
	public InputStream prepare(InputStream in, SecretKey password) {
		return encryptionUtility.prepare(in, password);
	}

	/**
	 * Load all persistent components from input stream.
	 * 
	 * @param in input stream to read data from
	 * @param password password for decryption. If {@code null}, the input
	 *            stream must not be encrypted.
	 * @return number of loaded items, {@code -1}, if start mark isn't found.
	 * @see #prepare(InputStream, SecretKey)
	 */
	public int loadComponents(InputStream in, SecretKey password) {
		return super.loadComponents(prepare(in, password));
	}

	/**
	 * Prepare output stream.
	 * 
	 * Writes random seed or {@link Bytes#EMPTY}, if no password is provided.
	 * 
	 * @param out output stream to write data to
	 * @param password password for encryption. If {@code null}, the output
	 *            stream is not encrypted.
	 * @return prepared output stream, {@link CipherOutputStream}, if a password
	 *         is provided.
	 * @throws IOException if an i/o-error occurred
	 */
	public OutputStream prepare(OutputStream out, SecretKey password) throws IOException {
		return encryptionUtility.prepare(out, password);
	}

	/**
	 * Save all persistent components to output stream.
	 * 
	 * Note: without password the stream may contain not encrypted critical
	 * credentials. It is required to protect this data before exporting it.
	 * 
	 * @param out output stream to write data to
	 * @param password password for encryption. If {@code null}, the output
	 *            stream is not encrypted.
	 * @param staleThresholdInSeconds stale threshold in seconds. e.g.
	 *            Connections without traffic for that time are skipped during
	 *            serialization.
	 * @throws IOException if an i/o-error occurred
	 * @see #prepare(OutputStream, SecretKey)
	 */
	public void saveComponents(OutputStream out, SecretKey password, long staleThresholdInSeconds) throws IOException {
		OutputStream serversOut = prepare(out, password);
		saveComponents(serversOut, staleThresholdInSeconds);
		if (serversOut != out) {
			// close CipherOutputStream to append padding
			serversOut.close();
		}
	}

	/**
	 * Load all added persistent components from file and register shutdown
	 * handler to store them on exit in that file.
	 * 
	 * @param file file name. The file to read the persistent data from, if
	 *            available. The file will be deleted after reading and used for
	 *            writing on shutdown.
	 * @param password64 password in base 64 encoding. If {@code null}, the
	 *            input file must not be encrypted and output file will not be
	 *            encrypted as well.
	 * @param staleThresholdInSeconds stale threshold in seconds. e.g.
	 *            Connections without traffic for that time are skipped during
	 *            serialization.
	 * @param hook called before
	 *            {@link #saveComponents(OutputStream, SecretKey, long)} on
	 *            shutdown.
	 */
	public void loadAndRegisterShutdown(String file, char[] password64, final long staleThresholdInSeconds,
			final Runnable hook) {
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
					loadComponents(in, key);
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
				if (hook != null) {
					hook.run();
				}
				store.delete();
				try {
					FileOutputStream out = new FileOutputStream(store);
					try {
						saveComponents(out, key, staleThresholdInSeconds);
					} finally {
						out.close();
					}
				} catch (IOException ex) {
					LOGGER.warn("Saving server state failed!", ex);
					store.delete();
				}
				LOGGER.info("Shutdown.");
			}
		});
	}
}
