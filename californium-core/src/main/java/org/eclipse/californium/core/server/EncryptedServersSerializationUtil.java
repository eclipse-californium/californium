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

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.EncryptedPersistentComponentUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Encrypted serialization and file based persistence for {@link CoapServer}s.
 * 
 * {@link #add(CoapServer)} all {@link CoapServer} and call
 * {@link #loadAndRegisterShutdown(String, char[], long)} before starting them.
 * 
 * @deprecated after migration of old persistence format, use
 *             {@link EncryptedPersistentComponentUtil} instead
 * @since 3.3
 */
@Deprecated
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

	private EncryptedPersistentComponentUtil encryptedPersistentUtil = new EncryptedPersistentComponentUtil();

	/**
	 * Create encrypted serialization utility with
	 * {@link #DEFAULT_CIPHER_ALGORITHM} and {@link #DEFAULT_KEY_SIZE_BITS}.
	 */
	public EncryptedServersSerializationUtil() {
		this(DEFAULT_CIPHER_ALGORITHM, DEFAULT_KEY_SIZE_BITS, false);
	}

	/**
	 * Create encrypted serialization utility with provided algorithm and key
	 * size.
	 * 
	 * @param cipherAlgorithm cipher algorithm
	 * @param keySizeBits key size in bits
	 */
	public EncryptedServersSerializationUtil(String cipherAlgorithm, int keySizeBits) {
		this(cipherAlgorithm, keySizeBits, false);
	}

	/**
	 * Create servers serialization utility.
	 * 
	 * @param useDeprecatedSerialization {@code true}, save using the deprecated
	 *            format. Used for test only.
	 * @since 3.4
	 */
	public EncryptedServersSerializationUtil(boolean useDeprecatedSerialization) {
		this(DEFAULT_CIPHER_ALGORITHM, DEFAULT_KEY_SIZE_BITS, useDeprecatedSerialization);
	}

	/**
	 * Create encrypted serialization utility with provided algorithm and key
	 * size.
	 * 
	 * @param cipherAlgorithm cipher algorithm
	 * @param keySizeBits key size in bits
	 * @param useDeprecatedSerialization {@code true}, save using the deprecated
	 *            format. Used for test only.
	 * @since 3.4
	 */
	public EncryptedServersSerializationUtil(String cipherAlgorithm, int keySizeBits,
			boolean useDeprecatedSerialization) {
		super(useDeprecatedSerialization);
		setCipher(cipherAlgorithm, keySizeBits);
		persistentUtil = encryptedPersistentUtil;
	}

	/**
	 * Set algorithm and key size.
	 * 
	 * @param cipherAlgorithm cipher algorithm
	 * @param keySizeBits key size in bits
	 */
	public void setCipher(String cipherAlgorithm, int keySizeBits) {
		encryptedPersistentUtil.setCipher(cipherAlgorithm, keySizeBits);
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
		in = encryptedPersistentUtil.prepare(in, password);
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
		OutputStream serversOut = encryptedPersistentUtil.prepare(out, password);
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
				LOGGER.info("Shutdown.");
			}
		});
	}

}
