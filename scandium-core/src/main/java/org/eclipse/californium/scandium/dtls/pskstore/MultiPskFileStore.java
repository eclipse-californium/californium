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
package org.eclipse.californium.scandium.dtls.pskstore;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.EncryptedStreamUtil;
import org.eclipse.californium.elements.util.StandardCharsets;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.elements.util.SystemResourceMonitors.SystemResourceCheckReady;
import org.eclipse.californium.elements.util.SystemResourceMonitors.SystemResourceMonitor;
import org.eclipse.californium.elements.util.SystemResourceMonitors.FileMonitor;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * File based {@link AdvancedPskStore} implementation supporting multiple peers.
 * 
 * Lines in format:
 * 
 * <pre>
 * identity = secret - key(base64)
 * </pre>
 * 
 * or
 * 
 * <pre>
 * identity = ":0x" secret-key (hex)
 * </pre>
 * 
 * Example:
 * 
 * <pre>
 * Client_identity=c2VjcmV0UFNL
 * imei351358811124772=:0x736573616D65
 * </pre>
 * 
 * <pre>
 * Base 64 "c2VjcmV0UFNL" := "secretPSK"
 * Hex "736573616D65" := "sesame"
 * </pre>
 * 
 * @since 3.7
 */
public class MultiPskFileStore implements AdvancedPskStore, Destroyable {

	private static final Logger LOGGER = LoggerFactory.getLogger(MultiPskFileStore.class);

	/**
	 * PSK credentials.
	 */
	private static class Credentials implements Destroyable {

		private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

		/**
		 * List of identities.
		 */
		private final List<PskPublicInformation> identities = new ArrayList<>();
		/**
		 * Map of identities and keys.
		 */
		private final Map<PskPublicInformation, SecretKey> keys = new HashMap<>();

		/**
		 * {@code true} if credentials are destroyed.
		 */
		private volatile boolean destroyed;

		/**
		 * Add entry.
		 * 
		 * New entries are appended to the index. Updated entries do not change
		 * their index position.
		 * 
		 * @param id PSK identity
		 * @param key PSK secret
		 */
		private void add(PskPublicInformation id, SecretKey key) {
			lock.writeLock().lock();
			try {
				if (keys.put(id, key) == null) {
					identities.add(id);
				}
			} finally {
				lock.writeLock().unlock();
			}
		}

		/**
		 * Remove entry.
		 * 
		 * @param id PSK identity
		 */
		private void remove(PskPublicInformation id) {
			lock.writeLock().lock();
			try {
				SecretKey key = keys.remove(id);
				if (key != null) {
					SecretUtil.destroy(key);
					identities.remove(id);
				}
			} finally {
				lock.writeLock().unlock();
			}
		}

		/**
		 * Remove entry by index.
		 * 
		 * The index is based on the order of
		 * {@link #add(PskPublicInformation, SecretKey)} new entries.
		 * 
		 * @param index index of entry.
		 * @throws IndexOutOfBoundsException if index is out of bounds
		 */
		private void remove(int index) {
			lock.writeLock().lock();
			try {
				PskPublicInformation id = identities.remove(index);
				if (id != null) {
					SecretKey key = keys.remove(id);
					if (key != null) {
						SecretUtil.destroy(key);
					}
				}
			} finally {
				lock.writeLock().unlock();
			}
		}

		/**
		 * Get PSK secret by PSK identity.
		 * 
		 * @param id PSK identity
		 * @return PSK secret, {@code null}, if not available.
		 */
		private SecretKey getSecret(PskPublicInformation id) {
			SecretKey key = null;
			lock.readLock().lock();
			try {
				key = keys.get(id);
			} finally {
				lock.readLock().unlock();
			}
			return SecretUtil.create(key);
		}

		/**
		 * Get PSK secret by index.
		 * 
		 * The index is based on the order of
		 * {@link #add(PskPublicInformation, SecretKey)} new entries.
		 * 
		 * @param index index of entry.
		 * @return PSK secret
		 * @throws IndexOutOfBoundsException if index is out of bounds
		 */
		private SecretKey getSecret(int index) {
			lock.readLock().lock();
			try {
				PskPublicInformation info = identities.get(index);
				if (info != null) {
					return getSecret(info);
				}
				return null;
			} finally {
				lock.readLock().unlock();
			}
		}

		/**
		 * Get identity by index.
		 * 
		 * The index is based on the order of
		 * {@link #add(PskPublicInformation, SecretKey)} new entries.
		 * 
		 * @param index index of identity
		 * @return identity as string
		 * @throws IndexOutOfBoundsException if index is out of bounds
		 */
		private String getIdentity(int index) {
			PskPublicInformation info = null;
			lock.readLock().lock();
			try {
				info = identities.get(index);
			} finally {
				lock.readLock().unlock();
			}
			if (info != null) {
				return info.getPublicInfoAsString();
			}
			return null;
		}

		/**
		 * Number of entries.
		 * 
		 * @return number of entries
		 */
		private int size() {
			lock.readLock().lock();
			try {
				return identities.size();
			} finally {
				lock.readLock().unlock();
			}
		}

		/**
		 * Lines in format:
		 * 
		 * <pre>
		 * identity = secret - key(base64)
		 * </pre>
		 * 
		 * @param writer writer to save PSK credentials
		 * @throws IOException if an I/O error occurred
		 */
		private void savePskCredentials(Writer writer) throws IOException {
			for (PskPublicInformation identity : identities) {
				SecretKey secretKey = keys.get(identity);
				if (secretKey != null) {
					byte[] key = secretKey.getEncoded();
					char[] base64 = StringUtil.byteArrayToBase64CharArray(key);
					Bytes.clear(key);
					writer.write(identity.getPublicInfoAsString());
					writer.write('=');
					writer.write(base64);
					writer.write(StringUtil.lineSeparator());
					Arrays.fill(base64, '.');
				}
			}
		}

		/**
		 * Load PSK credentials store.
		 * 
		 * Lines in format:
		 * 
		 * <pre>
		 * identity = secret - key(base64)
		 * </pre>
		 * 
		 * or
		 * 
		 * <pre>
		 * identity = ":0x" secret-key (hex)
		 * </pre>
		 * 
		 * The identity must not contain a {@code =}!
		 * 
		 * The psk credentials store keeps the order of the credentials in the
		 * file. Index {@code 0} will contain the credential of the first line.
		 * 
		 * @param reader reader for credentials store.
		 * @throws IOException if an I/O error occurred
		 */
		private void loadPskCredentials(Reader reader) throws IOException {
			BufferedReader lineReader = new BufferedReader(reader);
			try {
				int lineNumber = 0;
				int errors = 0;
				int comments = 0;
				String line;
				// readLine() reads the secret into a String,
				// what may be considered to be a weak practice.
				while ((line = lineReader.readLine()) != null) {
					++lineNumber;
					try {
						if (!line.isEmpty() && !line.startsWith("#")) {
							String[] entry = line.split("=", 2);
							if (entry.length == 2) {
								byte[] secretBytes;
								if (entry[1].startsWith(":0x")) {
									secretBytes = StringUtil.hex2ByteArray(entry[1].substring(3));
								} else {
									secretBytes = StringUtil.base64ToByteArray(entry[1]);
								}
								if (secretBytes.length == 0) {
									LOGGER.warn("{}: '{}' invalid base64 secret in psk-line!", lineNumber, line);
									++errors;
									continue;
								}
								SecretKey key = SecretUtil.create(secretBytes, "PSK");
								Bytes.clear(secretBytes);
								PskPublicInformation id = new PskPublicInformation(entry[0]);
								add(id, key);
							} else {
								++errors;
								LOGGER.warn("{}: '{}' invalid psk-line entries!", lineNumber, line);
							}
						} else {
							++comments;
						}
					} catch (IllegalArgumentException ex) {
						++errors;
						LOGGER.warn("{}: '{}' invalid psk-line!", lineNumber, line, ex);
					}
				}
				if (size() == 0 && errors > 0 && lineNumber == comments + errors) {
					LOGGER.warn("read psk-store, only errors, wrong password?");
					SecretUtil.destroy(this);
				}
			} catch (IOException e) {
				if (e.getCause() instanceof GeneralSecurityException) {
					LOGGER.warn("read psk-store, wrong password?", e);
					SecretUtil.destroy(this);
				} else {
					throw e;
				}
			} finally {
				try {
					lineReader.close();
				} catch (IOException e) {
				}
			}
			LOGGER.info("read {} PSK credentials.", size());
		}

		@Override
		public void destroy() throws DestroyFailedException {
			lock.writeLock().lock();
			try {
				identities.clear();
				for (SecretKey credentials : keys.values()) {
					SecretUtil.destroy(credentials);
				}
				keys.clear();
				destroyed = true;
			} finally {
				lock.writeLock().unlock();
			}
		}

		@Override
		public boolean isDestroyed() {
			return destroyed;
		}
	}

	/**
	 * Encryption utility for encrypted psk stores.
	 */
	private final EncryptedStreamUtil encryptionUtility = new EncryptedStreamUtil();

	/**
	 * Credentials.
	 * 
	 * @since 3.8
	 */
	private volatile Credentials credentials = new Credentials();

	/**
	 * {@code true} if psk store is destroyed.
	 */
	private volatile boolean destroyed;

	/**
	 * Seed of last loaded file.
	 * 
	 * The seed is a random header to ensure, that the encrypted file will be
	 * different, even if the same credentials are contained. Used to detect
	 * changes in encrypted file.
	 * 
	 * @see #clearSeed()
	 * @see #loadPskCredentials(String, SecretKey)
	 * @see #loadPskCredentials(InputStream, SecretKey)
	 * @since 3.8
	 */
	private byte[] seed;

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
	 * Set algorithm and key size.
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
	 * Get resource monitor for automatic credentials reloading.
	 * 
	 * @param file filename of credentials store.
	 * @param password password of credentials store. {@code null} to use
	 *            {@link #loadPskCredentials(String)} instead of
	 *            {@link #loadPskCredentials(String, SecretKey)}.
	 * @return resource monitor
	 * @since 3.8
	 */
	public SystemResourceMonitor getMonitor(final String file, final SecretKey password) {

		return new FileMonitor(file) {

			private SecretKey monitorPassword = SecretUtil.create(password);

			@Override
			protected void update(MonitoredValues values, SystemResourceCheckReady ready) {
				if (file != null) {
					if (monitorPassword != null) {
						loadPskCredentials(file, monitorPassword);
					} else {
						loadPskCredentials(file);
					}
				}
				ready(values);
				ready.ready(false);
			}
		};
	}

	/**
	 * Clear seed to force loading.
	 * 
	 * The store keeps the "seed" of encrypted files in order to prevent
	 * reloading that same file. To force loading the file, clear the "seed".
	 * 
	 * @see #loadPskCredentials(String, SecretKey)
	 * @see #loadPskCredentials(InputStream, SecretKey)
	 * @since 3.8
	 */
	public void clearSeed() {
		this.seed = null;
	}

	/**
	 * Load PSK credentials store.
	 * 
	 * @param file filename of credentials store.
	 * @return the file based PSK store for chaining
	 * @see #loadPskCredentials(Reader)
	 */
	public MultiPskFileStore loadPskCredentials(String file) {
		try (InputStream in = new FileInputStream(file)) {
			try (Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
				loadPskCredentials(reader);
			}
		} catch (IOException e) {
			LOGGER.warn("read psk-store:", e);
		}
		return this;
	}

	/**
	 * Load PSK credentials store.
	 * 
	 * @param in input stream.
	 * @return the file based PSK store for chaining
	 * @see #loadPskCredentials(Reader)
	 */
	public MultiPskFileStore loadPskCredentials(InputStream in) {
		try (Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
			loadPskCredentials(reader);
		} catch (IOException e) {
			LOGGER.warn("read psk-store:", e);
		}
		return this;
	}

	/**
	 * Load encrypted PSK credentials store.
	 * 
	 * @param file filename of credentials store.
	 * @param password password of credentials store.
	 * @return the file based PSK store for chaining
	 * @see #loadPskCredentials(Reader)
	 */
	public MultiPskFileStore loadPskCredentials(String file, SecretKey password) {
		try (InputStream in = new FileInputStream(file)) {
			loadPskCredentials(in, password);
		} catch (IOException e) {
			LOGGER.warn("read psk-store:", e);
		}
		return this;
	}

	/**
	 * Load encrypted PSK credentials store.
	 * 
	 * @param in input stream of credentials store.
	 * @param password password of credentials store.
	 * @return the file based PSK store for chaining
	 * @see #loadPskCredentials(Reader)
	 */
	public MultiPskFileStore loadPskCredentials(InputStream in, SecretKey password) {
		byte[] seed = encryptionUtility.readSeed(in);
		if (this.seed == null && !Arrays.equals(this.seed, seed)) {
			try (InputStream inEncrypted = encryptionUtility.prepare(seed, in, password)) {
				loadPskCredentials(inEncrypted);
				this.seed = seed;
			} catch (IOException e) {
				LOGGER.warn("read psk-store:", e);
			}
		} else {
			LOGGER.debug("Encrypted PSK store no changed seed.");
		}
		return this;
	}

	/**
	 * Load PSK credentials store.
	 * 
	 * Lines in format:
	 * 
	 * <pre>
	 * identity = secret - key(base64)
	 * </pre>
	 * 
	 * or
	 * 
	 * <pre>
	 * identity = ":0x" secret-key (hex)
	 * </pre>
	 * 
	 * The identity must not contain a {@code =}!
	 * 
	 * The psk credentials store keeps the order of the credentials in the file.
	 * Index {@code 0} will contain the credential of the first line.
	 * 
	 * @param reader reader for credentials store.
	 * @return the file based PSK store for chaining
	 * @throws IOException if an I/O error occurred
	 */
	public MultiPskFileStore loadPskCredentials(Reader reader) throws IOException {
		Credentials newCredentials = new Credentials();
		newCredentials.loadPskCredentials(reader);
		if (newCredentials.isDestroyed()) {
			if (credentials.size() == 0) {
				destroyed = true;
			}
		} else {
			credentials = newCredentials;
			this.seed = null;
		}
		return this;
	}

	/**
	 * Save PSK credentials store.
	 * 
	 * @param file filename of credentials store.
	 * @return the file based PSK store for chaining
	 * @see #savePskCredentials(Writer)
	 */
	public MultiPskFileStore savePskCredentials(String file) {
		try (OutputStream out = new FileOutputStream(file)) {
			try (Writer writer = new OutputStreamWriter(out, StandardCharsets.UTF_8)) {
				savePskCredentials(writer);
			}
		} catch (IOException e) {
			LOGGER.warn("write psk-store:", e);
		}
		return this;
	}

	/**
	 * Save PSK credentials store.
	 * 
	 * @param out output stream.
	 * @return the file based PSK store for chaining
	 * @see #savePskCredentials(Writer)
	 */
	public MultiPskFileStore savePskCredentials(OutputStream out) {
		try (Writer writer = new OutputStreamWriter(out, StandardCharsets.UTF_8)) {
			savePskCredentials(writer);
		} catch (IOException e) {
			LOGGER.warn("write psk-store:", e);
		}
		return this;
	}

	/**
	 * Save encrypted PSK credentials store.
	 * 
	 * @param file filename of credentials store.
	 * @param password password of credentials store.
	 * @return the file based PSK store for chaining
	 * @see #savePskCredentials(Writer)
	 */
	public MultiPskFileStore savePskCredentials(String file, SecretKey password) {
		try (OutputStream out = new FileOutputStream(file)) {
			savePskCredentials(out, password);
		} catch (IOException e) {
			LOGGER.warn("write psk-store:", e);
		}
		return this;
	}

	/**
	 * Save encrypted PSK credentials store.
	 * 
	 * @param out output stream to save credentials store.
	 * @param password password to credentials store.
	 * @return the file based PSK store for chaining
	 * @see #savePskCredentials(Writer)
	 */
	public MultiPskFileStore savePskCredentials(OutputStream out, SecretKey password) {
		try (OutputStream outEncrypted = encryptionUtility.prepare(seed, out, password)) {
			savePskCredentials(outEncrypted);
		} catch (IOException e) {
			LOGGER.warn("write psk-store:", e);
		}
		return this;
	}

	/**
	 * Save PSK credentials store.
	 * 
	 * Lines in format:
	 * 
	 * <pre>
	 * identity = secret - key(base64)
	 * </pre>
	 * 
	 * @param writer writer to save PSK credentials
	 * @return the file based PSK store for chaining
	 * @throws IOException if an I/O error occurred
	 */
	public MultiPskFileStore savePskCredentials(Writer writer) throws IOException {
		credentials.savePskCredentials(writer);
		return this;
	}

	/**
	 * Add identity and secret.
	 * 
	 * @param identity identity
	 * @param secret secret
	 * @return the file based PSK store for chaining
	 * @throws IllegalArgumentException if identity contains a {@code '='}.
	 */
	public MultiPskFileStore addKey(PskPublicInformation identity, SecretKey secret) {
		if (identity.getPublicInfoAsString().indexOf('=') >= 0) {
			throw new IllegalArgumentException("Identity must not contain '='!");
		}
		credentials.add(identity, SecretUtil.create(secret));
		return this;
	}

	/**
	 * Add identity and secret.
	 * 
	 * @param identity identity
	 * @param secret secret
	 * @return the file based PSK store for chaining
	 * @throws IllegalArgumentException if identity contains a {@code '='}.
	 */
	public MultiPskFileStore addKey(String identity, SecretKey secret) {
		return addKey(new PskPublicInformation(identity), secret);
	}

	/**
	 * Remove identity and secret.
	 * 
	 * @param identity identity
	 * @return the file based PSK store for chaining
	 */
	public MultiPskFileStore removeKey(PskPublicInformation identity) {
		credentials.remove(identity);
		return this;
	}

	/**
	 * Remove identity and secret.
	 * 
	 * @param index index of key
	 * @return the file based PSK store for chaining
	 * @throws IndexOutOfBoundsException if provided index is out of bounds
	 */
	public MultiPskFileStore removeKey(int index) {
		credentials.remove(index);
		return this;
	}

	/**
	 * Remove identity and secret.
	 * 
	 * @param identity identity
	 * @return the file based PSK store for chaining
	 */
	public MultiPskFileStore removeKey(String identity) {
		return removeKey(new PskPublicInformation(identity));
	}

	/**
	 * Get identity.
	 * 
	 * @param index index of identity.
	 * @return identity at provided index
	 * @throws IndexOutOfBoundsException if provided index is out of bounds
	 */
	public String getIdentity(int index) {
		return credentials.getIdentity(index);
	}

	/**
	 * Get secret key.
	 * 
	 * @param index index of key
	 * @return secret key at provided index
	 * @throws IndexOutOfBoundsException if provided index is out of bounds
	 */
	public SecretKey getSecret(int index) {
		return credentials.getSecret(index);
	}

	/**
	 * Get secret key.
	 * 
	 * @param identity identity
	 * @return secret key for identity. {@code null} if not available.
	 */
	public SecretKey getSecret(String identity) {
		return getSecret(new PskPublicInformation(identity));
	}

	/**
	 * Get secret key.
	 * 
	 * @param identity identity
	 * @return secret key for identity. {@code null} if not available.
	 */
	public SecretKey getSecret(PskPublicInformation identity) {
		return credentials.getSecret(identity);
	}

	/**
	 * Size.
	 * 
	 * @return number of identity and key pairs.
	 */
	public int size() {
		return credentials.size();
	}

	@Override
	public void destroy() throws DestroyFailedException {
		credentials.destroy();
		destroyed = true;
	}

	@Override
	public boolean isDestroyed() {
		return destroyed;
	}

	@Override
	public boolean hasEcdhePskSupported() {
		return true;
	}

	@Override
	public PskSecretResult requestPskSecretResult(ConnectionId cid, ServerNames serverName,
			PskPublicInformation identity, String hmacAlgorithm, SecretKey otherSecret, byte[] seed,
			boolean useExtendedMasterSecret) {
		return new PskSecretResult(cid, identity, credentials.getSecret(identity));
	}

	@Override
	public PskPublicInformation getIdentity(InetSocketAddress peerAddress, ServerNames virtualHost) {
		// not intended for clients
		return null;
	}

	@Override
	public void setResultHandler(HandshakeResultHandler resultHandler) {
		// empty implementation
	}
}
