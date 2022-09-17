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
 * @since 3.7
 */
public class MultiPskFileStore implements AdvancedPskStore, Destroyable {

	private static final Logger LOGGER = LoggerFactory.getLogger(MultiPskFileStore.class);

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
	 * Encryption utility for encrypted psk stores.
	 */
	private final EncryptedStreamUtil encryptionUtility = new EncryptedStreamUtil();
	/**
	 * {@code true} if psk store is destroyed.
	 */
	private volatile boolean destroyed;

	/**
	 * Set algorithm and key size.
	 * 
	 * @param cipherAlgorithm cipher algorithm
	 * @param keySizeBits key size in bits
	 */
	public void setCipher(String cipherAlgorithm, int keySizeBits) {
		encryptionUtility.setCipher(cipherAlgorithm, keySizeBits);
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
		try (InputStream inEncrypted = encryptionUtility.prepare(in, password)) {
			loadPskCredentials(inEncrypted);
		} catch (IOException e) {
			LOGGER.warn("read psk-store:", e);
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
		BufferedReader lineReader = new BufferedReader(reader);
		try {
			int lineNumber = 0;
			String line;
			// readLine() reads the secret into a String,
			// what may be considered to be a weak practice.
			while ((line = lineReader.readLine()) != null) {
				++lineNumber;
				try {
					if (!line.isEmpty() && !line.startsWith("#")) {
						String[] entry = line.split("=", 2);
						if (entry.length == 2) {
							byte[] secretBytes = StringUtil.base64ToByteArray(entry[1]);
							SecretKey key = SecretUtil.create(secretBytes, "PSK");
							Bytes.clear(secretBytes);
							PskPublicInformation id = new PskPublicInformation(entry[0]);
							lock.writeLock().lock();
							try {
								if (keys.put(id, SecretUtil.create(key)) == null) {
									identities.add(id);
								}
							} finally {
								lock.writeLock().unlock();
							}
						} else {
							LOGGER.warn("{}: '{}' invalid psk-line!", lineNumber, line);
						}
					}
				} catch (IllegalArgumentException ex) {
					LOGGER.warn("{}: '{}' invalid psk-line!", lineNumber, line);
				}
			}
		} catch (IOException e) {
			if (e.getCause() instanceof GeneralSecurityException) {
				LOGGER.warn("read psk-store, wrong password?:", e);
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
		LOGGER.info("read {} PSK credentials.", identities.size());
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
		try (OutputStream outEncrypted = encryptionUtility.prepare(out, password)) {
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
		lock.writeLock().lock();
		try {
			if (keys.put(identity, SecretUtil.create(secret)) == null) {
				identities.add(identity);
			}
		} finally {
			lock.writeLock().unlock();
		}
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
		lock.writeLock().lock();
		try {
			if (keys.remove(identity) != null) {
				identities.add(identity);
			}
		} finally {
			lock.writeLock().unlock();
		}
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
		lock.writeLock().lock();
		try {
			PskPublicInformation id = identities.remove(index);
			if (id != null) {
				keys.remove(id);
			}
		} finally {
			lock.writeLock().unlock();
		}
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
		lock.readLock().lock();
		try {
			PskPublicInformation info = identities.get(index);
			return info != null ? info.getPublicInfoAsString() : null;
		} finally {
			lock.readLock().unlock();
		}
	}

	/**
	 * Get secret key.
	 * 
	 * @param index index of key
	 * @return secret key at provided index
	 * @throws IndexOutOfBoundsException if provided index is out of bounds
	 */
	public SecretKey getSecret(int index) {
		lock.readLock().lock();
		try {
			PskPublicInformation info = identities.get(index);
			if (info != null) {
				return SecretUtil.create(keys.get(info));
			}
			return null;
		} finally {
			lock.readLock().unlock();
		}
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
		lock.readLock().lock();
		try {
			return SecretUtil.create(keys.get(identity));
		} finally {
			lock.readLock().unlock();
		}
	}

	/**
	 * Size.
	 * 
	 * @return number of identity and key pairs.
	 */
	public int size() {
		return identities.size();
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

	@Override
	public boolean hasEcdhePskSupported() {
		return true;
	}

	@Override
	public PskSecretResult requestPskSecretResult(ConnectionId cid, ServerNames serverName,
			PskPublicInformation identity, String hmacAlgorithm, SecretKey otherSecret, byte[] seed,
			boolean useExtendedMasterSecret) {
		lock.readLock().lock();
		try {
			return new PskSecretResult(cid, identity, SecretUtil.create(keys.get(identity)));
		} finally {
			lock.readLock().unlock();
		}
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
