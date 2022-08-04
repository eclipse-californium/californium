/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.cloud.util;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.EncryptedStreamUtil;
import org.eclipse.californium.elements.util.StandardCharsets;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.elements.util.SystemResourceMonitors.FileMonitor;
import org.eclipse.californium.elements.util.SystemResourceMonitors.SystemResourceCheckReady;
import org.eclipse.californium.elements.util.SystemResourceMonitors.SystemResourceMonitor;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resource store with optional automatic reload function.
 * 
 * @since 3.12
 */
public class ResourceStore<T extends ResourceParser<T>> implements Destroyable {

	private static final Logger LOGGER = LoggerFactory.getLogger(ResourceStore.class);

	/**
	 * Factory instance of {@link ResourceParser}.
	 */
	private final T factory;
	/**
	 * Encryption utility for encrypted resources.
	 */
	private final EncryptedStreamUtil encryptionUtility = new EncryptedStreamUtil();
	/**
	 * Observer for loaded {@link ResourceParser}.
	 */
	private volatile Observer<T> observer;
	/**
	 * Monitor for automatic reloading.
	 */
	protected volatile SystemResourceMonitor monitor;
	/**
	 * Logging tag for resource store.
	 */
	private volatile String tag = "";
	/**
	 * Current loaded resource.
	 */
	private volatile T currentResource;
	/**
	 * {@code true} if resource store is destroyed.
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
	 * @see #load(String, SecretKey)
	 * @see #load(InputStream, SecretKey)
	 */
	private byte[] seed;

	/**
	 * Create resource store.
	 * 
	 * @param factory the factory instance of {@link ResourceParser}.
	 * @throws NullPointerException if provided factory is {@code null}
	 */
	public ResourceStore(T factory) {
		if (factory == null) {
			throw new NullPointerException("factory must not be null!");
		}
		this.factory = factory;
		this.currentResource = factory.create();
	}

	/**
	 * Get write cipher specification.
	 * 
	 * @return cipher specification (algorithm + key size). e.g. "AES/GCM/128".
	 * @see EncryptedStreamUtil#getWriteCipher()
	 */
	public String getWriteCipher() {
		return encryptionUtility.getWriteCipher();
	}

	/**
	 * Get read cipher specification.
	 * 
	 * @return cipher specification (algorithm + key size). e.g. "AES/GCM/128".
	 *         {@code null}, if not available
	 * @see EncryptedStreamUtil#getReadCipher()
	 */
	public String getReadCipher() {
		return encryptionUtility.getReadCipher();
	}

	/**
	 * Set write cipher to default cipher.
	 * 
	 * @return this resource store for command chaining
	 * @see EncryptedStreamUtil#setDefaultWriteCipher()
	 */
	public ResourceStore<T> setDefaultWriteCipher() {
		encryptionUtility.setDefaultWriteCipher();
		return this;
	}

	/**
	 * Set cipher algorithm and key size for writing.
	 * 
	 * @param cipherAlgorithm cipher algorithm
	 * @param keySizeBits key size in bits
	 * @return this resource store for command chaining
	 * @throws IllegalArgumentException if cipher and key size is not supported
	 * @see EncryptedStreamUtil#setWriteCipher(String, int)
	 */
	public ResourceStore<T> setWriteCipher(String cipherAlgorithm, int keySizeBits) {
		encryptionUtility.setWriteCipher(cipherAlgorithm, keySizeBits);
		return this;
	}

	/**
	 * Set cipher for writing.
	 * 
	 * @param spec cipher specification (algorithm + key size). e.g.
	 *            "AES/GCM/128".
	 * @return this resource store for command chaining
	 * @throws IllegalArgumentException if cipher and key size is not supported
	 * @see EncryptedStreamUtil#setWriteCipher(String)
	 */
	public ResourceStore<T> setWriteCipher(String spec) {
		encryptionUtility.setWriteCipher(spec);
		return this;
	}

	/**
	 * Set logging tag.
	 * 
	 * @param tag logging tag
	 * @return this resource store for command chaining
	 * @throws NullPointerException if tag is {@code null}
	 */
	public ResourceStore<T> setTag(String tag) {
		if (tag == null) {
			throw new NullPointerException("tag must not be null!");
		}
		this.tag = tag;
		return this;
	}

	/**
	 * Get logging tag.
	 * 
	 * @return logging tag
	 */
	public String getTag() {
		return tag;
	}

	/**
	 * Set observer for new resource.
	 * 
	 * @param observer observer for loaded {@link ResourceParser}. May be
	 *            {@code null}.
	 * @return this credentials store for command chaining
	 */
	public ResourceStore<T> setObserver(Observer<T> observer) {
		this.observer = observer;
		return this;
	}

	/**
	 * Create resource monitor for automatic resource reloading.
	 * 
	 * @param file filename of resource.
	 * @param password password of resource. {@code null} to use
	 *            {@link #load(String)} instead of
	 *            {@link #load(String, SecretKey)}.
	 * @return created resource monitor
	 */
	public SystemResourceMonitor createMonitor(final String file, final SecretKey password) {
		if (file != null) {
			monitor = new FileMonitor(file) {

				private SecretKey monitorPassword = SecretUtil.create(password);

				@Override
				protected void update(MonitoredValues values, SystemResourceCheckReady ready) {
					if (monitorPassword != null) {
						load(file, monitorPassword);
					} else {
						load(file);
					}
					ready(values);
					ready.ready(false);
				}
			};
		} else {
			monitor = null;
		}
		return monitor;
	}

	/**
	 * Get resource monitor for automatic reloading.
	 * 
	 * @return resource monitor, or {@code null}, if not created.
	 * @see #createMonitor(String, SecretKey)
	 * @see #loadAndCreateMonitor(String, String, boolean)
	 */
	public SystemResourceMonitor getMonitor() {
		return monitor;
	}

	/**
	 * Clear seed to force loading.
	 * 
	 * The store keeps the "seed" of encrypted files in order to prevent
	 * reloading that same file. To force loading the file, clear the "seed".
	 * 
	 * @see #load(String, SecretKey)
	 * @see #load(InputStream, SecretKey)
	 */
	public void clearSeed() {
		if (seed != null) {
			Bytes.clear(seed);
			seed = null;
		}
	}

	/**
	 * Load resource from file.
	 * 
	 * @param file filename of resource.
	 * @return this resource store for command chaining
	 * @see #load(Reader)
	 */
	public ResourceStore<T> load(String file) {
		try (InputStream in = new FileInputStream(file)) {
			try (Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
				load(reader);
			}
		} catch (IOException e) {
			LOGGER.warn("{}read {}:", tag, file, e);
		}
		return this;
	}

	/**
	 * Load resource from {@link InputStream}.
	 * 
	 * @param in input stream of resource.
	 * @return this resource store for command chaining
	 * @see #load(Reader)
	 */
	public ResourceStore<T> load(InputStream in) {
		try (Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
			load(reader);
		} catch (IOException e) {
			LOGGER.warn("{}read:", tag, e);
		}
		return this;
	}

	/**
	 * Load encrypted resource from file.
	 * 
	 * @param file filename of resource.
	 * @param password password of resource.
	 * @return this resource store for command chaining
	 * @see #load(Reader)
	 */
	public ResourceStore<T> load(String file, SecretKey password) {
		try (InputStream in = new FileInputStream(file)) {
			load(in, password);
		} catch (IOException e) {
			LOGGER.warn("{}read encrypted {}:", tag, file, e);
		}
		return this;
	}

	/**
	 * Load encrypted resource from {@link InputStream}.
	 * 
	 * @param in input stream of resource.
	 * @param password password of resource.
	 * @return this resource store for command chaining
	 * @see #load(Reader)
	 */
	public ResourceStore<T> load(InputStream in, SecretKey password) {
		byte[] seed = encryptionUtility.readSeed(in);
		if (this.seed == null || !Arrays.equals(this.seed, seed)) {
			try (InputStream inEncrypted = encryptionUtility.prepare(seed, in, password)) {
				load(inEncrypted);
				this.seed = seed;
			} catch (IOException e) {
				LOGGER.warn("{}read encrypted:", tag, e);
			}
		} else {
			LOGGER.debug("{}encrypted not changed, (same seed).", tag);
		}
		return this;
	}

	/**
	 * Load resource from {@link Reader}.
	 * 
	 * @param reader reader of resource.
	 * @return this resource store for command chaining
	 * @throws IOException if an I/O error occurred
	 */
	public ResourceStore<T> load(Reader reader) throws IOException {
		T newConfigurations = factory.create();
		newConfigurations.load(reader);
		if (newConfigurations.isDestroyed()) {
			if (currentResource.isDestroyed()) {
				destroyed = true;
			}
		} else {
			Observer<T> observer = this.observer;
			if (observer != null) {
				observer.update(newConfigurations);
			}
			currentResource = newConfigurations;
			// reset seed.
			// if encryption is used, it will be set in the calling function.
			this.seed = null;
		}
		return this;
	}

	/**
	 * Save resource to file.
	 * 
	 * @param file filename of resource.
	 * @return this resource store for command chaining
	 * @see #save(Writer)
	 */
	public ResourceStore<T> save(String file) {
		try (OutputStream out = new FileOutputStream(file)) {
			try (Writer writer = new OutputStreamWriter(out, StandardCharsets.UTF_8)) {
				save(writer);
			}
		} catch (IOException e) {
			LOGGER.warn("{}write {}:", tag, file, e);
		}
		return this;
	}

	/**
	 * Save resource to {@link OutputStream}.
	 * 
	 * @param out output stream of resource.
	 * @return this resource store for command chaining
	 * @see #save(Writer)
	 */
	public ResourceStore<T> save(OutputStream out) {
		try (Writer writer = new OutputStreamWriter(out, StandardCharsets.UTF_8)) {
			save(writer);
		} catch (IOException e) {
			LOGGER.warn("{}write:", tag, e);
		}
		return this;
	}

	/**
	 * Save encrypted resource to file.
	 * 
	 * @param file filename of resource.
	 * @param password password of resource.
	 * @return this resource store for command chaining
	 * @see #save(Writer)
	 */
	public ResourceStore<T> save(String file, SecretKey password) {
		try (OutputStream out = new FileOutputStream(file)) {
			save(out, password);
		} catch (IOException e) {
			LOGGER.warn("{}write encrypted {}:", tag, file, e);
		}
		return this;
	}

	/**
	 * Save encrypted resource to {@link OutputStream}.
	 * 
	 * @param out output stream to save resource.
	 * @param password password of resource.
	 * @return this resource store for command chaining
	 * @see #save(Writer)
	 */
	public ResourceStore<T> save(OutputStream out, SecretKey password) {
		try (OutputStream outEncrypted = encryptionUtility.prepare(seed, out, password)) {
			save(outEncrypted);
		} catch (IOException e) {
			LOGGER.warn("{}write encrypted:", tag, e);
		}
		return this;
	}

	/**
	 * Save resource.
	 * 
	 * @param writer writer to save resource.
	 * @return this resource store for command chaining
	 * @throws IOException if an I/O error occurred
	 */
	public ResourceStore<T> save(Writer writer) throws IOException {
		currentResource.save(writer);
		return this;
	}

	/**
	 * Load resource and check for changes.
	 * 
	 * @param name name for monitoring
	 * @param password64 base64 encoded password of resource. {@code null} to
	 *            use {@link #load(String)} instead of
	 *            {@link #load(String, SecretKey)}.
	 * @param createMonitor {@code true} to create a monitor, {@code false}, if
	 *            not.
	 * @return loaded resource
	 */
	public T loadAndCreateMonitor(String name, String password64, boolean createMonitor) {
		if (password64 != null) {
			byte[] secret = StringUtil.base64ToByteArray(password64);
			SecretKey key = SecretUtil.create(secret, "PW");
			Bytes.clear(secret);
			load(name, key);
			if (createMonitor) {
				createMonitor(name, key);
			}
			SecretUtil.destroy(key);
			LOGGER.info("{}loaded encrypted store {}", getTag(), name);
		} else {
			load(name);
			if (createMonitor) {
				createMonitor(name, null);
			}
			LOGGER.info("{}loaded store {}", getTag(), name);
		}
		return currentResource;
	}

	/**
	 * Get current resource.
	 * 
	 * @return current resource
	 */
	public T getResource() {
		return currentResource;
	}

	@Override
	public void destroy() throws DestroyFailedException {
		currentResource.destroy();
		destroyed = true;
	}

	@Override
	public boolean isDestroyed() {
		return destroyed;
	}

	public interface Observer<T extends ResourceParser<T>> {

		void update(T newT);
	}
}
