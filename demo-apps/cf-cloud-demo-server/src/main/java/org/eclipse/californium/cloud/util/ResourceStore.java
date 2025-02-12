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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.concurrent.Semaphore;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.eclipse.californium.cloud.util.ResultConsumer.ResultCode;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.EncryptedStreamUtil;
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
	 * Semaphore to protect access.
	 * 
	 * @since 3.13
	 */
	protected final Semaphore semaphore = new Semaphore(1);
	/**
	 * Encryption utility for encrypted resources.
	 */
	protected final EncryptedStreamUtil encryptionUtility = new EncryptedStreamUtil();
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
	 * <p>
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
			monitor = new AppendFileMonitor(file, password);
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
		try (InputStream in = createInputStream(file)) {
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
		try (InputStream in = createInputStream(file)) {
			load(in, password);
		} catch (FileNotFoundException e) {
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
			if (newConfigurations instanceof AppendingResourceParser) {
				((AppendingResourceParser<?>) newConfigurations).clearNewEntries();
			}
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

	/**
	 * Get semaphore.
	 * 
	 * @return semaphore.
	 * @since 3.13
	 */
	public Semaphore getSemaphore() {
		return semaphore;
	}

	public interface Observer<T extends ResourceParser<T>> {

		void update(T newT);
	}

	public class AppendFileMonitor extends FileMonitor implements ResourceChangedHandler {

		private static final String BACKUP = ".bak";
		private static final String NEW = ".new";

		private final String file;
		private final SecretKey password;

		public AppendFileMonitor(final String file, final SecretKey password) {
			super(file);
			this.file = file;
			this.password = SecretUtil.create(password);
			cleanup();
		}

		public void cleanup() {
			if (getFile().exists()) {
				// cleanup
				File[] list = list("");
				if (list != null) {
					for (File file : list) {
						try {
							file.delete();
							LOGGER.info("{} cleanup {}", tag, file.getName());
						} catch (SecurityException ex) {
						}
					}
				}
			} else {
				// recover
				File[] backup = list(BACKUP);
				File[] newFile = list(NEW);
				if (backup != null && backup.length == 1 && newFile != null && newFile.length == 1) {
					// one backup, one new
					try {
						Files.move(newFile[0].toPath(), getFile().toPath(), StandardCopyOption.REPLACE_EXISTING);
						Files.deleteIfExists(backup[0].toPath());
					} catch (Exception ex) {
						LOGGER.info("{} append failed!", tag, ex);
					}
				}
			}
		}

		public File getParentDirectory() {
			return getFile().getAbsoluteFile().getParentFile();
		}

		public File[] list(final String suffix) {
			final String filename = getFile().getName();
			File directory = getParentDirectory();
			return directory.listFiles(new FilenameFilter() {

				@Override
				public boolean accept(File dir, String name) {
					return !name.equals(filename) && name.startsWith(filename) && name.endsWith(suffix);
				}
			});
		}

		@Override
		public void checkForUpdate(SystemResourceCheckReady ready) {
			if (semaphore.tryAcquire()) {
				try {
					super.checkForUpdate(ready);
				} finally {
					semaphore.release();
				}
			} else {
				// schedule next check
				ready.ready(false);
			}
		}

		@Override
		protected void update(MonitoredValues values, SystemResourceCheckReady ready) {
			if (password != null) {
				load(file, password);
			} else {
				load(file);
			}
			ready(values);
			ready.ready(false);
		}

		@Override
		public void changed(ResultConsumer response) {
			if (!(currentResource instanceof AppendingResourceParser)) {
				response.results(ResultCode.SERVER_ERROR, "no AppendResourceParser.");
				return;
			}
			AppendingResourceParser<?> resource = (AppendingResourceParser<?>) currentResource;
			try {
				int result = 0;
				File targetFile = getFile();
				File temp = File.createTempFile(file, NEW, getParentDirectory());
				if (password != null) {
					try (InputStream in = createInputStream(targetFile)) {
						byte[] seed = encryptionUtility.readSeed(in);
						try (InputStream inEncrypted = encryptionUtility.prepare(seed, in, password)) {
							try (OutputStream out = new FileOutputStream(temp)) {
								try (OutputStream outEncrypted = encryptionUtility.prepare(seed, out, password)) {
									result = appendNewEntries(resource, inEncrypted, outEncrypted);
								}
							}
						}
					} catch (IOException e) {
						LOGGER.warn("{}append encrypted {}:", tag, file, e);
						throw e;
					}
				} else {
					try (InputStream in = createInputStream(targetFile)) {
						try (OutputStream out = new FileOutputStream(temp)) {
							result = appendNewEntries(resource, in, out);
						}
					} catch (IOException e) {
						LOGGER.warn("{}append {}:", tag, file, e);
						throw e;
					}
				}
				if (result > 0) {
					MonitoredValues values = checkMonitoredValues();
					Path current = targetFile.toPath();
					Path backup = Paths.get(file + BACKUP);
					Path temporary = temp.toPath();
					try {
						Files.move(current, backup, StandardCopyOption.REPLACE_EXISTING);
					} catch (Exception ex) {
						LOGGER.info("{} backup failed!", tag, ex);
					}
					try {
						Files.move(temporary, current, StandardCopyOption.REPLACE_EXISTING);
					} catch (Exception ex) {
						LOGGER.info("{} append failed!", tag, ex);
						response.results(ResultCode.SERVER_ERROR, "failed to append file.");
						return;
					}
					cleanup();
					if (values == null) {
						values = checkMonitoredValues();
						ready(values);
					}
					resource.clearNewEntries();
					response.results(ResultCode.SUCCESS, "successfully added " + result + " new entries.");
				} else {
					temp.delete();
					response.results(ResultCode.SERVER_ERROR, "failed to append new entries.");
				}
			} catch (IOException e) {
				LOGGER.warn("{}append {}:", tag, file, e);
				response.results(ResultCode.SERVER_ERROR, "failed to save new entries. " + e.getMessage());
			}
		}
	}

	/**
	 * Append new entries of resource.
	 * 
	 * @param resource resource to append new entries
	 * @param in in stream to append new entries
	 * @param out out stream to write appended result
	 * @return number of written new entries.
	 * @throws IOException if an i/o error occurred
	 * @since 3.13
	 */
	protected static int appendNewEntries(AppendingResourceParser<?> resource, InputStream in, OutputStream out)
			throws IOException {
		int len;
		int result = resource.sizeNewEntries();
		byte[] buffer = new byte[8192];

		while ((len = in.read(buffer)) >= 0) {
			if (len > 0) {
				out.write(buffer, 0, len);
			}
		}
		try (Writer writer = new OutputStreamWriter(out, StandardCharsets.UTF_8)) {
			resource.saveNewEntries(writer);
		}
		return result;
	}

	/**
	 * Create input stream from file.
	 * <p>
	 * If file doesn't exists, return an empty input stream.
	 * 
	 * @param file file to read
	 * @return input stream
	 * @since 4.0
	 */
	protected static InputStream createInputStream(File file) {
		try {
			return new FileInputStream(file);
		} catch (FileNotFoundException e) {
			return new ByteArrayInputStream(Bytes.EMPTY);
		}
	}

	/**
	 * Create input stream from file.
	 * <p>
	 * If file doesn't exists, return an empty input stream.
	 * 
	 * @param file file to read
	 * @return input stream
	 * @since 4.0
	 */
	protected static InputStream createInputStream(String file) {
		try {
			return new FileInputStream(file);
		} catch (FileNotFoundException e) {
			return new ByteArrayInputStream(Bytes.EMPTY);
		}
	}
}
