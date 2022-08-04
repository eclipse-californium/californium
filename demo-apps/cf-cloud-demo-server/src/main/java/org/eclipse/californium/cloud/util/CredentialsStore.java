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
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.EncryptedStreamUtil;
import org.eclipse.californium.elements.util.PemReader;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.SslContextUtil.Credentials;
import org.eclipse.californium.elements.util.StandardCharsets;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.elements.util.SystemResourceMonitors.FileMonitor;
import org.eclipse.californium.elements.util.SystemResourceMonitors.SystemResourceCheckReady;
import org.eclipse.californium.elements.util.SystemResourceMonitors.SystemResourceMonitor;
import org.eclipse.californium.scandium.dtls.x509.CertificateConfigurationHelper;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Credentials store with optional automatic reload function.
 * 
 * @since 3.12
 */
public class CredentialsStore implements Destroyable {

	private static final Logger LOGGER = LoggerFactory.getLogger(CredentialsStore.class);

	/**
	 * Encryption utility for encrypted resources.
	 */
	private final EncryptedStreamUtil encryptionUtility = new EncryptedStreamUtil();
	/**
	 * Observer for loaded {@link Credentials}.
	 */
	private volatile Observer observer;
	/**
	 * Monitor for automatic reloading.
	 */
	private volatile SystemResourceMonitor monitor;
	/**
	 * Logging tag for resource store.
	 */
	private volatile String tag = "";
	/**
	 * Current loaded credentials.
	 */
	private volatile Credentials currentCredentials;
	/**
	 * {@code true} if credentials are destroyed.
	 */
	private volatile boolean destroyed;

	/**
	 * Seed of last loaded file1.
	 * 
	 * The seed is a random header to ensure, that the encrypted file will be
	 * different, even if the same credentials are contained. Used to detect
	 * changes in encrypted file.
	 * 
	 * @see #clearSeed()
	 * @see #load(String, String, SecretKey)
	 * @see #load(InputStream, SecretKey)
	 */
	private byte[] seed;

	/**
	 * Create credentials store.
	 */
	public CredentialsStore() {
		this.currentCredentials = new Credentials(null);
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
	 * Set logging tag.
	 * 
	 * @param tag logging tag
	 * @return this credentials store for command chaining
	 */
	public CredentialsStore setTag(String tag) {
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
	 * Indicates encryption.
	 * 
	 * @return {@code true}, if credentials are encrypted, {@code false},
	 *         otherwise.
	 */
	public boolean isEncrypted() {
		return seed != null;
	}

	/**
	 * Set observer for new credentials.
	 * 
	 * @param observer observer for loaded credentials
	 * @return this credentials store for command chaining
	 */
	public CredentialsStore setObserver(Observer observer) {
		this.observer = observer;
		return this;
	}

	/**
	 * Create resource monitor for automatic credentials reloading.
	 * 
	 * @param file1 filename of credentials 1.
	 * @param file2 filename of credentials 2. May be {@code null}.
	 * @param password password of credentials. {@code null} to use
	 *            {@link #load(String, String)} instead of
	 *            {@link #load(String, String, SecretKey)}.
	 * @return created resource monitor
	 */
	public SystemResourceMonitor createMonitor(final String file1, final String file2, final SecretKey password) {
		if (file1 != null) {
			monitor = new FileMonitor(file1) {

				private SecretKey monitorPassword = SecretUtil.create(password);

				@Override
				protected void update(MonitoredValues values, SystemResourceCheckReady ready) {
					for (int loop = 0; loop < 3; ++loop) {
						try {
							if (monitorPassword != null) {
								load(file1, file2, monitorPassword);
							} else {
								load(file1, file2);
							}
							// on success, prevent reading again
							ready(values);
							break;
						} catch (IllegalArgumentException ex) {
							if (loop < 2) {
								LOGGER.info("{}error: {}, retry in 1s ...", tag, ex.getMessage());
							} else {
								LOGGER.info("{}error: {}", tag, ex.getMessage());
							}
							// key pair mismatch
							// race condition reading new file pair?
							try {
								Thread.sleep(1000);
							} catch (InterruptedException e) {
							}
						}
					}
					ready.ready(false);
				}
			};
		} else {
			monitor = null;
		}
		return monitor;
	}

	/**
	 * Get resource monitor for automatic credentials reloading.
	 * 
	 * @return resource monitor, or {@code null}, if not created.
	 * @see #createMonitor(String, String, SecretKey)
	 * @see #loadAndCreateMonitor(String, String, String, boolean)
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
	 * @see #load(String, String, SecretKey)
	 * @see #load(InputStream, SecretKey)
	 */
	public void clearSeed() {
		if (seed != null) {
			Bytes.clear(seed);
			seed = null;
		}
	}

	/**
	 * Load credentials from file.
	 * 
	 * @param file1 filename of credentials 1.
	 * @param file2 filename of credentials 2. May be {@code null}.
	 * @return this credentials store for command chaining
	 * @see #load(Reader)
	 */
	public CredentialsStore load(String file1, String file2) {
		try (InputStream in1 = new FileInputStream(file1)) {
			try (Reader reader1 = new InputStreamReader(in1, StandardCharsets.UTF_8)) {
				Credentials newCredentials1 = load(reader1);
				if (changed(newCredentials1)) {
					if (file2 != null && !complete(newCredentials1)) {
						try (InputStream in2 = new FileInputStream(file2)) {
							try (Reader reader2 = new InputStreamReader(in2, StandardCharsets.UTF_8)) {
								Credentials newCredentials2 = load(reader2);
								if (newCredentials2 != null) {
									newCredentials1 = merge(newCredentials1, newCredentials2);
								}
							}
						} catch (IOException e) {
							LOGGER.warn("{}read credentials {}:", tag, file2, e);
						}
					}
					applyCredentials(newCredentials1);
				} else if (newCredentials1 != null) {
					LOGGER.info("{}read credentials {}: not changed", tag, file1);
				}
			}
		} catch (IOException e) {
			LOGGER.warn("{}read credentials {}:", tag, file1, e);
		}
		return this;
	}

	/**
	 * Load encrypted credentials from file.
	 * 
	 * @param file1 filename of credentials 1.
	 * @param file2 filename of credentials 2. May be {@code null}.
	 * @param password password of credentials.
	 * @return this resource store for command chaining
	 * @see #load(Reader)
	 */
	public CredentialsStore load(String file1, String file2, SecretKey password) {
		try (InputStream in = new FileInputStream(file1)) {
			Credentials newCredentials1 = load(in, password);
			if (changed(newCredentials1)) {
				if (file2 != null && !complete(newCredentials1)) {
					byte[] seed = this.seed;
					this.seed = null;
					try (InputStream in2 = new FileInputStream(file2)) {
						Credentials newCredentials2 = load(in2, password);
						if (newCredentials2 != null) {
							newCredentials1 = merge(newCredentials1, newCredentials2);
						}
					} catch (IOException e) {
						LOGGER.warn("{}read encrypted credentials {}:", tag, file2, e);
					} finally {
						this.seed = seed;
					}
				}
				applyCredentials(newCredentials1);
			} else if (newCredentials1 != null) {
				LOGGER.info("{}read encrypted credentials {}: not changed", tag, file1);
			}
		} catch (IOException e) {
			LOGGER.warn("{}read encrypted credentials {}:", tag, file1, e);
		}
		return this;
	}

	/**
	 * Apply new credentials.
	 * 
	 * @param newCredentials new credentials.
	 */
	private void applyCredentials(Credentials newCredentials) {
		if (!complete(newCredentials)) {
			LOGGER.info("Credentials are not complete!");
			clearSeed();
			return;
		}
		if (newCredentials.getPrivateKey() != null) {
			CertificateConfigurationHelper helper = new CertificateConfigurationHelper();
			helper.verifyKeyPair(newCredentials.getPrivateKey(), newCredentials.getPublicKey());
		}
		final Observer observer = this.observer;
		if (observer != null) {
			observer.update(newCredentials);
		}
		currentCredentials = newCredentials;
	}

	/**
	 * Load encrypted credentials from {@link InputStream}.
	 * 
	 * @param in input stream of resource.
	 * @param password password of resource.
	 * @return loaded credentials, or {@code null}, if not successful
	 * @see #load(Reader)
	 */
	private Credentials load(InputStream in, SecretKey password) {
		byte[] seed = encryptionUtility.readSeed(in);
		if (this.seed == null || !Arrays.equals(this.seed, seed)) {
			try (InputStream inEncrypted = encryptionUtility.prepare(seed, in, password)) {
				try (Reader reader = new InputStreamReader(inEncrypted, StandardCharsets.UTF_8)) {
					Credentials newCredentials = load(reader);
					if (newCredentials != null) {
						this.seed = seed;
						return newCredentials;
					}
				}
			} catch (IOException e) {
				LOGGER.warn("{}read encrypted credentials:", tag, e);
			}
		} else {
			LOGGER.debug("{}encrypted credentials not changed, (same seed).", tag);
		}
		return null;
	}

	/**
	 * Load credentials from {@link Reader}.
	 * 
	 * @param reader reader of resource.
	 * @return loaded credentials, or {@code null}, if not successful
	 * @throws IOException if an I/O error occurred
	 */
	private Credentials load(Reader reader) throws IOException {
		try {
			Credentials newCredentials = SslContextUtil.loadPemCredentials(new PemReader(reader));
			if (newCredentials.isDestroyed()) {
				LOGGER.info("Loaded credentials are empty!", newCredentials);
				if (currentCredentials.isDestroyed()) {
					destroyed = true;
				}
			} else {
				// reset seed.
				// if encryption is used, it will be
				// set in the calling function.
				this.seed = null;
				LOGGER.info("Loaded {}", newCredentials);
				return newCredentials;
			}
		} catch (GeneralSecurityException e) {
			LOGGER.warn("Loading credentials failed {}", e.getMessage());
			if (currentCredentials.isDestroyed()) {
				destroyed = true;
			}
		}
		return null;
	}

	/**
	 * Check, if credentials are complete.
	 * 
	 * @param newCredentials new credentials to check
	 * @return {@code true}, if complete, {@code false}, otherwise.
	 */
	protected boolean complete(Credentials newCredentials) {
		return !newCredentials.isDestroyed()
				&& (newCredentials.getPublicKey() != null) == (newCredentials.getPrivateKey() != null);
	}

	/**
	 * Check, if new credentials have changed based on the
	 * {@link #currentCredentials}.
	 * 
	 * @param newCredentials new credentials
	 * @return {@code true}, if the new credentials has changed, {@code false},
	 *         otherwise.
	 */
	protected boolean changed(Credentials newCredentials) {
		if (newCredentials == null) {
			return false;
		} else if (changed(currentCredentials.getPrivateKey(), newCredentials.getPrivateKey())) {
			LOGGER.info("Private key changed");
			return true;
		} else if (changed(currentCredentials.getPublicKey(), newCredentials.getPublicKey())) {
			LOGGER.info("Public key changed");
			return true;
		} else if (changed(currentCredentials.getCertificateChain(), newCredentials.getCertificateChain())) {
			LOGGER.info("Certificate chain changed");
			return true;
		} else if (changed(currentCredentials.getTrustedCertificates(), newCredentials.getTrustedCertificates())) {
			LOGGER.info("Trusted certificates changed");
			return true;
		}
		return false;
	}

	/**
	 * Check,if an item has changed.
	 * 
	 * @param <T> type of item
	 * @param currentItem the current item.
	 * @param newItem the new item.
	 * @return {@code true}, if the new item has changed, {@code false},
	 *         otherwise.
	 */
	private static <T> boolean changed(T currentItem, T newItem) {
		if (newItem == null || newItem == currentItem) {
			return false;
		} else if (currentItem == null) {
			return true;
		}
		if (currentItem.getClass().getComponentType() == null) {
			return !currentItem.equals(newItem);
		} else if (newItem.getClass().getComponentType() != null) {
			return !Arrays.deepEquals((Object[]) currentItem, (Object[]) newItem);
		} else {
			return true;
		}
	}

	/**
	 * Merge two {@link Credentials}.
	 * 
	 * @param credentials1 credentials to merge
	 * @param credentials2 credentials to merge
	 * @return merged credentials
	 * @throws IllegalArgumentException if credentials are ambiguous.
	 */
	private static Credentials merge(Credentials credentials1, Credentials credentials2) {
		PrivateKey privateKey = credentials1.getPrivateKey();
		PublicKey publicKey = credentials1.getPublicKey();
		X509Certificate[] chain = credentials1.getCertificateChain();
		Certificate[] trusts = credentials1.getTrustedCertificates();
		if (credentials2.getPrivateKey() != null) {
			if (privateKey != null && !privateKey.equals(credentials2.getPrivateKey())) {
				throw new IllegalArgumentException("Ambiguous private key!");
			}
			privateKey = credentials2.getPrivateKey();
		}
		if (credentials2.getPublicKey() != null) {
			if (publicKey != null && !publicKey.equals(credentials2.getPublicKey())) {
				throw new IllegalArgumentException("Ambiguous public key!");
			}
			publicKey = credentials2.getPublicKey();
		}
		if (credentials2.getCertificateChain() != null) {
			if (chain != null && !Arrays.deepEquals(chain, credentials2.getCertificateChain())) {
				throw new IllegalArgumentException("Ambiguous chain!");
			}
			chain = credentials2.getCertificateChain();
		}
		if (credentials2.getTrustedCertificates() != null) {
			if (trusts != null && !Arrays.deepEquals(trusts, credentials2.getTrustedCertificates())) {
				throw new IllegalArgumentException("Ambiguous trusts!");
			}
			trusts = credentials2.getTrustedCertificates();
		}
		if (privateKey == null && publicKey == null) {
			return new Credentials(trusts);
		} else {
			return new Credentials(privateKey, publicKey, chain);
		}
	}

	/**
	 * Load credentials and create monitor to check for changes.
	 * 
	 * @param name1 name 1 for monitoring.
	 * @param name2 name 2 for monitoring. May be {@code null}.
	 * @param password64 base64 encoded password of credentials. {@code null} to
	 *            use {@link #load(String, String)} instead of
	 *            {@link #load(String, String, SecretKey)}.
	 * @param createMonitor {@code true} to create a monitor, {@code false}, if
	 *            not.
	 * @return loaded credentials.
	 */
	public Credentials loadAndCreateMonitor(String name1, String name2, String password64, boolean createMonitor) {
		if (password64 != null) {
			byte[] secret = StringUtil.base64ToByteArray(password64);
			SecretKey key = SecretUtil.create(secret, "PW");
			Bytes.clear(secret);
			load(name1, name2, key);
			if (createMonitor) {
				createMonitor(name1, name2, key);
			}
			SecretUtil.destroy(key);
			LOGGER.info("{}loaded encrypted stores {}, {}", getTag(), name1, name2);
		} else {
			load(name1, name2);
			if (createMonitor) {
				createMonitor(name1, name2, null);
			}
			LOGGER.info("{}loaded stores {}, {}", getTag(), name1, name2);
		}
		return currentCredentials;
	}

	/**
	 * Get currently loaded credentials.
	 * 
	 * @return current credentials
	 */
	public Credentials getCredentials() {
		return currentCredentials;
	}

	@Override
	public void destroy() throws DestroyFailedException {
		currentCredentials.destroy();
		destroyed = true;
	}

	@Override
	public boolean isDestroyed() {
		return destroyed;
	}

	/**
	 * Observer for new credentials
	 */
	public interface Observer {

		/**
		 * Called, when new credentials are applied.
		 * 
		 * @param newCredentials the new credentials.
		 */
		void update(Credentials newCredentials);
	}
}
