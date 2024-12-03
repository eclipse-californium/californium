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
package org.eclipse.californium.cloud.s3.proxy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Semaphore;
import java.util.function.Consumer;

import javax.crypto.SecretKey;

import org.eclipse.californium.cloud.s3.proxy.S3Request.CacheMode;
import org.eclipse.californium.cloud.util.AppendingResourceParser;
import org.eclipse.californium.cloud.util.ResourceChangedHandler;
import org.eclipse.californium.cloud.util.ResourceParser;
import org.eclipse.californium.cloud.util.ResourceStore;
import org.eclipse.californium.cloud.util.ResultConsumer;
import org.eclipse.californium.cloud.util.ResultConsumer.ResultCode;
import org.eclipse.californium.elements.util.SystemResourceMonitors.SystemResourceCheckReady;
import org.eclipse.californium.elements.util.SystemResourceMonitors.SystemResourceMonitor;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * S3 based resource store with optional automatic reload function.
 * 
 * @since 3.12
 */
public class S3ResourceStore<T extends ResourceParser<T>> extends ResourceStore<T> {

	private static final Logger LOGGER = LoggerFactory.getLogger(S3ResourceStore.class);

	/**
	 * S3 client to load resources.
	 */
	private final S3ProxyClient s3Client;

	/**
	 * Creates S3 based resource store.
	 * 
	 * @param factory factory instance of {@link ResourceParser}.
	 * @param s3Client s3Client to read resource from S3
	 * @throws NullPointerException if provided factory is {@code null}
	 */
	public S3ResourceStore(T factory, S3ProxyClient s3Client) {
		super(factory);
		this.s3Client = s3Client;
		LOGGER.debug("S3-resource");
	}

	/**
	 * Creates resource monitor for automatic resource reloading.
	 * 
	 * @param key s3 key of resource store.
	 * @param password password of resource. {@code null} to use
	 *            {@link #load(String)} instead of
	 *            {@link #load(String, SecretKey)}.
	 * @return created resource monitor
	 */
	@Override
	public SystemResourceMonitor createMonitor(final String key, final SecretKey password) {
		if (key != null) {
			monitor = new AppendS3Monitor(key, password);
		} else {
			monitor = null;
		}
		return monitor;
	}

	@Override
	public S3ResourceStore<T> load(final String key) {
		load(key, (in) -> {
			if (in != null) {
				super.load(in);
				LOGGER.info("S3-resource {} loaded.", key);
			}
		}, true);
		return this;
	}

	@Override
	public S3ResourceStore<T> load(final String key, SecretKey password) {
		final SecretKey s3Password = SecretUtil.create(password);
		load(key, (in) -> {
			if (in != null) {
				super.load(in, s3Password);
				SecretUtil.destroy(s3Password);
				LOGGER.info("S3-encrypted-resource {} loaded.", key);
			}
		}, true);
		return this;
	}

	/**
	 * Loads resource from S3.
	 * 
	 * @param key s3 key of resource
	 * @param handler handler for loaded stream
	 * @param wait {@code true} wait until loaded, {@code false}, don't wait.
	 */
	public void load(final String key, final Consumer<InputStream> handler, boolean wait) {
		final CountDownLatch ready = new CountDownLatch(1);
		s3Client.load(S3Request.builder().key(key).build(), (response) -> {
			try {
				handler.accept(response.getContentAsStream());
			} finally {
				ready.countDown();
			}
		});
		if (wait) {
			try {
				ready.await();
			} catch (InterruptedException e) {
			}
		}
	}

	/**
	 * {@link SystemResourceMonitor} with {@link ResourceChangedHandler}.
	 * <p>
	 * Monitors S3 resource and writes changes to S3.
	 */
	public class AppendS3Monitor implements SystemResourceMonitor, ResourceChangedHandler {

		private final String key;
		private final SecretKey password;

		public AppendS3Monitor(final String key, final SecretKey password) {
			this.key = key;
			this.password = SecretUtil.create(password);
		}

		@Override
		public void checkForUpdate(SystemResourceCheckReady ready) {
			Semaphore semaphore = getSemaphore();
			if (semaphore.tryAcquire()) {
				LOGGER.debug("S3-resource {} check ...", key);
				try {
					load(key, (in) -> {
						if (in != null) {
							if (password != null) {
								load(in, password);
								LOGGER.info("S3-encrypted-resource {} loaded.", key);
							} else {
								load(in);
								LOGGER.info("S3-resource {} loaded.", key);
							}
						}
						ready.ready(false);
						getSemaphore().release();
					}, false);
					semaphore = null;
				} finally {
					if (semaphore != null) {
						semaphore.release();
					}
				}
			} else {
				// schedule next check
				ready.ready(false);
			}
		}

		@Override
		public void changed(ResultConsumer response) {
			T currentResource = getResource();
			String tag = getTag();
			if (!(currentResource instanceof AppendingResourceParser)) {
				response.results(ResultCode.SERVER_ERROR, "no AppendResourceParser.");
				return;
			}
			final AppendingResourceParser<?> resource = (AppendingResourceParser<?>) currentResource;

			s3Client.load(S3Request.builder().key(key).cacheMode(CacheMode.FORCE).build(), (load) -> {
				try {
					if (load != null) {
						int result = 0;
						InputStream in = load.getContentAsStream();
						ByteArrayOutputStream out = new ByteArrayOutputStream();
						if (password != null) {
							byte[] seed = encryptionUtility.readSeed(in);
							try (InputStream inEncrypted = encryptionUtility.prepare(seed, in, password)) {
								try (OutputStream outEncrypted = encryptionUtility.prepare(seed, out, password)) {
									LOGGER.info("{}append encrypted {}.", tag, key);
									result = appendNewEntries(resource, inEncrypted, outEncrypted);
								}
							} catch (IOException e) {
								LOGGER.warn("{}append encrypted {}:", tag, key, e);
								throw e;
							}
						} else {
							try {
								LOGGER.info("{}append {}.", tag, key);
								result = appendNewEntries(resource, in, out);
							} catch (IOException e) {
								LOGGER.warn("{}append {}:", tag, key, e);
								throw e;
							}
						}
						if (result > 0) {
							S3PutRequest.Builder builder = S3PutRequest.builder();
							builder.key(key);
							builder.content(out.toByteArray());
							builder.contentType(load.getContentType());
							final int r = result;
							s3Client.save(builder.build(), (save) -> {
								if (save != null && save.getHttpStatusCode() < 300) {
									resource.clearNewEntries();
									response.results(ResultCode.SUCCESS, "successfully added " + r + " new entries.");
								} else {
									response.results(ResultCode.SERVER_ERROR, "failed to save new entries to S3.");
								}
							});
						} else {
							response.results(ResultCode.SERVER_ERROR, "failed to append new entries.");
						}
					} else {
						LOGGER.info("{}read {} failed!", tag, key);
						response.results(ResultCode.SERVER_ERROR, "failed to read old entries.");
					}
				} catch (IOException e) {
					LOGGER.info("{}read {} failed!", tag, key, e);
					response.results(ResultCode.SERVER_ERROR, "failed to save new entries. " + e.getMessage());
				}
			});
		}
	}

}
