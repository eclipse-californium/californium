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

import java.io.InputStream;
import java.util.concurrent.CountDownLatch;
import java.util.function.Consumer;

import javax.crypto.SecretKey;

import org.eclipse.californium.cloud.util.ResourceParser;
import org.eclipse.californium.cloud.util.ResourceStore;
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
	 * Create S3 based resource store.
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
	 * Create resource monitor for automatic resource reloading.
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
			monitor = new SystemResourceMonitor() {

				SecretKey s3Password = SecretUtil.create(password);

				@Override
				public void checkForUpdate(SystemResourceCheckReady ready) {
					LOGGER.debug("S3-resource {} check ...", key);
					load(key, (in) -> {
						if (in != null) {
							if (s3Password != null) {
								load(in, s3Password);
								LOGGER.info("S3-encrypted-resource {} loaded.", key);
							} else {
								load(in);
								LOGGER.info("S3-resource {} loaded.", key);
							}
						}
						ready.ready(false);
					}, false);
				}
			};
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
	 * Load resource from S3.
	 * 
	 * @param key s3 key of resource
	 * @param handler handler for loaded stream
	 * @param wait {@code true} wait until loaded, {@code false}, don't wait.
	 */
	public void load(final String key, final Consumer<InputStream> handler, boolean wait) {
		final CountDownLatch ready = new CountDownLatch(1);
		s3Client.load(S3Request.builder().key(key).build(), (in) -> {
			try {
				handler.accept(in);
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
}
