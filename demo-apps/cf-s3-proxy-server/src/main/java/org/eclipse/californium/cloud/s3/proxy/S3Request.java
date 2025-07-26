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

/**
 * S3 request.
 * 
 * @since 3.12
 */
public class S3Request extends S3BaseRequest {

	/**
	 * Cache/ETAG mode.
	 * 
	 * @since 3.13
	 */
	public enum CacheMode {
		/**
		 * Don't use ETAG.
		 */
		NONE,
		/**
		 * Use ETAG and cache response.
		 */
		CACHE,
		/**
		 * Force read and cache response.
		 */
		FORCE
	}

	/**
	 * Key.
	 */
	private final String key;
	/**
	 * eTag.
	 * 
	 * @since 4.0
	 */
	private final String etag;
	/**
	 * Cache/ETAG mode.
	 * 
	 * @since 3.13
	 */
	private final CacheMode cacheMode;

	/**
	 * Creates S3 request.
	 * 
	 * @param key S3 key
	 * @param etag S3 etag
	 * @param redirect redirect info, if S3 bucket is temporary redirected after
	 *            creating. Otherwise {@code null}.
	 * @param cacheMode cache mode.
	 * @since 4.0 (added etag)
	 */
	public S3Request(String key, String etag, Redirect redirect, CacheMode cacheMode) {
		super(redirect);
		this.key = key;
		this.cacheMode = cacheMode;
		this.etag = etag;
	}

	/**
	 * Gets key.
	 * 
	 * @return key
	 */
	public String getKey() {
		return key;
	}

	/**
	 * Gets etag.
	 * 
	 * @return etag
	 * @since 4.0
	 */
	public String getEtag() {
		return etag;
	}

	/**
	 * Gets cache/ETAG mode.
	 * 
	 * @return cache/ETAG mode.
	 * @since 3.13
	 */
	public CacheMode getCacheMode() {
		return cacheMode;
	}

	/**
	 * Creates S3-request-builder.
	 * 
	 * @return created builder
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Creates S3 request builder from S3-request.
	 * 
	 * @param request S3-request.
	 * @return created builder
	 */
	public static Builder builder(S3Request request) {
		return new Builder(request);
	}

	/**
	 * S3-request-builder.
	 */
	public static class Builder extends S3BaseRequest.Builder {

		/**
		 * Key.
		 */
		protected String key;
		/**
		 * Etag.
		 * 
		 * @since 4.0
		 */
		protected String etag;
		/**
		 * Cache/ETAG mode.
		 * 
		 * @since 3.13
		 */
		protected CacheMode cacheMode = CacheMode.CACHE;

		/**
		 * Creates S3 request builder.
		 */
		protected Builder() {
		}

		/**
		 * Create S3 request builder from S3-request.
		 * 
		 * @param request S3-request.
		 */
		protected Builder(S3Request request) {
			super(request);
			this.key = request.key;
			this.etag = request.etag;
			this.cacheMode = request.cacheMode;
		}

		/**
		 * Sets S3 key.
		 * 
		 * @param key S3 key
		 * @return builder for command chaining
		 */
		public Builder key(String key) {
			this.key = key;
			return this;
		}

		/**
		 * Sets S3 etag
		 * 
		 * @param etag S3 etag
		 * @return builder for command chaining
		 * @since 4.0
		 */
		public Builder etag(String etag) {
			this.etag = etag;
			return this;
		}

		/**
		 * Sets cache/ETAG mode.
		 * 
		 * @param cacheMode cache/ETAG modes.
		 * @return builder for command chaining
		 * @since 3.13
		 */
		public Builder cacheMode(CacheMode cacheMode) {
			this.cacheMode = cacheMode;
			return this;
		}

		@Override
		public Builder redirect(Redirect redirect) {
			super.redirect(redirect);
			return this;
		}

		/**
		 * Creates S3-request.
		 * 
		 * @return S3-request
		 */
		public S3Request build() {
			return new S3Request(key, etag, redirect, cacheMode);
		}
	}
}
