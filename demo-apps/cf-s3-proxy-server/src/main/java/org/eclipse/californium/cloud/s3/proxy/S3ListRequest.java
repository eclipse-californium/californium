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
 * S3 list request.
 * 
 * @since 3.13
 */
public class S3ListRequest extends S3Request {

	/**
	 * S3 delimiter.
	 */
	private final String delimiter;
	/**
	 * Key to start list after.
	 */
	private final String startAfter;
	/**
	 * Maximum number of keys to fetch.
	 */
	private final Integer maxKeys;

	/**
	 * Creates S3 list request.
	 * 
	 * @param key S3 key.
	 * @param delimiter content for S3 PUT requests
	 * @param startAfter content type for S3 PUT requests
	 * @param maxKeys maximum number of keys to fetch
	 * @param redirect redirect info, if S3 bucket is temporary redirected after
	 *            creating.
	 */
	public S3ListRequest(String key, String delimiter, String startAfter, Integer maxKeys, Redirect redirect) {
		super(key, redirect, CacheMode.NONE);
		this.delimiter = delimiter;
		this.startAfter = startAfter;
		this.maxKeys = maxKeys;
	}

	/**
	 * Gets delimiter for S3 LIST.
	 * 
	 * @return delimiter for S3 LIST.
	 */
	public String getDelimiter() {
		return delimiter;
	}

	/**
	 * Gets key to start S3 LIST after.
	 * 
	 * @return key to start S3 LIST after.
	 */
	public String getStartAfter() {
		return startAfter;
	}

	/**
	 * Gets maximum number of keys to fetch.
	 * 
	 * @return maximum number of keys to fetch.
	 */
	public Integer getMaximumKeys() {
		return maxKeys;
	}

	/**
	 * Creates S3 LIST request builder.
	 * 
	 * @return created builder
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Creates S3 LIST request builder from S3 LIST request.
	 * 
	 * @param request S3 LIST request.
	 * @return created builder
	 */
	public static Builder builder(S3ListRequest request) {
		return new Builder(request);
	}

	/**
	 * S3 LIST request builder.
	 */
	public static class Builder extends S3Request.Builder {

		/**
		 * S3 delimiter.
		 */
		protected String delimiter;
		/**
		 * Key to start list after.
		 */
		protected String startAfter;
		/**
		 * Maximum number of keys to fetch.
		 */
		protected Integer maxKeys;

		/**
		 * Creates S3 LIST request builder.
		 */
		protected Builder() {
		}

		/**
		 * Creates builder from S3 LIST request.
		 * 
		 * @param request S3 LIST request
		 */
		protected Builder(S3ListRequest request) {
			super(request);
			this.delimiter = request.delimiter;
			this.startAfter = request.startAfter;
			this.maxKeys = request.maxKeys;
		}

		@Override
		public Builder key(String key) {
			super.key(key);
			return this;
		}

		/**
		 * Sets delimiter for S3 LIST request.
		 * 
		 * @param delimiter delimiter
		 * @return builder for command chaining
		 */
		public Builder delimiter(String delimiter) {
			this.delimiter = delimiter;
			return this;
		}

		/**
		 * Sets key to start S3 LIST after.
		 * 
		 * @param startAfter key to start list after
		 * @return builder for command chaining
		 */
		public Builder startAfter(String startAfter) {
			this.startAfter = startAfter;
			return this;
		}

		/**
		 * Sets maximum number of keys to fetch.
		 * 
		 * @param maxKeys maximum number of keys to fetch
		 * @return builder for command chaining
		 */
		public Builder maxKeys(Integer maxKeys) {
			this.maxKeys = maxKeys;
			return this;
		}

		@Override
		public Builder redirect(Redirect redirect) {
			super.redirect(redirect);
			return this;
		}

		/**
		 * Creates S3 LIST request.
		 * 
		 * @return S3 LIST request
		 */
		public S3ListRequest build() {
			return new S3ListRequest(key, delimiter, startAfter, maxKeys, redirect);
		}
	}
}
