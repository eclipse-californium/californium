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

import java.util.HashMap;
import java.util.Map;

/**
 * S3 PUT request.
 * 
 * @since 3.13
 */
public class S3PutRequest extends S3Request {

	/**
	 * Name of time in metadata.
	 */
	public static final String METADATA_TIME = "time";

	/**
	 * Content for S3 PUT requests.
	 */
	private final byte[] content;
	/**
	 * Content type for S3 PUT requests.
	 */
	private final String contentType;
	/**
	 * Content encoding for S3 PUT requests.
	 * 
	 * @since 4.0
	 */
	private final String contentEncoding;
	/**
	 * Timestamp for S3 PUT request.
	 */
	private final Long timestamp;
	/**
	 * Map of meta data.
	 */
	private final Map<String, String> meta;

	/**
	 * Creates S3 PUT request.
	 * 
	 * @param key S3 key.
	 * @param etag S3 etag.
	 * @param content content for S3 PUT requests
	 * @param contentType content type for S3 PUT requests
	 * @param contentEncoding content encoding for S3 PUT requests
	 * @param timestamp timestamp for S3 PUT requests
	 * @param meta map of meta data
	 * @param redirect redirect info, if S3 bucket is temporary redirected after
	 *            creating.
	 * @param cacheMode cache mode.
	 * @since 4.0 (added parameter etag and contentEncoding)
	 */
	public S3PutRequest(String key, String etag, byte[] content, String contentType, String contentEncoding, Long timestamp,
			Map<String, String> meta, Redirect redirect, CacheMode cacheMode) {
		super(key, etag, redirect, cacheMode);
		this.content = content;
		this.contentType = contentType;
		this.contentEncoding = contentEncoding;
		this.timestamp = timestamp;
		this.meta = meta;
	}

	/**
	 * Gets content for S3 PUT.
	 * 
	 * @return content for S3 PUT.
	 */
	public byte[] getContent() {
		return content;
	}

	/**
	 * Gets content type for S3 PUT.
	 * 
	 * @return content type for S3 PUT.
	 */
	public String getContentType() {
		return contentType;
	}

	/**
	 * Gets content encoding for S3 PUT.
	 * 
	 * @return content encoding for S3 PUT.
	 * @since 4.0
	 */
	public String getContentEncoding() {
		return contentEncoding;
	}

	/**
	 * Gets timestamp for S3 PUT.
	 * 
	 * @return timestamp for S3 PUT.
	 */
	public Long getTimestamp() {
		return timestamp;
	}

	/**
	 * Gets metadata for S3 PUT.
	 * 
	 * @return metadata, maybe empty.
	 * @since 3.13
	 */
	public Map<String, String> getMetadata() {
		Map<String, String> meta = new HashMap<>();
		if (this.meta != null) {
			meta.putAll(this.meta);
		}
		if (timestamp != null) {
			meta.put(METADATA_TIME, Long.toString(timestamp));
		}
		return meta;
	}

	/**
	 * Creates S3 PUT request builder.
	 * 
	 * @return created builder
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Creates S3 PUT request builder from S3 PUT request.
	 * 
	 * @param request S3 PUT request.
	 * @return created builder
	 */
	public static Builder builder(S3PutRequest request) {
		return new Builder(request);
	}

	/**
	 * S3 PUT request builder.
	 */
	public static class Builder extends S3Request.Builder {

		/**
		 * Content for S3 PUT request.
		 */
		protected byte[] content;
		/**
		 * Content-type for S3 PUT request.
		 */
		protected String contentType;
		/**
		 * Content-encoding for S3 PUT request.
		 * 
		 * @since 4.0
		 */
		protected String contentEncoding;
		/**
		 * Timestamp for S3 PUT request.
		 */
		protected Long timestamp;
		/**
		 * Map of meta data.
		 */
		protected Map<String, String> meta;

		/**
		 * Creates S3 PUT request builder.
		 */
		protected Builder() {
		}

		/**
		 * Creates builder from S3 PUT request.
		 * 
		 * @param request S3 PUT request
		 */
		protected Builder(S3PutRequest request) {
			super(request);
			this.content = request.content;
			this.contentType = request.contentType;
			this.contentEncoding = request.contentEncoding;
			this.timestamp = request.timestamp;
		}

		@Override
		public Builder key(String key) {
			super.key(key);
			return this;
		}

		@Override
		public Builder etag(String etag) {
			super.etag(etag);
			return this;
		}

		/**
		 * Sets content for S3 PUT request.
		 * 
		 * @param content content
		 * @return builder for command chaining
		 */
		public Builder content(byte[] content) {
			this.content = content;
			return this;
		}

		/**
		 * Sets content-type for S3 PUT request.
		 * 
		 * @param contentType content-type for PUT request
		 * @return builder for command chaining
		 */
		public Builder contentType(String contentType) {
			this.contentType = contentType;
			return this;
		}

		/**
		 * Sets content-encoding for S3 PUT request.
		 * 
		 * @param contentEncoding content-encoding for PUT request
		 * @return builder for command chaining
		 * @since 4.0
		 */
		public Builder contentEncoding(String contentEncoding) {
			this.contentEncoding = contentEncoding;
			return this;
		}

		/**
		 * Sets timestamp for S3 PUT request.
		 * 
		 * @param timestamp timestamp
		 * @return builder for command chaining
		 */
		public Builder timestamp(Long timestamp) {
			this.timestamp = timestamp;
			return this;
		}

		/**
		 * Sets map of meta data.
		 * 
		 * @param meta map of meta data.
		 * @return builder for command chaining
		 */
		public Builder meta(Map<String, String> meta) {
			this.meta = meta;
			return this;
		}

		@Override
		public Builder redirect(Redirect redirect) {
			super.redirect(redirect);
			return this;
		}

		@Override
		public Builder cacheMode(CacheMode cacheMode) {
			super.cacheMode(cacheMode);
			return this;
		}

		/**
		 * Creates S3 PUT request.
		 * 
		 * @return S3 PUT request
		 */
		public S3PutRequest build() {
			return new S3PutRequest(key, etag, content, contentType, contentEncoding, timestamp, meta, redirect, cacheMode);
		}
	}
}
