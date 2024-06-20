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
 * S3 PUT request.
 * 
 * @since 3.13
 */
public class S3PutRequest extends S3Request {

	/**
	 * Content for S3 PUT requests.
	 */
	private final byte[] content;
	/**
	 * Content type for S3 PUT requests.
	 */
	private final String contentType;
	/**
	 * Timestamp for S3 PUT request.
	 */
	private final Long timestamp;

	/**
	 * Create S3 PUT request.
	 * 
	 * @param key S3 key.
	 * @param content content for S3 PUT requests
	 * @param contentType content type for S3 PUT requests
	 * @param timestamp timestamp for S3 PUT requests
	 * @param redirect redirect info, if S3 bucket is temporary redirected after
	 *            creating.
	 * @param force force mode. {@code true} to not use ETAGs.
	 */
	public S3PutRequest(String key, byte[] content, String contentType, Long timestamp, Redirect redirect,
			boolean force) {
		super(key, redirect, force);
		this.content = content;
		this.contentType = contentType;
		this.timestamp = timestamp;
	}

	/**
	 * Get content for S3 PUT.
	 * 
	 * @return content for S3 PUT.
	 */
	public byte[] getContent() {
		return content;
	}

	/**
	 * Get content type for S3 PUT.
	 * 
	 * @return content type for S3 PUT.
	 */
	public String getContentType() {
		return contentType;
	}

	/**
	 * Get timestamp for S3 PUT.
	 * 
	 * @return timestamp for S3 PUT.
	 */
	public Long getTimestamp() {
		return timestamp;
	}

	/**
	 * Create S3 PUT request builder.
	 * 
	 * @return created builder
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Create S3 PUT request builder from S3 PUT request.
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
		 * Timestamp for S3 PUT request.
		 */
		protected Long timestamp;

		/**
		 * Create S3 PUT request builder.
		 */
		protected Builder() {
		}

		/**
		 * Create builder from S3 PUT request.
		 * 
		 * @param request S3 PUT request
		 */
		protected Builder(S3PutRequest request) {
			super(request);
			this.content = request.content;
			this.contentType = request.contentType;
			this.timestamp = request.timestamp;
		}

		@Override
		public Builder key(String key) {
			super.key(key);
			return this;
		}

		/**
		 * Set content for S3 PUT request.
		 * 
		 * @param content content
		 * @return builder for command chaining
		 */
		public Builder content(byte[] content) {
			this.content = content;
			return this;
		}

		/**
		 * Set content-type for S3 PUT request.
		 * 
		 * @param contentType content-type for PUT request
		 * @return builder for command chaining
		 */
		public Builder contentType(String contentType) {
			this.contentType = contentType;
			return this;
		}

		/**
		 * Set timestamp for S3 PUT request.
		 * 
		 * @param timestamp timestamp
		 * @return builder for command chaining
		 */
		public Builder timestamp(Long timestamp) {
			this.timestamp = timestamp;
			return this;
		}

		@Override
		public Builder redirect(Redirect redirect) {
			super.redirect(redirect);
			return this;
		}

		/**
		 * Creates S3 PUT request.
		 * 
		 * @return S3 PUT request
		 */
		public S3PutRequest build() {
			return new S3PutRequest(key, content, contentType, timestamp, redirect, force);
		}
	}
}
