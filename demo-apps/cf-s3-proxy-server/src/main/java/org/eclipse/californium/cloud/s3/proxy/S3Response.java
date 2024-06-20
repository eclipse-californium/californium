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

/**
 * S3 response.
 * 
 * @since 3.13
 */
public class S3Response {

	/**
	 * Http status code.
	 */
	private final int httpStatusCode;
	/**
	 * Content.
	 */
	private final String content;
	/**
	 * Content as stream.
	 */
	private final InputStream contentAsStream;
	/**
	 * Content type.
	 */
	private final String contentType;
	/**
	 * Timestamp.
	 */
	private final Long timestamp;

	/**
	 * Create S3 response.
	 * 
	 * @param httpStatusCode http status code
	 * @param content content as string
	 * @param contentAsStream content as input stream
	 * @param contentType content type
	 * @param timestamp timestamp
	 */
	public S3Response(int httpStatusCode, String content, InputStream contentAsStream, String contentType,
			Long timestamp) {
		this.httpStatusCode = httpStatusCode;
		this.content = content;
		this.contentAsStream = contentAsStream;
		this.contentType = contentType;
		this.timestamp = timestamp;
	}

	/**
	 * Get http status code.
	 * 
	 * @return http status code.
	 */
	public int getHttpStatusCode() {
		return httpStatusCode;
	}

	/**
	 * Get content.
	 * 
	 * @return content
	 */
	public String getContent() {
		return content;
	}

	/**
	 * Get content as stream.
	 * 
	 * @return content as stream
	 */
	public InputStream getContentAsStream() {
		return contentAsStream;
	}

	/**
	 * Get content type.
	 * 
	 * @return content type
	 */
	public String getContentType() {
		return contentType;
	}

	/**
	 * Get content type.
	 * 
	 * @return content type
	 */
	public Long getTimestamp() {
		return timestamp;
	}

	/**
	 * Create S3-request-builder.
	 * 
	 * @return created builder
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Create S3-request-builder from S3-request.
	 * 
	 * @param request S3-request.
	 * @return created builder
	 */
	public static Builder builder(S3Response request) {
		return new Builder(request);
	}

	/**
	 * S3-request-builder.
	 */
	public static class Builder {

		/**
		 * Http status code.
		 */
		public int httpStatusCode;
		/**
		 * Content.
		 */
		private String content;
		/**
		 * Content as stream.
		 */
		private InputStream contentAsStream;
		/**
		 * Content type.
		 */
		private String contentType;
		/**
		 * Timestamp.
		 */
		private Long timestamp;

		/**
		 * Create S3-request-builder.
		 */
		protected Builder() {
		}

		/**
		 * Create S3 response builder from S3 response.
		 * 
		 * @param response S3-response.
		 */
		protected Builder(S3Response response) {
			this.httpStatusCode = response.httpStatusCode;
			this.content = response.content;
			this.contentAsStream = response.contentAsStream;
			this.contentType = response.contentType;
			this.timestamp = response.timestamp;
		}

		/**
		 * Set http status code.
		 * 
		 * @param httpStatusCode http status code
		 * @return builder for command chaining
		 */
		public Builder httpStatusCode(int httpStatusCode) {
			this.httpStatusCode = httpStatusCode;
			return this;
		}

		/**
		 * Set content.
		 * 
		 * @param content content.
		 * @return builder for command chaining
		 */
		public Builder content(String content) {
			this.content = content;
			return this;
		}

		/**
		 * Set content.
		 * 
		 * @param content content as stream.
		 * @return builder for command chaining
		 */
		public Builder content(InputStream content) {
			this.contentAsStream = content;
			return this;
		}

		/**
		 * Set content type.
		 * 
		 * @param contentType content type.
		 * @return builder for command chaining
		 */
		public Builder contentType(String contentType) {
			this.contentType = contentType;
			return this;
		}

		/**
		 * Set timestamp.
		 * 
		 * @param timestamp timestamp.
		 * @return builder for command chaining
		 */
		public Builder timestamp(Long timestamp) {
			this.timestamp = timestamp;
			return this;
		}

		/**
		 * Creates S3 response.
		 * 
		 * @return S3 response
		 */
		public S3Response build() {
			return new S3Response(httpStatusCode, content, contentAsStream, contentType, timestamp);
		}
	}
}
