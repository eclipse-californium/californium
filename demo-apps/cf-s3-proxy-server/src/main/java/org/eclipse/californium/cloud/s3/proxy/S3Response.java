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
import java.util.Map;

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
	 * Content length.
	 */
	private final Long contentLength;
	/**
	 * Timestamp.
	 */
	private final Long timestamp;
	/**
	 * Map of meta data.
	 */
	private final Map<String, String> meta;

	/**
	 * Creates S3 response.
	 * 
	 * @param httpStatusCode http status code
	 * @param content content as string
	 * @param contentAsStream content as input stream
	 * @param contentType content type
	 * @param contentLength content length
	 * @param timestamp timestamp
	 * @param meta map of meta data
	 */
	public S3Response(int httpStatusCode, String content, InputStream contentAsStream, String contentType,
			Long contentLength, Long timestamp, Map<String, String> meta) {
		this.httpStatusCode = httpStatusCode;
		this.content = content;
		this.contentAsStream = contentAsStream;
		this.contentType = contentType;
		this.contentLength = contentLength;
		this.timestamp = timestamp;
		this.meta = meta;
	}

	/**
	 * Gets http status code.
	 * 
	 * @return http status code.
	 */
	public int getHttpStatusCode() {
		return httpStatusCode;
	}

	/**
	 * Gets content.
	 * 
	 * @return content
	 */
	public String getContent() {
		return content;
	}

	/**
	 * Gets content as stream.
	 * 
	 * @return content as stream
	 */
	public InputStream getContentAsStream() {
		return contentAsStream;
	}

	/**
	 * Gets content type.
	 * 
	 * @return content type
	 */
	public String getContentType() {
		return contentType;
	}

	/**
	 * Gets content length.
	 * 
	 * @return content length
	 */
	public Long getContentLength() {
		return contentLength;
	}

	/**
	 * Gets timestamp of last update.
	 * 
	 * @return timestamp of last update
	 */
	public Long getTimestamp() {
		return timestamp;
	}

	/**
	 * Gets map of meta data.
	 * 
	 * @return map of meta data.
	 */
	public Map<String, String> getMetadata() {
		return meta;
	}

	/**
	 * Creates S3 response builder.
	 * 
	 * @return created builder
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Creates S3 response builder from S3 response.
	 * 
	 * @param response S3-response.
	 * @return created builder
	 */
	public static Builder builder(S3Response response) {
		return new Builder(response);
	}

	/**
	 * S3 response builder.
	 */
	public static class Builder {

		/**
		 * Http status code.
		 */
		public int httpStatusCode;
		/**
		 * Content.
		 */
		protected String content;
		/**
		 * Content as stream.
		 */
		protected InputStream contentAsStream;
		/**
		 * Content type.
		 */
		protected String contentType;
		/**
		 * Content length.
		 */
		protected Long contentLength;
		/**
		 * Timestamp.
		 */
		protected Long timestamp;
		/**
		 * Map of meta data.
		 */
		protected Map<String, String> meta;

		/**
		 * Create S3 response builder.
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
			this.contentLength = response.contentLength;
			this.timestamp = response.timestamp;
			this.meta = response.meta;
		}

		/**
		 * Sets http status code.
		 * 
		 * @param httpStatusCode http status code
		 * @return builder for command chaining
		 */
		public Builder httpStatusCode(int httpStatusCode) {
			this.httpStatusCode = httpStatusCode;
			return this;
		}

		/**
		 * Sets content.
		 * 
		 * @param content content.
		 * @return builder for command chaining
		 */
		public Builder content(String content) {
			this.content = content;
			return this;
		}

		/**
		 * Sets content.
		 * 
		 * @param content content as stream.
		 * @return builder for command chaining
		 */
		public Builder content(InputStream content) {
			this.contentAsStream = content;
			return this;
		}

		/**
		 * Sets content type.
		 * 
		 * @param contentType content type.
		 * @return builder for command chaining
		 */
		public Builder contentType(String contentType) {
			this.contentType = contentType;
			return this;
		}

		/**
		 * Sets content length.
		 * 
		 * @param contentLength content length.
		 * @return builder for command chaining
		 */
		public Builder contentLength(Long contentLength) {
			this.contentLength = contentLength;
			return this;
		}

		/**
		 * Sets timestamp.
		 * 
		 * @param timestamp timestamp.
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

		/**
		 * Creates S3 response.
		 * 
		 * @return S3 response
		 */
		public S3Response build() {
			return new S3Response(httpStatusCode, content, contentAsStream, contentType, contentLength, timestamp,
					meta);
		}
	}
}
