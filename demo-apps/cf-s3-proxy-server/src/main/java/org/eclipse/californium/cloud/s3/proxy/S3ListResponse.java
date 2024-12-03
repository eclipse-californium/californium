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
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * S3 LIST response.
 * 
 * @since 3.13
 */
public class S3ListResponse extends S3Response {

	/**
	 * List of prefixes (directories).
	 */
	private final List<String> prefixes;
	/**
	 * List of objects.
	 */
	private final List<S3Object> objects;

	/**
	 * Creates S3 LIST response.
	 * 
	 * @param prefixes list of prefixes (directories).
	 * @param objects list of objects.
	 */
	public S3ListResponse(List<String> prefixes, List<S3Object> objects) {
		super(200, null, null, null, null, null, null);
		this.prefixes = prefixes;
		this.objects = objects;
	}

	/**
	 * Creates S3 LIST response.
	 * 
	 * @param httpStatusCode http status code
	 * @param content content as string
	 * @param contentAsStream content as input stream
	 * @param contentType content type
	 * @param contentLength content length
	 * @param timestamp timestamp
	 * @param meta map of meta data
	 */
	public S3ListResponse(int httpStatusCode, String content, InputStream contentAsStream, String contentType,
			Long contentLength, Long timestamp, Map<String, String> meta) {
		super(httpStatusCode, content, contentAsStream, contentType, contentLength, timestamp, meta);
		this.prefixes = Collections.emptyList();
		this.objects = Collections.emptyList();
	}

	/**
	 * Gets list of prefixes.
	 * 
	 * @return list of prefixes.
	 */
	public List<String> getPrefixes() {
		return prefixes;
	}

	/**
	 * Gets list of objects.
	 * 
	 * @return list of objects.
	 */
	public List<S3Object> getObjects() {
		return objects;
	}

	/**
	 * Creates S3 LIST response builder.
	 * 
	 * @return created builder
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * S3 LIST response builder.
	 */
	public static class Builder extends S3Response.Builder {

		/**
		 * List of prefixes (directories).
		 */
		protected List<String> prefixes;
		/**
		 * List of objects.
		 */
		protected List<S3Object> objects;

		/**
		 * Create S3 LIST response builder.
		 */
		protected Builder() {
		}

		@Override
		public Builder httpStatusCode(int httpStatusCode) {
			super.httpStatusCode(httpStatusCode);
			return this;
		}

		@Override
		public Builder content(String content) {
			super.content(content);
			return this;
		}

		@Override
		public Builder content(InputStream content) {
			super.content(content);
			return this;
		}

		@Override
		public Builder contentType(String contentType) {
			super.contentType(contentType);
			return this;
		}

		@Override
		public Builder contentLength(Long contentLength) {
			super.contentLength(contentLength);
			return this;
		}

		@Override
		public Builder timestamp(Long timestamp) {
			super.timestamp(timestamp);
			return this;
		}

		@Override
		public Builder meta(Map<String, String> meta) {
			super.meta(meta);
			return this;
		}

		/**
		 * Sets list of prefixes.
		 * 
		 * @param prefixes list of prefixes (directories).
		 * @return builder for command chaining
		 */
		public Builder prefixes(List<String> prefixes) {
			this.prefixes = prefixes;
			return this;
		}

		/**
		 * Sets list of objects.
		 * 
		 * @param objects list of objects.
		 * @return builder for command chaining
		 */
		public Builder objects(List<S3Object> objects) {
			this.objects = objects;
			return this;
		}

		/**
		 * Creates S3 LIST response.
		 * 
		 * @return S3 LIST response
		 */
		public S3ListResponse build() {
			if (prefixes != null && objects != null) {
				return new S3ListResponse(prefixes, objects);
			} else {
				return new S3ListResponse(httpStatusCode, content, contentAsStream, contentType, contentLength,
						timestamp, meta);
			}
		}
	}

	/**
	 * S3 object.
	 */
	public static class S3Object implements Comparable<S3Object> {

		/**
		 * S3 resource key.
		 */
		public final String key;
		/**
		 * S3 resource ETAG.
		 */
		public final String etag;

		/**
		 * Creates S3 object.
		 * 
		 * @param key S3 resource key
		 * @param etag S3 resource ETAG
		 */
		public S3Object(String key, String etag) {
			this.key = key;
			this.etag = etag;
		}

		@Override
		public int hashCode() {
			return key.hashCode();
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			S3Object other = (S3Object) obj;
			if (key == null) {
				if (other.key != null)
					return false;
			} else if (!key.equals(other.key))
				return false;
			if (etag == null) {
				if (other.etag != null)
					return false;
			} else if (!etag.equals(other.etag))
				return false;
			return true;
		}

		@Override
		public int compareTo(S3Object other) {
			int res = key.compareTo(other.key);
			if (res == 0) {
				res = etag.compareTo(other.etag);
			}
			return res;
		}

	}
}
