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

import java.net.URI;

/**
 * S3 request.
 * 
 * @since 3.12
 */
public class S3Request {

	/**
	 * Key.
	 */
	private final String key;
	/**
	 * Redirect info, if S3 bucket is temporary redirected after creating.
	 */
	private final Redirect redirect;

	/**
	 * Create S3 request.
	 * 
	 * @param key S3 key
	 * @param redirect redirect info, if S3 bucket is temporary redirected after
	 *            creating. Otherwise {@code null}.
	 */
	public S3Request(String key, Redirect redirect) {
		this.key = key;
		this.redirect = redirect;
	}

	/**
	 * Get key.
	 * 
	 * @return key
	 */
	public String getKey() {
		return key;
	}

	/**
	 * Get redirect info.
	 * 
	 * Used, if S3 bucket is temporary redirected after creating. Otherwise
	 * {@code null}.
	 * 
	 * @return redirect info, if S3 bucket is temporary redirected after
	 *         creating. Otherwise {@code null}.
	 */
	public Redirect getRedirect() {
		return redirect;
	}

	/**
	 * Redirect info.
	 * 
	 * Info if S3 bucket is temporary redirected after creating.
	 */
	public static class Redirect {

		/**
		 * Redirected endpoint.
		 */
		public final URI endpoint;
		/**
		 * Redirected external https endpoint.
		 */
		public final String externalEndpoint;

		/**
		 * Create redirect info.
		 * 
		 * @param endpoint redirected endpoint
		 * @param externalEndpoint Redirected external https endpoint
		 */
		public Redirect(URI endpoint, String externalEndpoint) {
			this.endpoint = endpoint;
			this.externalEndpoint = externalEndpoint;
		}

		@Override
		public String toString() {
			return externalEndpoint;
		}
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
	public static Builder builder(S3Request request) {
		return new Builder(request);
	}

	/**
	 * S3-request-builder.
	 */
	public static class Builder {

		/**
		 * Key.
		 */
		protected String key;
		/**
		 * Redirect info, if S3 bucket is temporary redirected after creating.
		 */
		protected Redirect redirect;

		/**
		 * Create S3-request-builder.
		 */
		protected Builder() {
		}

		/**
		 * Create S3-request-builder from S3-request.
		 * 
		 * @param request S3-request.
		 */
		protected Builder(S3Request request) {
			this.key = request.key;
			this.redirect = request.redirect;
		}

		/**
		 * Set S3 key.
		 * 
		 * @param key S3 key
		 * @return builder for command chaining
		 */
		public Builder key(String key) {
			this.key = key;
			return this;
		}

		/**
		 * Set redirect info.
		 * 
		 * @param redirect redirect info, if S3 bucket is temporary redirected
		 *            after creating.
		 * @return builder for command chaining
		 */
		public Builder redirect(Redirect redirect) {
			this.redirect = redirect;
			return this;
		}

		/**
		 * Creates S3-request.
		 * 
		 * @return S3-request
		 */
		public S3Request build() {
			return new S3Request(key, redirect);
		}
	}
}
