/********************************************************************************
 * Copyright (c) 2025 Contributors to the Eclipse Foundation
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
 * S3 base request.
 * 
 * @since 4.0
 */
public class S3BaseRequest {

	/**
	 * Redirect info, if S3 bucket is temporary redirected after creating.
	 */
	private final Redirect redirect;

	/**
	 * Creates S3 base request.
	 * 
	 * @param redirect redirect info, if S3 bucket is temporary redirected after
	 *            creating. Otherwise {@code null}.
	 */
	public S3BaseRequest(Redirect redirect) {
		this.redirect = redirect;
	}

	/**
	 * Gets redirect info.
	 * <p>
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
	 * <p>
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
		 * Creates redirect info.
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
	 * Creates S3 base request builder.
	 * 
	 * @return created builder
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Creates S3 base request builder from S3 base request.
	 * 
	 * @param request S3 base request.
	 * @return created builder
	 */
	public static Builder builder(S3BaseRequest request) {
		return new Builder(request);
	}

	/**
	 * S3 base request builder.
	 */
	public static class Builder {

		/**
		 * Redirect info, if S3 bucket is temporary redirected after creating.
		 */
		protected Redirect redirect;

		/**
		 * Creates S3 base request builder.
		 */
		protected Builder() {
		}

		/**
		 * Create S3 base request builder from S3 base request.
		 * 
		 * @param request S3 base request.
		 */
		protected Builder(S3BaseRequest request) {
			this.redirect = request.redirect;
		}

		/**
		 * Sets redirect info.
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
		 * Creates S3 base request.
		 * 
		 * @return S3 base request
		 */
		public S3BaseRequest build() {
			return new S3BaseRequest(redirect);
		}
	}
}
