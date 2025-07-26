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

import java.util.ArrayList;
import java.util.List;

import org.eclipse.californium.cloud.s3.proxy.S3ListResponse.S3Object;

/**
 * S3 deletes list request.
 * 
 * @since 4.0
 */
public class S3DeletesRequest extends S3BaseRequest {

	/**
	 * S3 deletes list.
	 */
	private final List<S3Object> deletes;

	/**
	 * Creates S3 deletes list request.
	 * 
	 * @param deletes list of S3 key and eTAGs.
	 * @param redirect redirect info, if S3 bucket is temporary redirected after
	 *            creating.
	 */
	public S3DeletesRequest(List<S3Object> deletes, Redirect redirect) {
		super(redirect);
		this.deletes = new ArrayList<>(deletes);
	}

	/**
	 * Gets list of deletes for S3.
	 * 
	 * @return list of deletes for S3.
	 */
	public List<S3Object> getDeletes() {
		return deletes;
	}

	/**
	 * Creates S3 deletes list request builder.
	 * 
	 * @return created builder
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Creates S3 deletes list request builder from S3 deletes list request.
	 * 
	 * @param request S3 deletes list request.
	 * @return created builder
	 */
	public static Builder builder(S3DeletesRequest request) {
		return new Builder(request);
	}

	/**
	 * S3 deletes list request builder.
	 */
	public static class Builder extends S3BaseRequest.Builder {

		/**
		 * S3 deletes.
		 */
		protected List<S3Object> deletes;

		/**
		 * Creates S3 deletes list request builder.
		 */
		protected Builder() {
		}

		/**
		 * Creates builder from S3 deletes list request.
		 * 
		 * @param request S3 deletes list request
		 */
		protected Builder(S3DeletesRequest request) {
			super(request);
			this.deletes = request.deletes;
		}

		/**
		 * Sets list of deletes.
		 * 
		 * @param deletes list of deletes
		 * @return builder for command chaining
		 */
		public Builder deletes(List<S3Object> deletes) {
			this.deletes = deletes;
			return this;
		}

		@Override
		public Builder redirect(Redirect redirect) {
			super.redirect(redirect);
			return this;
		}

		/**
		 * Creates S3 deletes list request.
		 * 
		 * @return S3 deletes list request
		 */
		public S3DeletesRequest build() {
			return new S3DeletesRequest(deletes, redirect);
		}
	}
}
