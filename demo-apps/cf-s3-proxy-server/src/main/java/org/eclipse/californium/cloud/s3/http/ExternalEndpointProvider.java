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
package org.eclipse.californium.cloud.s3.http;

/**
 * External https endpoint provider for S3 buckets.
 * <p>
 * Used for web-app to access data directly on S3.
 * 
 * @since 3.12
 */
public interface ExternalEndpointProvider {

	/**
	 * Gets external https endpoint for S3 bucket.
	 * 
	 * @return external https endpoint for S3 bucket
	 */
	String getExternalEndpoint();

	/**
	 * Gets region of S3 bucket.
	 * 
	 * @return region of S3 bucket
	 */
	String getRegion();

}
