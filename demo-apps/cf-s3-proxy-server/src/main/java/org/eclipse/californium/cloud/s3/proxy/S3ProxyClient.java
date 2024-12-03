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

import java.util.function.Consumer;

import org.eclipse.californium.cloud.s3.http.ExternalEndpointProvider;
import org.eclipse.californium.core.coap.Response;

/**
 * S3 proxy client.
 * <p>
 * Implements PUT and GET for device objects and SAVE, LOAD, LIST and DELETE for
 * other resources.
 * 
 * @since 3.12
 */
public interface S3ProxyClient extends ExternalEndpointProvider {

	/**
	 * Default S3 region.
	 */
	String DEFAULT_REGION = "us-east-1";

	/**
	 * Gets default S3 ACL.
	 * 
	 * @return default S3 ACL
	 */
	String getAcl();

	/**
	 * Executes S3 PUT request for device data.
	 * 
	 * @param request PUT request
	 * @param handler callback for coap-response
	 */
	void put(S3ProxyRequest request, Consumer<Response> handler);

	/**
	 * Executes S3 GET request for device data.
	 * 
	 * @param request GET request
	 * @param handler callback for coap-response
	 */
	void get(S3ProxyRequest request, Consumer<Response> handler);

	/**
	 * Executes S3 PUT request.
	 * 
	 * @param request PUT request
	 * @param handler callback for resource content
	 * @since 3.13
	 */
	void save(S3PutRequest request, final Consumer<S3Response> handler);

	/**
	 * Executes S3 GET request.
	 * 
	 * @param request GET request
	 * @param handler callback for resource content
	 */
	void load(S3Request request, final Consumer<S3Response> handler);

	/**
	 * Executes S3 LIST request.
	 * 
	 * @param request LIST request
	 * @param handler callback for list response
	 * @since 3.13
	 */
	void list(S3ListRequest request, final Consumer<S3ListResponse> handler);

	/**
	 * Executes S3 delete request.
	 * 
	 * @param request delete request
	 * @param handler callback for delete response
	 * @since 3.13
	 */
	void delete(S3Request request, final Consumer<S3Response> handler);

}
