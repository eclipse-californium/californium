/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Francesco Corazza - HTTP cross-proxy
 ******************************************************************************/
package org.eclipse.californium.proxy.resources;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;

import com.google.common.cache.CacheStats;


public interface CacheResource {

	/**
	 * 
	 */
	public void cacheResponse(Request request, Response response);

	public CacheStats getCacheStats();

	/**
	 * Gets cached response.
	 * 
	 * @param request
	 *            the request
	 * @return the cached response or null in case it is not present
	 */
	public Response getResponse(Request request);

	public void invalidateRequest(Request request);
}
