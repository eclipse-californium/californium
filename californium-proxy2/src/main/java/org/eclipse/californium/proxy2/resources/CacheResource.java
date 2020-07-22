/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Francesco Corazza - HTTP cross-proxy
 ******************************************************************************/
package org.eclipse.californium.proxy2.resources;

import org.eclipse.californium.core.coap.Response;

import com.google.common.cache.CacheStats;

/**
 * Basic API for response cache.
 */
public interface CacheResource {

	/**
	 * Cache response.
	 * 
	 * Depending on the response code, the response is either kept, or all kept
	 * responses for the resource are invalidated.
	 * 
	 * @param key cache key of request
	 * @param response response to process
	 */
	public void cacheResponse(CacheKey key, Response response);

	/**
	 * Get cache statistics.
	 * 
	 * @return cache statistics
	 */
	public CacheStats getCacheStats();

	/**
	 * Gets cached response.
	 * 
	 * @param key cache key of request
	 * @return the cached response or null in case it is not present
	 */
	public Response getResponse(CacheKey key);

	/**
	 * Invalidate all responses for the referred resource.
	 * 
	 * @param key cache key to invalidate all responses of the referred resource
	 */
	public void invalidateRequest(CacheKey key);
}
