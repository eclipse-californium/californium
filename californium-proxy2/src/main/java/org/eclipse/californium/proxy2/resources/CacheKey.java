/*******************************************************************************
 * Copyright (c) 2020 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.proxy2.resources;

import java.net.URI;
import java.util.Arrays;

import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Response;

/**
 * Nested class that normalizes the variable fields of the coap requests to
 * be used as a key for the cache. The class tries to handle also the
 * different requests that must refer to the same response (e.g., requests
 * that with or without the accept options produce the same response).
 */
public final class CacheKey {
	private final Code method;
	private final URI uri;
	private final int mediaType;
	private final byte[] payload;
	private final int hashCode;
	/**
	 * Response to be loaded into the cache.
	 * Only to be used, when added to cache.
	 */
	private Response response;

	/**
	 * Create a key for the cache
	 * 
	 * @param cacheKey request
	 * @param contentType content type.
	 * @return cache key
	 * @throws NullPointerException if cacheKey is {@code null}
	 */
	static CacheKey fromCacheKey(CacheKey cacheKey, int contentType) {
		if (cacheKey == null) {
			throw new NullPointerException("cacheKey must not be null!");
		}

		// create the new cacheKey
		return new CacheKey(cacheKey.getMethod(), cacheKey.getUri(), contentType, cacheKey.payload);
	}

	public CacheKey(Code method, URI uri, int mediaType, byte[] payload) {
		if (method == null) {
			throw new NullPointerException("method must not be null!");
		}
		if (uri == null) {
			throw new NullPointerException("URI must not be null!");
		}
		this.method = method;
		this.uri = uri;
		this.mediaType = mediaType;
		this.payload = payload;
		final int prime = 31;
		int result = 1;
		result = prime * result + mediaType;
		result = prime * result + method.hashCode();
		result = prime * result + Arrays.hashCode(payload);
		result = prime * result + uri.hashCode();
		this.hashCode = result;
	}

	/*
	 * (non-Javadoc)
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		CacheKey other = (CacheKey) obj;
		if (mediaType != other.mediaType) {
			return false;
		}
		if (method != other.method) {
			return false;
		}
		if (uri == null) {
			if (other.uri != null) {
				return false;
			}
		} else if (!uri.equals(other.uri)) {
			return false;
		}
		if (!Arrays.equals(payload, other.payload)) {
			return false;
		}
		return true;
	}

	/**
	 * @return the mediaType
	 */
	public int getMediaType() {
		return mediaType;
	}

	/**
	 * @return the method.
	 */
	public Code getMethod() {
		return method;
	}

	/**
	 * @return the uri
	 */
	public URI getUri() {
		return uri;
	}

	/**
	 * @return the response
	 */
	public Response getResponse() {
		return response;
	}

	/*
	 * (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return hashCode;
	}

	public String toString() {
		return method + " " + uri + "#ct=" + MediaTypeRegistry.toString(mediaType);
	}

	void setResponse(Response response) {
		this.response = response;
	}
}