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

import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.CacheStats;
import com.google.common.cache.LoadingCache;
import com.google.common.primitives.Ints;


/**
 * Resource to handle the caching in the proxy.
 */
public class ProxyCacheResource extends CoapResource implements CacheResource {
	
	/**
	 * The time after which an entry is removed. Since it is not possible to set
	 * the expiration for the single instances, this constant represent the
	 * upper bound for the cache. The real lifetime will be handled explicitly
	 * with the max-age option.
	 */
	private static final int CACHE_RESPONSE_MAX_AGE = 
			NetworkConfig.getStandard().getInt(NetworkConfig.Keys.HTTP_CACHE_RESPONSE_MAX_AGE);

	/**
	 * Maximum size for the cache.
	 */
	private static final long CACHE_SIZE = 
			NetworkConfig.getStandard().getInt(NetworkConfig.Keys.HTTP_CACHE_SIZE);

	/**
	 * The cache. http://code.google.com/p/guava-libraries/wiki/CachesExplained
	 */
	private final LoadingCache<CacheKey, Response> responseCache;

	private boolean enabled = false;

	/**
	 * Instantiates a new proxy cache resource.
	 */
	public ProxyCacheResource() {
		this(false);
	}
	
	/**
	 * Instantiates a new proxy cache resource.
	 */
	public ProxyCacheResource(boolean enabled) {
		super("cache");
		this.enabled = enabled;

		// builds a new cache that:
		// - has a limited size of CACHE_SIZE entries
		// - removes entries after CACHE_RESPONSE_MAX_AGE seconds from the last
		// write
		// - record statistics
		responseCache = CacheBuilder.newBuilder().maximumSize(CACHE_SIZE).recordStats().expireAfterWrite(CACHE_RESPONSE_MAX_AGE, TimeUnit.SECONDS).build(new CacheLoader<CacheKey, Response>() {
			@Override
			public Response load(CacheKey request) throws NullPointerException {
				// retrieve the response from the incoming request, no
				// exceptions are thrown
				Response cachedResponse = request.getResponse();

				// check for null and raise an exception that clients must
				// handle
				if (cachedResponse == null) {
					throw new NullPointerException();
				}

				return cachedResponse;
			}
		});
	}

	/**
	 * Puts in cache an entry or, if already present, refreshes it. The method
	 * first checks the response code, only the 2.xx codes are cached by coap.
	 * In case of 2.01, 2.02, and 2.04 response codes it invalidates the
	 * possibly present response. In case of 2.03 it updates the freshness of
	 * the response with the max-age option provided. In case of 2.05 it creates
	 * the key and caches the response if the max-age option is higher than
	 * zero.
	 */
	@Override
	public void cacheResponse(Request request, Response response) {
		// enable or disable the caching (debug purposes)
		if (!enabled) {
			return;
		}

		// only the response with success codes should be cached
		ResponseCode code = response.getCode();
		if (ResponseCode.isSuccess(code)) {
			// get the request
//			Request request = response.getRequest();
			CacheKey cacheKey = null;
			try {
				cacheKey = CacheKey.fromContentTypeOption(request);
			} catch (URISyntaxException e) {
				LOGGER.warning("Cannot create the cache key: " + e.getMessage());
			}

			if (code == ResponseCode.CREATED || code == ResponseCode.DELETED || code == ResponseCode.CHANGED) {
				// the stored response should be invalidated if the response has
				// codes: 2.01, 2.02, 2.04.
				invalidateRequest(cacheKey);
			} else if (code == ResponseCode.VALID) {
				// increase the max-age value according to the new response
//				Option maxAgeOption = response.getFirstOption(OptionNumberRegistry.MAX_AGE);
				Long maxAgeOption = response.getOptions().getMaxAge();
				if (maxAgeOption != null) {
					// get the cached response
					Response cachedResponse = responseCache.getUnchecked(cacheKey);

					// calculate the new parameters
					long newCurrentTime = response.getTimestamp();
					long newMaxAge = maxAgeOption.longValue();

					// set the new parameters
					cachedResponse.getOptions().setMaxAge(newMaxAge);
					cachedResponse.setTimestamp(newCurrentTime);

					LOGGER.finer("Updated cached response");
				} else {
					LOGGER.warning("No max-age option set in response: " + response);
				}
			} else if (code == ResponseCode.CONTENT) {
				// set max-age if not set
//				Option maxAgeOption = response.getFirstOption(OptionNumberRegistry.MAX_AGE);
				Long maxAgeOption = response.getOptions().getMaxAge();
				if (maxAgeOption == null) {
					response.getOptions().setMaxAge(OptionNumberRegistry.Defaults.MAX_AGE);
				}

				if (maxAgeOption > 0) {
					// cache the request
					try {
						// Caches loaded by a CacheLoader will call
						// CacheLoader.load(K) to load new values into the cache
						// when used the get method.
						Response responseInserted = responseCache.get(cacheKey);
						if (responseInserted != null) {
//							if (Bench_Help.DO_LOG) 
								LOGGER.finer("Cached response");
						} else {
							LOGGER.warning("Failed to insert the response in the cache");
						}
					} catch (Exception e) {
						// swallow
						LOGGER.log(Level.WARNING, "Exception while inserting the response in the cache", e);
					}
				} else {
					// if the max-age option is set to 0, then the response
					// should be invalidated
					invalidateRequest(request);
				}
			} else {
				// this code should not be reached
				LOGGER.severe("Code not recognized: " + code);
			}
		}
	}

	@Override
	public CacheStats getCacheStats() {
		return responseCache.stats();
	}

	/**
	 * Retrieves the response in the cache that matches the request passed, null
	 * otherwise. The method creates the key for the cache starting from the
	 * request and checks if the cache contains it. If present, the method
	 * updates the max-age of the linked response to consider the time passed in
	 * the cache (according to the freshness model) and returns it. On the
	 * contrary, if the response has passed its expiration time, it is
	 * invalidated and the method returns null.
	 */
	@Override
	public Response getResponse(Request request) {
		if (!enabled) {
			return null;
		}

		// search the desired representation
		Response response = null;
		CacheKey cacheKey = null;

		for (CacheKey acceptKey : CacheKey.fromAcceptOptions(request)) {
			response = responseCache.getIfPresent(acceptKey);
			cacheKey = acceptKey;

			if (response != null) {
				break;
			}
		}

		// if the response is not null, manage the cached response
		if (response != null) {
			LOGGER.finer("Cache hit");

			// check if the response is expired
			long currentTime = System.nanoTime();
			long nanosLeft = getRemainingLifetime(response, currentTime);
			if (nanosLeft > 0) {
				// if the response can be used, then update its max-age to
				// consider the aging of the response while in the cache
				response.getOptions().setMaxAge(nanosLeft);
				// set the current time as the response timestamp
				response.setTimestamp(currentTime);
			} else {
				LOGGER.finer("Expired response");

				// try to validate the response
				response = validate(cacheKey);
				if (response != null) {
					LOGGER.finer("Validation successful");
				} else {
					invalidateRequest(cacheKey);
				}
			}
		}

		return response;
	}
	
	@Override
	public void invalidateRequest(Request request) {
		invalidateRequest(CacheKey.fromAcceptOptions(request));
		LOGGER.finer("Invalidated request");
	}

	@Override
	public void handleDELETE(CoapExchange exchange) {
		responseCache.invalidateAll();
		exchange.respond(ResponseCode.DELETED);
	}

	@Override
	public void handleGET(CoapExchange exchange) {
		StringBuilder builder = new StringBuilder();
		builder.append("Available commands:\n - GET: show cached values\n - DELETE: empty the cache\n - POST: enable/disable caching\n");

		// get cache values
		builder.append("\nCached values:\n");
		for (CacheKey cachedRequest : responseCache.asMap().keySet()) {
			Response response = responseCache.asMap().get(cachedRequest);

			builder.append(cachedRequest.getProxyUri()).append(" (").append(
					MediaTypeRegistry.toString(cachedRequest.getMediaType())).append(") > ").append(getRemainingLifetime(response)).append(" seconds | (").append(cachedRequest.getMediaType()).append(")\n");
		}

		exchange.respond(ResponseCode.CONTENT, builder.toString());
	}

	@Override
	public void handlePOST(CoapExchange exchange) {
		enabled = !enabled;
		String content = enabled ? "Enabled" : "Disabled";
		exchange.respond(ResponseCode.CHANGED, content);
	}

	private long getRemainingLifetime(Response response) {
		return getRemainingLifetime(response, System.nanoTime());
	}

	/**
	 * Method that checks if the lifetime allowed for the response if expired.
	 * The result is calculated with the initial timestamp (when the response
	 * has been received) and the max-age option compared against the current
	 * timestamp. If the max-age option is not specified, it will be assumed the
	 * default (60 seconds).
	 * 
	 * @param response
	 *            the response
	 * @param currentTime
	 * @return true, if is expired
	 */
	private long getRemainingLifetime(Response response, long currentTime) {
		// get the timestamp
		long arriveTime = response.getTimestamp();
		
		Long maxAgeOption = response.getOptions().getMaxAge();
		long oldMaxAge = OptionNumberRegistry.Defaults.MAX_AGE;
		if (maxAgeOption != null) {
			oldMaxAge = maxAgeOption.longValue();
		}

		// calculate the time that the response has spent in the cache
		double secondsInCache = TimeUnit.NANOSECONDS.toSeconds(currentTime - arriveTime);
		int cacheTime = Ints.checkedCast(Math.round(secondsInCache));
		return oldMaxAge - cacheTime;
	}

	private void invalidateRequest(CacheKey cacheKey) {
		responseCache.invalidate(cacheKey);
	}

	private void invalidateRequest(List<CacheKey> cacheKeys) {
		responseCache.invalidateAll(cacheKeys);
	}

	private Response validate(CacheKey cachedRequest) {
		// TODO
		return null;
	}

	/**
	 * Nested class that normalizes the variable fields of the coap requests to
	 * be used as a key for the cache. The class tries to handle also the
	 * different requests that must refer to the same response (e.g., requests
	 * that with or without the accept options produce the same response).
	 */
	private static final class CacheKey {
		private final String proxyUri;
		private final int mediaType;
		private Response response;
		private final byte[] payload;

		/**
		 * Creates a list of keys for the cache from a request with multiple
		 * accept options set. Method needed to search for content-type
		 * wildcards in the cache (text/* means: text/plain, text/html,
		 * text/xml, text/csv, etc.). If the accept option is not set, it simply
		 * gives back the keys for every representation.
		 * 
		 * @param request
		 * @return the list of cache keys
		 */
		private static List<CacheKey> fromAcceptOptions(Request request) {
			if (request == null) {
				throw new IllegalArgumentException("request == null");
			}

			List<CacheKey> cacheKeys = new LinkedList<ProxyCacheResource.CacheKey>();
			String proxyUri = request.getOptions().getProxyUri();
			try {
				// TODO why not UTF-8?
				proxyUri = URLEncoder.encode(proxyUri, "ISO-8859-1");
			} catch (UnsupportedEncodingException e) {
				LOGGER.severe("ISO-8859-1 encoding not supported: " + e.getMessage());
			}
			byte[] payload = request.getPayload();

			// Implementation in new Cf (Only one accept option allowed)
			int accept = request.getOptions().getAccept();
			if (accept < 0) {
				// if the accept options are not set, simply set all media types
				// FIXME not efficient
				for (Integer acceptType : MediaTypeRegistry.getAllMediaTypes()) {
					cacheKeys.add(new CacheKey(proxyUri, acceptType, payload));
				}
			} else {
				cacheKeys.add(new CacheKey(proxyUri, accept, payload));
			}

			return cacheKeys;
		}

		/**
		 * Create a key for the cache starting from a request and the
		 * content-type of the corresponding response.
		 * 
		 * @param request
		 * @return
		 * @throws URISyntaxException
		 */
		private static CacheKey fromContentTypeOption(Request request) throws URISyntaxException {
			if (request == null) {
				throw new IllegalArgumentException("request == null");
			}

			Response response = request.getResponse();
			if (response == null) {
				return fromAcceptOptions(request).get(0);
			}

			String proxyUri = request.getOptions().getProxyUri();
			int mediaType = response.getOptions().getContentFormat();
			if (mediaType < 0) {
				// content-format option not set, use default
				mediaType = MediaTypeRegistry.TEXT_PLAIN;
			}
			byte[] payload = request.getPayload();

			// create the new cacheKey
			CacheKey cacheKey = new CacheKey(proxyUri, mediaType, payload);
			cacheKey.setResponse(response);

			return cacheKey;
		}

		public CacheKey(String proxyUri, int mediaType, byte[] payload) {
			this.proxyUri = proxyUri;
			this.mediaType = mediaType;
			this.payload = payload;
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
			if (!Arrays.equals(payload, other.payload)) {
				return false;
			}
			if (proxyUri == null) {
				if (other.proxyUri != null) {
					return false;
				}
			} else if (!proxyUri.equals(other.proxyUri)) {
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
		 * @return the proxyUri
		 */
		public String getProxyUri() {
			return proxyUri;
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
			final int prime = 31;
			int result = 1;
			result = prime * result + mediaType;
			result = prime * result + Arrays.hashCode(payload);
			result = prime * result + (proxyUri == null ? 0 : proxyUri.hashCode());
			return result;
		}

		private void setResponse(Response response) {
			this.response = response;

		}
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
}
