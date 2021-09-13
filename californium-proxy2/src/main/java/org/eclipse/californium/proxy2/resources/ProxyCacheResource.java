/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.proxy2.resources;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ConcurrentModificationException;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.proxy2.config.Proxy2Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.CacheStats;
import com.google.common.cache.LoadingCache;
import com.google.common.cache.RemovalListener;
import com.google.common.cache.RemovalNotification;
import com.google.common.util.concurrent.UncheckedExecutionException;

/**
 * Resource to handle the caching in the proxy.
 */
public class ProxyCacheResource extends CoapResource implements CacheResource {

	private static final Logger LOGGER = LoggerFactory.getLogger(ProxyCacheResource.class);

	/**
	 * The cache.
	 * 
	 * @see <a href=
	 *      "http://code.google.com/p/guava-libraries/wiki/CachesExplained"
	 *      target="_blank"> Guava - Caches Explained</a>
	 */
	private final LoadingCache<CacheKey, Response> responseCache;

	private final ConcurrentMap<URI, Set<CacheKey>> resourceCache = new ConcurrentHashMap<>();

	private final ReentrantLock lock = new ReentrantLock();

	private boolean enabled = false;

	/**
	 * Instantiates a new disabled proxy cache resource.
	 * 
	 * @see #setEnabled(boolean)
	 * @see #isEnabled()
	 */
	public ProxyCacheResource() {
		this(null, false);
	}

	/**
	 * Instantiates a new proxy cache resource.
	 * 
	 * @param enabled {@code true}, enable proxy, or {@code false}, otherwise.
	 * @see #setEnabled(boolean)
	 * @see #isEnabled()
	 */
	public ProxyCacheResource(boolean enabled) {
		this(null, enabled);
	}

	/**
	 * Instantiates a new proxy cache resource.
	 * 
	 * @param configuration Configuration to use. {@code null} to
	 *            use {@link Configuration#getStandard()} .
	 * @param enabled {@code true}, enable proxy, or {@code false}, otherwise.
	 * @see #setEnabled(boolean)
	 * @see #isEnabled()
	 * @since 3.0
	 */
	public ProxyCacheResource(Configuration configuration, boolean enabled) {
		super("cache");
		this.enabled = enabled;
		if (configuration == null) {
			configuration = Configuration.getStandard();
		}
		int maxAge = configuration.getTimeAsInt(Proxy2Config.CACHE_RESPONSE_MAX_AGE, TimeUnit.SECONDS);
		int size = configuration.get(Proxy2Config.CACHE_SIZE);

		// builds a new cache that:
		// - has a limited size of CACHE_SIZE entries
		// - removes entries after CACHE_RESPONSE_MAX_AGE seconds from the last
		// write
		// - record statistics
		responseCache = CacheBuilder.newBuilder().maximumSize(size).recordStats()
				.expireAfterWrite(maxAge, TimeUnit.SECONDS).removalListener(new RemovalListener<CacheKey, Response>() {

					@Override
					public void onRemoval(RemovalNotification<CacheKey, Response> notification) {
						removeFromResourceCache(notification.getKey());
					}
				}).build(new CacheLoader<CacheKey, Response>() {

					@Override
					public Response load(CacheKey request) throws NullPointerException {
						// retrieve the response from the incoming request, no
						// exceptions are thrown
						Response cachedResponse = request.getResponse();

						// check for null and raise an exception
						// that clients must handle
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
	public void cacheResponse(CacheKey cacheKey, Response response) {
		// enable or disable the caching (debug purposes)
		if (!enabled) {
			return;
		}

		// only the response with success codes should be cached
		if (response.isSuccess()) {
			lock.lock();
			try {
				internalCacheResponse(cacheKey, response, true);
				int contentFormat = response.getOptions().getContentFormat();
				if (contentFormat != MediaTypeRegistry.UNDEFINED) {
					int alternativeFormat = cacheKey.getMediaType() == contentFormat ? MediaTypeRegistry.UNDEFINED
							: contentFormat;
					internalCacheResponse(CacheKey.fromCacheKey(cacheKey, alternativeFormat), response, false);
				}
			} finally {
				lock.unlock();
			}
		}
	}

	private void internalCacheResponse(CacheKey cacheKey, Response response, boolean all) {
		if (!lock.isHeldByCurrentThread()) {
			throw new ConcurrentModificationException("cache has pending access!");
		}
		ResponseCode code = response.getCode();

		if (code == ResponseCode.CREATED || code == ResponseCode.DELETED || code == ResponseCode.CHANGED) {
			// the stored response should be invalidated if the response has
			// codes: 2.01, 2.02, 2.04.
			if (all) {
				URI uri = cacheKey.getUri();
				if (response.getOptions().getLocationPathCount() > 0) {
					String locationPath = response.getOptions().getLocationPathString();
					uri = getResourceUri(uri, locationPath);
				} else {
					uri = getResourceUri(uri);
				}
				invalidate(uri);
			}
		} else if (code == ResponseCode.VALID) {
			// increase the max-age value according to the new response
			// Option maxAgeOption =
			// response.getFirstOption(OptionNumberRegistry.MAX_AGE);
			Long maxAgeOption = response.getOptions().getMaxAge();
			if (maxAgeOption != null) {
				// get the cached response
				Response cachedResponse = responseCache.getIfPresent(cacheKey);
				if (cachedResponse != null) {
					// calculate the new parameters
					long newCurrentTime = response.getNanoTimestamp();
					long newMaxAge = maxAgeOption.longValue();

					// set the new parameters
					cachedResponse.getOptions().setMaxAge(newMaxAge);
					cachedResponse.setNanoTimestamp(newCurrentTime);

					LOGGER.debug("Updated cached response");
				}
			} else {
				LOGGER.warn("No max-age option set in response: {}", response);
			}
		} else if (code == ResponseCode.CONTENT) {
			// set max-age if not set
			// Option maxAgeOption =
			// response.getFirstOption(OptionNumberRegistry.MAX_AGE);
			long maxAgeOption = response.getOptions().getMaxAge();

			if (maxAgeOption > 0) {
				// cache the request
				try {
					URI resource = getResourceUri(cacheKey.getUri());
					Set<CacheKey> keys = resourceCache.get(resource);
					if (keys == null) {
						keys = new CopyOnWriteArraySet<>();
						Set<CacheKey> previousKeys = resourceCache.putIfAbsent(resource, keys);
						if (previousKeys != null) {
							keys = previousKeys;
						}
					}
					if (keys.add(cacheKey)) {
						LOGGER.debug("Add new response to resource {}, {} responses", resource, keys.size());
					} else {
						LOGGER.debug("Refresh response for resource {}, {} responses", resource, keys.size());
					}
					// Caches loaded by a CacheLoader will call
					// CacheLoader.load(K) to load new values into the cache
					// when used the get method.
					cacheKey.setResponse(response);
					Response responseInserted = responseCache.get(cacheKey);
					if (responseInserted != null) {
						// if (Bench_Help.DO_LOG)
						LOGGER.debug("Cached response {}#hc={}", cacheKey, cacheKey.hashCode());
					} else {
						LOGGER.warn("Failed to insert the response in the cache");
					}
					cacheKey.setResponse(null);
				} catch (UncheckedExecutionException e) {
					// swallow
					LOGGER.warn("Exception while inserting the response in the cache", e);
				} catch (ExecutionException e) {
					// swallow
					LOGGER.warn("Exception while inserting the response in the cache", e);
				}
			} else {
				// if the max-age option is set to 0, then the response
				// should be invalidated
				invalidate(cacheKey);
			}
		} else {
			// this code should not be reached
			LOGGER.error("Code not recognized: {}", code);
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
	public Response getResponse(CacheKey cacheKey) {
		if (!enabled) {
			return null;
		}

		// search the desired representation
		Response response = responseCache.getIfPresent(cacheKey);
		LOGGER.debug("Cache read {}#hc={}", cacheKey, cacheKey.hashCode());

		// if the response is not null, manage the cached response
		if (response != null) {
			LOGGER.debug("Cache hit");

			// check if the response is expired
			long currentTime = ClockUtil.nanoRealtime();
			long secondsLeft = getRemainingLifetime(response, currentTime);
			if (secondsLeft <= 0) {
				LOGGER.debug("Expired response");

				lock.lock();
				try {
					// try to validate the response
					Response validatedResponse = validate(cacheKey);
					if (validatedResponse != null) {
						LOGGER.debug("Validation successful");
						response = validatedResponse;
						currentTime = ClockUtil.nanoRealtime();
						secondsLeft = getRemainingLifetime(response, currentTime);
					} else {
						invalidate(response, cacheKey);
					}
				} finally {
					lock.unlock();
				}
			}
			if (secondsLeft > 0) {
				// copy response to be sent as proxy response
				// mid & token are set, when sending the response
				Response proxyResponse = new Response(response.getCode());
				proxyResponse.setOptions(new OptionSet(response.getOptions()));
				proxyResponse.setPayload(response.getPayload());
				proxyResponse.getOptions().setMaxAge(secondsLeft);
				return proxyResponse;
			}
		}

		return null;
	}

	@Override
	public void invalidateRequest(CacheKey cacheKey) {
		URI resource = getResourceUri(cacheKey.getUri());
		lock.lock();
		try {
			invalidate(resource);
		} finally {
			lock.unlock();
		}
	}

	@Override
	public void handleDELETE(CoapExchange exchange) {
		lock.lock();
		try {
			responseCache.invalidateAll();
			resourceCache.clear();
		} finally {
			lock.unlock();
		}
		exchange.respond(ResponseCode.DELETED);
	}

	@Override
	public void handleGET(CoapExchange exchange) {
		StringBuilder builder = new StringBuilder();
		builder.append(
				"Available commands:\n - GET: show cached values\n - DELETE: empty the cache\n - POST: enable/disable caching\n");

		// get cache values
		long currentTime = ClockUtil.nanoRealtime();
		builder.append("\nCached values:\n");
		for (CacheKey cachedRequest : responseCache.asMap().keySet()) {
			Response response = responseCache.asMap().get(cachedRequest);

			builder.append(cachedRequest.getUri()).append(" (")
					.append(MediaTypeRegistry.toString(cachedRequest.getMediaType())).append(") > ")
					.append(getRemainingLifetime(response, currentTime)).append(" seconds").append(")\n");
		}

		exchange.respond(ResponseCode.CONTENT, builder.toString());
	}

	@Override
	public void handlePOST(CoapExchange exchange) {
		enabled = !enabled;
		String content = enabled ? "Enabled" : "Disabled";
		exchange.respond(ResponseCode.CHANGED, content);
	}

	/**
	 * Method that checks if the lifetime allowed for the response if expired.
	 * The result is calculated with the initial timestamp (when the response
	 * has been received) and the max-age option compared against the current
	 * timestamp. If the max-age option is not specified, it will be assumed the
	 * default (60 seconds).
	 * 
	 * @param response the response
	 * @param currentTime the current nano realtime.
	 * @return remaining life time in seconds
	 */
	private long getRemainingLifetime(Response response, long currentTime) {

		long nanoSecondsInCache = currentTime - response.getNanoTimestamp();
		long maxAgeInNanoSeconds = TimeUnit.SECONDS.toNanos(response.getOptions().getMaxAge());
		return TimeUnit.NANOSECONDS.toSeconds(maxAgeInNanoSeconds - nanoSecondsInCache + 500000000);

	}

	private void invalidate(Response response, CacheKey cacheKey) {
		if (!lock.isHeldByCurrentThread()) {
			throw new ConcurrentModificationException("cache has pending access!");
		}
		invalidate(cacheKey);
		int contentType = response.getOptions().getContentFormat();
		if (contentType != MediaTypeRegistry.UNDEFINED) {
			// the cache contains also a entry for UNDEFINED from freshest
			// response
			// check, if that must be invalidated as well
			if (cacheKey.getMediaType() == MediaTypeRegistry.UNDEFINED) {
				// invalidate the typed entry as well
				invalidate(CacheKey.fromCacheKey(cacheKey, contentType));
			} else {
				CacheKey cacheKeyWithoutContentType = CacheKey.fromCacheKey(cacheKey, MediaTypeRegistry.UNDEFINED);
				if (response == responseCache.getIfPresent(cacheKeyWithoutContentType)) {
					// invalidate the untyped entry, it's the same as the typed
					invalidate(cacheKeyWithoutContentType);
				}
			}
		}
	}

	private void removeFromResourceCache(CacheKey cacheKey) {
		URI resource = getResourceUri(cacheKey.getUri());
		Set<CacheKey> set = resourceCache.remove(resource);
		if (set != null) {
			set.remove(cacheKey);
		}
	}

	private void invalidate(URI uri) {
		Set<CacheKey> set = resourceCache.remove(uri);
		if (set != null) {
			LOGGER.debug("Invalidate resource {}, {} responses", uri, set.size());
			for (CacheKey cacheKey : set) {
				invalidate(cacheKey);
			}
		}
	}

	private URI getResourceUri(URI uri) {
		if (uri.getQuery() != null || uri.getFragment() != null) {
			try {
				uri = new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), uri.getPath(), null, null);
			} catch (URISyntaxException e) {
				LOGGER.warn("URI malformed {}", uri, e);
			}
		}
		return uri;
	}

	private URI getResourceUri(URI uri, String locationPath) {
		try {
			uri = new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), locationPath, null, null);
		} catch (URISyntaxException e) {
			LOGGER.warn("URI malformed {}", uri, e);
		}
		return uri;
	}

	private void invalidate(CacheKey cacheKey) {
		responseCache.invalidate(cacheKey);
	}

	private Response validate(CacheKey cachedRequest) {
		// TODO
		return null;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
}
