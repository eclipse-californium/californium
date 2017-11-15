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

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;

import com.google.common.cache.CacheStats;
import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Table;


/**
 * Resource that encapsulate the proxy statistics.
 */
public class StatsResource extends CoapResource {
	
	private final Table<String, String, StatHelper> statsTable = HashBasedTable.create();

	private static String CACHE_LOG_NAME = "_cache_log.log";

	/**
	 * Instantiates a new stats resource.
	 * 
	 * @param cacheResource
	 */
	public StatsResource(CacheResource cacheResource) {
		super("stats");
		getAttributes().setTitle("Keeps track of the requests served by the proxy.");

		// add the sub-resource to show stats
		add(new CacheStatResource("cache", cacheResource));
		add(new ProxyStatResource("proxy"));
	}

	public void updateStatistics(Request request, boolean cachedResponse) {
		URI proxyUri = null;
		try {
			proxyUri = new URI(request.getOptions().getProxyUri());
		} catch (URISyntaxException e) {
			LOGGER.warning(String.format("Proxy-uri malformed: %s", 
					request.getOptions().getProxyUri()));
		}

		if (proxyUri == null) {
			// throw new IllegalArgumentException("proxyUri == null");
			return;
		}

		// manage the address requester
		String addressString = proxyUri.getHost();
		if (addressString != null) {
			// manage the resource requested
			String resourceString = proxyUri.getPath();
			if (resourceString != null) {
				// check if there is already an entry for the row/column
				// association
				StatHelper statHelper = statsTable.get(addressString, resourceString);
				if (statHelper == null) {
					// create a new stat if it not present
					statHelper = new StatHelper();

					// add the new element to the table
					statsTable.put(addressString, resourceString, statHelper);
				}

				// increment the count of the requests
				statHelper.increment(cachedResponse);
			}
		}
	}

	/**
	 * Builds a pretty print from the statistics gathered.
	 * 
	 * @return the statistics as string
	 */
	private String getStatString() {
		StringBuilder builder = new StringBuilder();

		builder.append(String.format("Served %d addresses and %d resources\n", statsTable.rowKeySet().size(), statsTable.cellSet().size()));
		builder.append("＿\n");
		// iterate over every row (addresses)
		for (String address : statsTable.rowKeySet()) {
			builder.append(String.format("|- %s\n", address));
			builder.append("|\t ＿\n");
			// iterate over every column for a specific address
			for (String resource : statsTable.row(address).keySet()) {
				builder.append(String.format("|\t |- %s: \n", resource));

				// get the statistics
				StatHelper statHelper = statsTable.get(address, resource);
				builder.append(String.format("|\t |------ total requests: %d\n", statHelper.getTotalCount()));
				builder.append(String.format("|\t |------ total cached replies: %d\n", statHelper.getCachedCount()));
				// builder.append(String.format("|\t |------ last period (%d sec) requests: %d\n",
				// PERIOD_SECONDS, statHelper.getLastPeriodCount()));
				// builder.append(String.format("|\t |------ last period (%d sec) avg delay (nanosec): %d\n",
				// PERIOD_SECONDS, statHelper.getLastPeriodAvgDelay()));
				builder.append("|\t |\n");
			}
			builder.append("|\t ￣\n");
			builder.append("|\n");
		}
		builder.append("￣\n");

		return builder.length() == 0 ? "The proxy has not received any request, yet." : builder.toString();
	}

	private static final class CacheStatResource extends CoapResource {
		private CacheStats relativeCacheStats;
		private final CacheResource cacheResource;

		private static final long DEFAULT_LOGGING_DELAY = 5;
		ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();

		/**
		 * Instantiates a new debug resource.
		 * 
		 * @param resourceIdentifier
		 *            the resource identifier
		 * @param cacheResource
		 */
		public CacheStatResource(String resourceIdentifier, CacheResource cacheResource) {
			super(resourceIdentifier);

			this.cacheResource = cacheResource;
			relativeCacheStats = cacheResource.getCacheStats();
		}

		/**
		 * Method to get the stats about the cache.
		 * 
		 * @return
		 */
		public String getStats() {
			StringBuilder stringBuilder = new StringBuilder();
			CacheStats cacheStats = cacheResource.getCacheStats().minus(relativeCacheStats);

			stringBuilder.append(String.format("Total successful loaded values: %d %n", cacheStats.loadSuccessCount()));
			stringBuilder.append(String.format("Total requests: %d %n", cacheStats.requestCount()));
			stringBuilder.append(String.format("Hits ratio: %d/%d - %.3f %n", cacheStats.hitCount(), cacheStats.missCount(), cacheStats.hitRate()));
			stringBuilder.append(String.format("Average time spent loading new values (nanoseconds): %.3f %n", cacheStats.averageLoadPenalty()));
			stringBuilder.append(String.format("Number of cache evictions: %d %n", cacheStats.evictionCount()));

			return stringBuilder.toString();
		}

		@Override
		public void handleDELETE(CoapExchange exchange) {
			// reset the cache
			relativeCacheStats = cacheResource.getCacheStats().minus(relativeCacheStats);
			exchange.respond(ResponseCode.DELETED);
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			String payload = "Available commands:\n - GET: show statistics\n - POST write stats to file\n - DELETE: reset statistics\n\n";
			payload += getStats();
			Response response = new Response(ResponseCode.CONTENT);
			response.setPayload(payload);
			response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
			exchange.respond(response);
		}

		@Override
		public void handlePOST(CoapExchange exchange) {
			// TODO include stopping the writing => make something for the whole
			// proxy
			// executor.shutdown();
			// request.respond(CodeRegistry.RESP_DELETED, "Stopped",
			// MediaTypeRegistry.TEXT_PLAIN);

			// starting to log the stats on a new file

			// create the new file
			String logName = System.nanoTime() + CACHE_LOG_NAME;
			final File cacheLog = new File(logName);
			try {
				cacheLog.createNewFile();

				// write the header
				com.google.common.io.Files.write("hits%, avg. load, #evictions \n", cacheLog, Charset.defaultCharset());
			} catch (IOException e) {
			}

			executor.scheduleWithFixedDelay(new Runnable() {

				@Override
				public void run() {
					CacheStats cacheStats = cacheResource.getCacheStats().minus(relativeCacheStats);

					String csvStats = String.format("%.3f, %.3f, %d %n", cacheStats.hitRate(), cacheStats.averageLoadPenalty(), cacheStats.evictionCount());
					try {
						com.google.common.io.Files.append(csvStats, cacheLog, Charset.defaultCharset());
					} catch (IOException e) {
					}
				}
			}, 0, DEFAULT_LOGGING_DELAY, TimeUnit.SECONDS);

			Response response = new Response(ResponseCode.CREATED);
			response.setPayload("Creted log: " + logName);
			response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
			exchange.respond(response);
		}
	}

	private final class ProxyStatResource extends CoapResource {

		public ProxyStatResource(String resourceIdentifier) {
			super(resourceIdentifier);
		}

		@Override
		public void handleDELETE(CoapExchange exchange) {
			// reset all the statistics
			statsTable.clear();
			exchange.respond(ResponseCode.DELETED);
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			String payload = "Available commands:\n - GET: show statistics\n - POST write stats to file\n - DELETE: reset statistics\n\n";
			payload += getStatString();
			Response response = new Response(ResponseCode.CONTENT);
			response.setPayload(payload);
			response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
			exchange.respond(response);
		}

	}

	/**
	 * The Class StatisticsHelper.
	 */
	private static class StatHelper {
		private int totalCount = 0;
		private int cachedCount = 0;

		public int getCachedCount() {
			return cachedCount;
		}
		
		/**
		 * @return the totalCount
		 */
		public int getTotalCount() {
			return totalCount;
		}

		public void increment(boolean cachedResponse) {
			// add the total request counter
			totalCount++;
			if (cachedResponse) {
				cachedCount++;
			}

			// add the new request's timestamp to the list
			// long currentTimestamp = System.nanoTime();
			// lastPeriodTimestamps.add(currentTimestamp);

			// clean the list by the old entries
			// cleanTimestamps(currentTimestamp);
		}
	}
}
