/*******************************************************************************
 * Copyright (c) 2017 NTNU Gjøvik and others.
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
 *    Martin Storø Nyfløtt (NTNU Gjøvik) - performance improvements to HTTP cross-proxy
 ******************************************************************************/
package org.eclipse.californium.proxy2.http;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.DefaultConnectionKeepAliveStrategy;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClientBuilder;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManager;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.http.protocol.RequestConnControl;
import org.apache.hc.core5.http.protocol.RequestDate;
import org.apache.hc.core5.http.protocol.RequestExpectContinue;
import org.apache.hc.core5.http.protocol.RequestTargetHost;
import org.apache.hc.core5.http.protocol.RequestUserAgent;
import org.apache.hc.core5.http2.HttpVersionPolicy;
import org.apache.hc.core5.pool.PoolConcurrencyPolicy;
import org.apache.hc.core5.pool.PoolReusePolicy;
import org.apache.hc.core5.reactor.IOReactorConfig;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.proxy2.config.Proxy2Config;

/**
 * Provide http clients using pooled connection management.
 */
public class HttpClientFactory {

	private static final TimeValue KEEP_ALIVE = TimeValue.ofSeconds(5);
	private static AtomicReference<Configuration> config = new AtomicReference<Configuration>();

	private HttpClientFactory() {
	}

	/**
	 * Set the configuration for the http client.
	 * 
	 * @param config configuration
	 * @return previous configuration, or {@code null}, if not available
	 * @since 3.0 (changed return type and parameter to Configuration)
	 */
	public static Configuration setNetworkConfig(Configuration config) {
		return HttpClientFactory.config.getAndSet(config);
	}

	/**
	 * Get the configuration for the http client.
	 * 
	 * @return configuration for the http client
	 * @since 3.0 (changed return type to Configuration)
	 */
	public static Configuration getNetworkConfig() {
		Configuration config = HttpClientFactory.config.get();
		if (config == null) {
			HttpClientFactory.config.compareAndSet(null, Configuration.getStandard());
			config = HttpClientFactory.config.get();
		}
		return config;
	}

	/**
	 * Create the pooled asynchronous http client.
	 * 
	 * @return asynchronous http client
	 */
	public static CloseableHttpAsyncClient createClient() {
		return createClient(getNetworkConfig());
	}

	/**
	 * Create the pooled asynchronous http client.
	 * 
	 * @param config configuration for the http client
	 * @return asynchronous http client
	 * @since 3.0 (changed parameter to Configuration)
	 */
	public static CloseableHttpAsyncClient createClient(Configuration config) {
		int connectionIdleSecs = config.getTimeAsInt(Proxy2Config.HTTP_CONNECTION_IDLE_TIMEOUT, TimeUnit.SECONDS);
		final CloseableHttpAsyncClient client = HttpAsyncClientBuilder.create().disableCookieManagement()
				.setDefaultRequestConfig(createCustomRequestConfig(config))
				.setConnectionManager(createPoolingConnManager(config)).setVersionPolicy(HttpVersionPolicy.NEGOTIATE)
				.setIOReactorConfig(
						IOReactorConfig.custom().setSoTimeout(Timeout.ofSeconds(connectionIdleSecs)).build())
				.addRequestInterceptorFirst(new RequestConnControl()).addRequestInterceptorFirst(new RequestDate())
				.addRequestInterceptorFirst(new RequestExpectContinue())
				.addRequestInterceptorFirst(new RequestTargetHost()).addRequestInterceptorFirst(new RequestUserAgent())
				.setKeepAliveStrategy(new DefaultConnectionKeepAliveStrategy() {

					@Override
					public TimeValue getKeepAliveDuration(HttpResponse response, HttpContext context) {
						TimeValue keepAlive = super.getKeepAliveDuration(response, context);
						if (keepAlive == null || keepAlive.getDuration() < 0) {
							// Keep connections alive if a keep-alive value
							// has not be explicitly set by the server
							keepAlive = KEEP_ALIVE;
						}
						return keepAlive;
					}

				}).build();
		client.start();
		return client;
	}

	/**
	 * Create the http request-config.
	 * 
	 * @param config configuration for the http client
	 * @return http request-config
	 * @since 3.0 (changed parameter to Configuration)
	 */
	private static RequestConfig createCustomRequestConfig(Configuration config) {
		long connecTimeoutMillis = config.get(Proxy2Config.HTTP_CONNECT_TIMEOUT, TimeUnit.MILLISECONDS);
		return RequestConfig.custom().setConnectionRequestTimeout(Timeout.ofMilliseconds(connecTimeoutMillis * 4))
				.setConnectTimeout(Timeout.ofMilliseconds(connecTimeoutMillis)).build();
	}

	/**
	 * Create pooling connection Manager.
	 * 
	 * @param config configuration for the http client
	 * @return pooling connection Manager
	 * @since 3.0 (changed parameter to Configuration)
	 */
	private static PoolingAsyncClientConnectionManager createPoolingConnManager(Configuration config) {
		long connectionIdleSecs = config.get(Proxy2Config.HTTP_CONNECTION_IDLE_TIMEOUT, TimeUnit.MILLISECONDS);
		return PoolingAsyncClientConnectionManagerBuilder.create()
				.setPoolConcurrencyPolicy(PoolConcurrencyPolicy.STRICT).setConnPoolPolicy(PoolReusePolicy.LIFO)
				.setConnectionTimeToLive(TimeValue.ofSeconds(connectionIdleSecs)).setMaxConnTotal(250)
				.setMaxConnPerRoute(50).build();
	}
}
