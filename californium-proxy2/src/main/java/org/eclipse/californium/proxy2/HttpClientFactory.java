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
package org.eclipse.californium.proxy2;

import java.util.concurrent.atomic.AtomicReference;

import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.protocol.RequestAcceptEncoding;
import org.apache.http.client.protocol.ResponseContentEncoding;
import org.apache.http.impl.client.DefaultConnectionKeepAliveStrategy;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.impl.nio.conn.PoolingNHttpClientConnectionManager;
import org.apache.http.impl.nio.reactor.DefaultConnectingIOReactor;
import org.apache.http.nio.reactor.ConnectingIOReactor;
import org.apache.http.nio.reactor.IOReactorException;
import org.apache.http.protocol.*;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provide http clients using pooled connection management.
 */
public class HttpClientFactory {

	private static final int KEEP_ALIVE = 5000;
	private static final Logger LOGGER = LoggerFactory.getLogger(HttpClientFactory.class);
	private static AtomicReference<NetworkConfig> config = new AtomicReference<NetworkConfig>();

	private HttpClientFactory() {
	}

	public static NetworkConfig setNetworkConfig(NetworkConfig config) {
		return HttpClientFactory.config.getAndSet(config);
	}

	public static NetworkConfig getNetworkConfig() {
		NetworkConfig config = HttpClientFactory.config.get();
		if (config == null) {
			HttpClientFactory.config.compareAndSet(null, NetworkConfig.getStandard());
			config = HttpClientFactory.config.get();
		}
		return config;
	}

	public static CloseableHttpAsyncClient createClient() {
		return createClient(getNetworkConfig());
	}

	public static CloseableHttpAsyncClient createClient(NetworkConfig config) {
		try {
			final CloseableHttpAsyncClient client = HttpAsyncClientBuilder.create().disableCookieManagement()
					.setDefaultRequestConfig(createCustomRequestConfig(config))
					.setConnectionManager(createPoolingConnManager()).addInterceptorFirst(new RequestAcceptEncoding())
					.addInterceptorFirst(new RequestConnControl())
					// .addInterceptorFirst(new RequestContent())
					.addInterceptorFirst(new RequestDate()).addInterceptorFirst(new RequestExpectContinue(true))
					.addInterceptorFirst(new RequestTargetHost()).addInterceptorFirst(new RequestUserAgent())
					.addInterceptorFirst(new ResponseContentEncoding())
					.setKeepAliveStrategy(new DefaultConnectionKeepAliveStrategy() {

						@Override
						public long getKeepAliveDuration(HttpResponse response, HttpContext context) {
							long keepAlive = super.getKeepAliveDuration(response, context);
							if (keepAlive == -1) {
								// Keep connections alive if a keep-alive value
								// has not be explicitly set by the server
								keepAlive = KEEP_ALIVE;
							}
							return keepAlive;
						}

					}).build();
			client.start();
			return client;
		} catch (IOReactorException e) {
			LOGGER.error("create http-client failed!", e);
			return null;
		}
	}

	private static RequestConfig createCustomRequestConfig(NetworkConfig config) {
		int connecTimeoutMillis = config.getInt(Keys.TCP_CONNECT_TIMEOUT);
		int socketTimeoutSecs = config.getInt(Keys.TCP_CONNECTION_IDLE_TIMEOUT);
		return RequestConfig.custom().setConnectionRequestTimeout(connecTimeoutMillis * 4)
				.setConnectTimeout(connecTimeoutMillis).setSocketTimeout(socketTimeoutSecs * 1000).build();
	}

	private static PoolingNHttpClientConnectionManager createPoolingConnManager() throws IOReactorException {
		ConnectingIOReactor ioReactor = new DefaultConnectingIOReactor();

		PoolingNHttpClientConnectionManager cm = new PoolingNHttpClientConnectionManager(ioReactor);
		cm.setMaxTotal(250);
		cm.setDefaultMaxPerRoute(50);

		return cm;
	}
}
