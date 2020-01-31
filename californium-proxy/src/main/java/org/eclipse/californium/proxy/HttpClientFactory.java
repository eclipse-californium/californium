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
package org.eclipse.californium.proxy;

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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HttpClientFactory {
	private static final int KEEP_ALIVE = 5000;
	private static final Logger LOGGER = LoggerFactory.getLogger(HttpClientFactory.class);

	private HttpClientFactory() {
	}

	public static CloseableHttpAsyncClient createClient() {
		try {
			final CloseableHttpAsyncClient client = HttpAsyncClientBuilder.create()
					.disableCookieManagement()
					.setDefaultRequestConfig(createCustomRequestConfig())
					.setConnectionManager(createPoolingConnManager())
					.addInterceptorFirst(new RequestAcceptEncoding())
					.addInterceptorFirst(new RequestConnControl())
					// .addInterceptorFirst(new RequestContent())
					.addInterceptorFirst(new RequestDate())
					.addInterceptorFirst(new RequestExpectContinue(true))
					.addInterceptorFirst(new RequestTargetHost())
					.addInterceptorFirst(new RequestUserAgent())
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

					})
					.build();
			client.start();
			return client;
		} catch (IOReactorException e) {
			LOGGER.error("create http-client failed!", e);
			return null;
		}
	}

	private static RequestConfig createCustomRequestConfig() {
		return RequestConfig.custom()
				.setConnectionRequestTimeout(5000)
				.setConnectTimeout(1000)
				.setSocketTimeout(500).build();
	}

	private static PoolingNHttpClientConnectionManager createPoolingConnManager() throws IOReactorException {
		ConnectingIOReactor ioReactor = new DefaultConnectingIOReactor();

		PoolingNHttpClientConnectionManager cm = new PoolingNHttpClientConnectionManager(ioReactor);
		cm.setMaxTotal(50);
		cm.setDefaultMaxPerRoute(50);

		return cm;
	}
}
