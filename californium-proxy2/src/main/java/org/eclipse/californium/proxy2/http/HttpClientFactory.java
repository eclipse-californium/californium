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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLEngine;

import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.DefaultConnectionKeepAliveStrategy;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClientBuilder;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManager;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.core5.function.Factory;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.http.protocol.RequestDate;
import org.apache.hc.core5.http2.HttpVersionPolicy;
import org.apache.hc.core5.pool.PoolConcurrencyPolicy;
import org.apache.hc.core5.pool.PoolReusePolicy;
import org.apache.hc.core5.reactor.IOReactorConfig;
import org.apache.hc.core5.reactor.ssl.TlsDetails;
import org.apache.hc.core5.util.ReflectionUtils;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.proxy2.config.Proxy2Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provide http clients using pooled connection management.
 */
public class HttpClientFactory {

	private static final Logger LOGGER = LoggerFactory.getLogger(HttpClientFactory.class);

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
	 * <b>Note:</b> Since 3.7 obsolete interceptors have been removed from
	 * configuration.
	 * 
	 * See <a href=
	 * "https://lists.apache.org/thread/r7qrl6v16vpr5bcopys4d5ppy84twnpt" target
	 * ="_blank">Apache - http - mailing-list</a> for details.
	 * 
	 * @param config configuration for the http client
	 * @return asynchronous http client
	 * @since 3.0 (changed parameter to Configuration)
	 */
	public static CloseableHttpAsyncClient createClient(Configuration config) {
		int connectionIdleSecs = config.getTimeAsInt(Proxy2Config.HTTP_CONNECTION_IDLE_TIMEOUT, TimeUnit.SECONDS);
		HttpVersionPolicy policy;
		switch (config.get(Proxy2Config.HTTP_VERSION_POLICY)) {
		case HTTP_1:
			policy = HttpVersionPolicy.FORCE_HTTP_1;
			break;
		case HTTP_2:
			policy = HttpVersionPolicy.FORCE_HTTP_2;
			break;
		case NEGOTIATE:
			policy = HttpVersionPolicy.NEGOTIATE;
			break;
		default:
			policy = HttpVersionPolicy.NEGOTIATE;
			break;
		}
		final CloseableHttpAsyncClient client = HttpAsyncClientBuilder.create().disableCookieManagement()
				.setDefaultRequestConfig(createCustomRequestConfig(config))
				.setConnectionManager(createPoolingConnManager(config)).setVersionPolicy(policy)
				.setIOReactorConfig(
						IOReactorConfig.custom().setSoTimeout(Timeout.ofSeconds(connectionIdleSecs)).build())
				.addRequestInterceptorFirst(new RequestDate())
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
				.setMaxConnPerRoute(50).setTlsStrategy(ClientTlsStrategyBuilder.create().useSystemProperties()
						.setTlsDetailsFactory(new TlsDetailsFactory()).build())
				.build();
	}

	/**
	 * TLS details factory.
	 * 
	 * Since java 8, {@code SSLEngine.getApplicationProtocol()} is available and
	 * used to negotiate http/1 and http/2. In java 7 this is only accessible
	 * via reflection direct from the internal implementing class. With java 17
	 * this does not longer work. Therefore this implementation tries to use
	 * {@code SSLEngine.getApplicationProtocol()} via reflection, and only if
	 * that is not available, then calls the internal implementation also via
	 * reflection.
	 * 
	 * Gets obsolete when moving to Apache http 5.2 and a newer java version.
	 * 
	 * @see <a href=
	 *      "https://github.com/apache/httpcomponents-client/blob/5.1.x/httpclient5/src/test/java/org/apache/hc/client5/http/examples/AsyncClientTlsAlpn.java"
	 *      >Apache - examples - AsyncClientTlsAlpn.java</a>
	 * @since 3.7
	 */
	private static class TlsDetailsFactory implements Factory<SSLEngine, TlsDetails> {

		private final Method getApplicationProtocolMethod;

		private TlsDetailsFactory() {
			Method getApplicationProtocolMethod = null;
			try {
				getApplicationProtocolMethod = SSLEngine.class.getMethod("getApplicationProtocol");
			} catch (NoSuchMethodException e) {
				if (ReflectionUtils.determineJRELevel() > 7) {
					LOGGER.info("SSLEngine.getApplicationProtocol() missing!", e);
				}
			} catch (SecurityException e) {
				LOGGER.warn("SSLEngine.getApplicationProtocol()", e);
			}
			this.getApplicationProtocolMethod = getApplicationProtocolMethod;
		}

		private String getApplicationProtocol(final SSLEngine sslEngine) {
			String applicationProtocol = null;
			if (getApplicationProtocolMethod != null) {
				try {
					applicationProtocol = (String) getApplicationProtocolMethod.invoke(sslEngine);
				} catch (IllegalAccessException e) {
					LOGGER.warn("SSLEngine.getApplicationProtocol()", e);
				} catch (IllegalArgumentException e) {
					LOGGER.warn("SSLEngine.getApplicationProtocol()", e);
				} catch (InvocationTargetException e) {
					LOGGER.warn("SSLEngine.getApplicationProtocol()", e);
				}
			} else {
				applicationProtocol = ReflectionUtils.callGetter(sslEngine, "ApplicationProtocol", String.class);
			}
			if (applicationProtocol != null) {
				LOGGER.info("SSLEngine: application protocol {}", applicationProtocol);
			}
			return applicationProtocol;
		}

		@Override
		public TlsDetails create(final SSLEngine sslEngine) {
			String applicationProtocol = getApplicationProtocol(sslEngine);
			return new TlsDetails(sslEngine.getSession(), applicationProtocol);
		}

	}
}
