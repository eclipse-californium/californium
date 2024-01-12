/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.proxy2.config;

import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.DefinitionUtils;
import org.eclipse.californium.elements.config.SystemConfig;
import org.eclipse.californium.elements.config.TimeDefinition;
import org.eclipse.californium.elements.config.Configuration.ModuleDefinitionsProvider;
import org.eclipse.californium.elements.config.EnumDefinition;
import org.eclipse.californium.elements.config.IntegerDefinition;

/**
 * Configuration definitions for proxy2.
 * 
 * @since 3.0
 */
public final class Proxy2Config {

	public static final String MODULE = "PROXY2.";

	/**
	 * HTTP version.
	 * 
	 * @since 3.7
	 */
	public enum HttpVersion {

		HTTP_1, HTTP_2, NEGOTIATE

	}

	/**
	 * The default http-tcp connection idle timeout in seconds.
	 * <p>
	 * The default value is 10s.
	 */
	public static final int DEFAULT_HTTP_CONNECTION_IDLE_TIMEOUT_IN_SECONDS = 10;

	/**
	 * The default http-tcp connect timeout in seconds.
	 * <p>
	 * The default value is 10s.
	 */
	public static final int DEFAULT_HTTP_CONNECT_TIMEOUT_IN_SECONDS = 10;

	/**
	 * The default http-tls handshake timeout in seconds.
	 * <p>
	 * The default value is 10s.
	 */
	public static final int DEFAULT_HTTPS_HANDSHAKE_TIMEOUT_IN_SECONDS = 10;

	public static final IntegerDefinition HTTP_PORT = new IntegerDefinition(MODULE + "HTTP_PORT", "HTTP server port.",
			80, 1);
	public static final TimeDefinition HTTP_SERVER_SOCKET_TIMEOUT = new TimeDefinition(
			MODULE + "HTTP_SERVER_SOCKET_TIMEOUT", "HTTP server socket timeout.", 10L, TimeUnit.SECONDS);
	public static final IntegerDefinition HTTP_SERVER_SOCKET_BUFFER_SIZE = new IntegerDefinition(
			MODULE + "HTTP_SERVER_SOCKET_BUFFER_SIZE", "HTTP server socker buffersize.", 8192, 2048);
	public static final TimeDefinition CACHE_RESPONSE_MAX_AGE = new TimeDefinition(MODULE + "CACHE_RESPONSE_MAX_AGE",
			"Maximum age to cache responses.", 1L, TimeUnit.HOURS);
	public static final IntegerDefinition CACHE_SIZE = new IntegerDefinition(MODULE + "CACHE_SIZE",
			"Size of response cache.", 1000, 10);
	public static final TimeDefinition HTTP_CONNECTION_IDLE_TIMEOUT = new TimeDefinition(
			MODULE + "HTTP_CONNECTION_IDLE_TIMEOUT", "HTTP connection idle timeout.",
			DEFAULT_HTTP_CONNECTION_IDLE_TIMEOUT_IN_SECONDS, TimeUnit.SECONDS);
	public static final TimeDefinition HTTP_CONNECT_TIMEOUT = new TimeDefinition(MODULE + "HTTP_CONNECT_TIMEOUT",
			"HTTP connect timeout", DEFAULT_HTTP_CONNECT_TIMEOUT_IN_SECONDS, TimeUnit.SECONDS);
	public static final EnumDefinition<HttpVersion> HTTP_VERSION_POLICY = new EnumDefinition<>(
			MODULE + "HTTP_VERSION_POLICY", "HTTP version policy.", HttpVersion.NEGOTIATE,
			HttpVersion.values());
	public static final IntegerDefinition HTTP_WORKER_THREADS = new IntegerDefinition(MODULE + "HTTP_WORKER_THREADS",
			"HTTP worker threads", 1, 1);
	public static final TimeDefinition HTTPS_HANDSHAKE_TIMEOUT = new TimeDefinition(MODULE + "HTTPS_HANDSHAKE_TIMEOUT",
			"HTTPS handshake timeout", DEFAULT_HTTPS_HANDSHAKE_TIMEOUT_IN_SECONDS, TimeUnit.SECONDS);

	public static final ModuleDefinitionsProvider DEFINITIONS = new ModuleDefinitionsProvider() {

		@Override
		public String getModule() {
			return MODULE;
		}

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(HTTP_PORT, 8080);
			config.set(HTTP_SERVER_SOCKET_TIMEOUT, 100000, TimeUnit.MILLISECONDS);
			config.set(HTTP_SERVER_SOCKET_BUFFER_SIZE, 8192);
			config.set(CACHE_RESPONSE_MAX_AGE, 1, TimeUnit.HOURS);
			config.set(CACHE_SIZE, 1000);
			config.set(HTTP_CONNECTION_IDLE_TIMEOUT, DEFAULT_HTTP_CONNECTION_IDLE_TIMEOUT_IN_SECONDS, TimeUnit.SECONDS);
			config.set(HTTP_WORKER_THREADS, 1);
			config.set(HTTP_CONNECT_TIMEOUT, DEFAULT_HTTP_CONNECT_TIMEOUT_IN_SECONDS, TimeUnit.SECONDS);
			config.set(HTTP_VERSION_POLICY, HttpVersion.NEGOTIATE);
			config.set(HTTPS_HANDSHAKE_TIMEOUT, DEFAULT_HTTPS_HANDSHAKE_TIMEOUT_IN_SECONDS, TimeUnit.SECONDS);
			DefinitionUtils.verify(Proxy2Config.class, config);
		}
	};

	static {
		Configuration.addDefaultModule(DEFINITIONS);
	}

	/**
	 * Register definitions of this module to the default definitions. Register
	 * the required definitions of {@link CoapConfig} and {@link SystemConfig}
	 * as well.
	 */
	public static void register() {
		CoapConfig.register();
	}

}
