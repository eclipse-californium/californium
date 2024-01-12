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
package org.eclipse.californium.elements.config;

import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.config.Configuration.ModuleDefinitionsProvider;

/**
 * Configuration definitions for TCP/TLS.
 * 
 * @since 3.0
 */
public final class TcpConfig {

	public static final String MODULE = "TCP.";

	/**
	 * The default tcp connection idle timeout in seconds.
	 * <p>
	 * The default value is 10s.
	 */
	public static final int DEFAULT_TCP_CONNECTION_IDLE_TIMEOUT_IN_SECONDS = 10;

	/**
	 * The default tcp connect timeout in seconds.
	 * <p>
	 * The default value is 10s.
	 */
	public static final int DEFAULT_TCP_CONNECT_TIMEOUT_IN_SECONDS = 10;

	/**
	 * The default tls handshake timeout in seconds.
	 * <p>
	 * The default value is 10s.
	 */
	public static final int DEFAULT_TLS_HANDSHAKE_TIMEOUT_IN_SECONDS = 10;

	/**
	 * TCP connection idle timeout. Drop connection, if a quiet period reaches
	 * that timeout.
	 */
	public static final TimeDefinition TCP_CONNECTION_IDLE_TIMEOUT = new TimeDefinition(
			MODULE + "CONNECTION_IDLE_TIMEOUT", "TCP connection idle timeout.",
			DEFAULT_TCP_CONNECTION_IDLE_TIMEOUT_IN_SECONDS, TimeUnit.SECONDS);
	/**
	 * TCP connect timeout.
	 */
	public static final TimeDefinition TCP_CONNECT_TIMEOUT = new TimeDefinition(MODULE + "CONNECT_TIMEOUT",
			"TCP connect timeout.", DEFAULT_TCP_CONNECT_TIMEOUT_IN_SECONDS, TimeUnit.SECONDS);
	/**
	 * Number of TCP worker threads.
	 * 
	 * Since 3.9: supports value {@code 0} for the default value of the TCP
	 * implementation, e.g. of netty.io.
	 */
	public static final IntegerDefinition TCP_WORKER_THREADS = new IntegerDefinition(MODULE + "WORKER_THREADS",
			"Number of TCP worker threads. 0 to use default of TCP implementation.", 0, 0);
	/**
	 * TLS handshake timeout.
	 */
	public static final TimeDefinition TLS_HANDSHAKE_TIMEOUT = new TimeDefinition(MODULE + "HANDSHAKE_TIMEOUT",
			"TLS handshake timeout.", 10L, TimeUnit.SECONDS);
	/**
	 * TLS session timeout.
	 */
	public static final TimeDefinition TLS_SESSION_TIMEOUT = new TimeDefinition(MODULE + "SESSION_TIMEOUT",
			"TLS session timeout.", 1L, TimeUnit.HOURS);
	/**
	 * TLS client authentication mode.
	 */
	public static final EnumDefinition<CertificateAuthenticationMode> TLS_CLIENT_AUTHENTICATION_MODE = new EnumDefinition<>(
			MODULE + "CLIENT_AUTHENTICATION_MODE", "TLS client authentication mode.",
			CertificateAuthenticationMode.WANTED, CertificateAuthenticationMode.values());
	/**
	 * Enable the TLS client to verify the server certificate's subjects.
	 */
	public static final BooleanDefinition TLS_VERIFY_SERVER_CERTIFICATES_SUBJECT = new BooleanDefinition(
			MODULE + "VERIFY_SERVER_CERTIFICATES_SUBJECT", "TLS verifies the server certificate's subjects.", true);

	public static final ModuleDefinitionsProvider DEFINITIONS = new ModuleDefinitionsProvider() {

		@Override
		public String getModule() {
			return MODULE;
		}

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(TCP_WORKER_THREADS, 0);
			config.set(TCP_CONNECTION_IDLE_TIMEOUT, DEFAULT_TCP_CONNECTION_IDLE_TIMEOUT_IN_SECONDS, TimeUnit.SECONDS);
			config.set(TCP_CONNECT_TIMEOUT, DEFAULT_TCP_CONNECT_TIMEOUT_IN_SECONDS, TimeUnit.SECONDS);
			config.set(TLS_HANDSHAKE_TIMEOUT, DEFAULT_TLS_HANDSHAKE_TIMEOUT_IN_SECONDS, TimeUnit.SECONDS);
			config.set(TLS_SESSION_TIMEOUT, 1, TimeUnit.HOURS);
			config.set(TLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.WANTED);
			config.set(TLS_VERIFY_SERVER_CERTIFICATES_SUBJECT, true);
			DefinitionUtils.verify(TcpConfig.class, config);
		}

	};

	static {
		Configuration.addDefaultModule(DEFINITIONS);
	}

	/**
	 * Register definitions of this module to the default definitions. Register
	 * the required definitions of {@link SystemConfig} as well.
	 */
	public static void register() {
		SystemConfig.register();
	}

}
