/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.cli.tcp.netty;

import java.security.GeneralSecurityException;
import java.util.concurrent.ExecutorService;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;

import org.eclipse.californium.cli.CliConnectorFactory;
import org.eclipse.californium.cli.ClientBaseConfig;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.tcp.netty.TlsClientConnector;
import org.eclipse.californium.elements.util.SslContextUtil;

/**
 * TLS connector factory for CLI.
 * 
 * @since 2.4
 */
public class TlsConnectorFactory implements CliConnectorFactory {

	private static final String ALIAS = "client";

	@Override
	public Connector create(ClientBaseConfig clientConfig, ExecutorService executor) {
		NetworkConfig config = clientConfig.networkConfig;
		int tcpThreads = config.getInt(Keys.TCP_WORKER_THREADS);
		int tcpConnectTimeout = config.getInt(Keys.TCP_CONNECT_TIMEOUT);
		int tlsHandshakeTimeout = config.getInt(Keys.TLS_HANDSHAKE_TIMEOUT);
		int tcpIdleTimeout = config.getInt(Keys.TCP_CONNECTION_IDLE_TIMEOUT);
		int maxPeers = config.getInt(Keys.MAX_ACTIVE_PEERS);
		int sessionTimeout = config.getInt(Keys.SECURE_SESSION_TIMEOUT);

		SSLContext clientSslContext = null;
		try {
			KeyManager[] keyManager;
			if (clientConfig.authentication.anonymous) {
				keyManager = SslContextUtil.createAnonymousKeyManager();
			} else {
				keyManager = SslContextUtil.createKeyManager(ALIAS,
						clientConfig.authentication.credentials.getPrivateKey(),
						clientConfig.authentication.credentials.getCertificateChain());
			}
			TrustManager[] trustManager;
			if (clientConfig.trust.trustall) {
				trustManager = SslContextUtil.createTrustAllManager();
			} else {
				trustManager = SslContextUtil.createTrustManager(ALIAS, clientConfig.trust.trusts);
			}
			clientSslContext = SSLContext.getInstance(SslContextUtil.DEFAULT_SSL_PROTOCOL);
			clientSslContext.init(keyManager, trustManager, null);
			SSLSessionContext clientSessionContext = clientSslContext.getClientSessionContext();
			if (clientSessionContext != null) {
				clientSessionContext.setSessionTimeout(sessionTimeout);
				clientSessionContext.setSessionCacheSize(maxPeers);
			}
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		return new TlsClientConnector(clientSslContext, tcpThreads, tcpConnectTimeout, tlsHandshakeTimeout,
				tcpIdleTimeout);
	}
}
