/*******************************************************************************
 * Copyright (c) 2016 Amazon Web Services.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * <p>
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.html.
 * <p>
 * Contributors:
 * Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 * Achim Kraus (Bosch Software Innovations GmbH) - create "remote aware" SSLEngine
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import io.netty.channel.Channel;
import io.netty.handler.ssl.SslHandler;

/**
 * A TCP client connector that establishes outbound TLS connections.
 */
public class TlsClientConnector extends TcpClientConnector {

	private static final Logger LOGGER = Logger.getLogger(TlsClientConnector.class.getName());

	private final SSLContext sslContext;

	/**
	 * Creates TLS client connector with custom SSL context. Useful for using client keys, or custom trust stores. The
	 * context must be initialized by the caller.
	 */
	public TlsClientConnector(SSLContext sslContext, int numberOfThreads, int connectTimeoutMillis, int idleTimeout) {
		super(numberOfThreads, connectTimeoutMillis, idleTimeout);
		this.sslContext = sslContext;
	}

	/**
	 * Creates new TLS client connector that uses default JVM SSL configuration.
	 */
	public TlsClientConnector(int numberOfThreads, int connectTimeoutMillis, int idleTimeout) {
		super(numberOfThreads, connectTimeoutMillis, idleTimeout);

		try {
			this.sslContext = SSLContext.getInstance("TLS");
			this.sslContext.init(null, null, null);
		} catch (NoSuchAlgorithmException | KeyManagementException e) {
			throw new RuntimeException("Unable to initialize SSL context", e);
		}
	}

	@Override
	protected void onNewChannelCreated(SocketAddress remote, Channel ch) {
		SSLEngine sslEngine = createSllEngine(remote);
		sslEngine.setUseClientMode(true);
		ch.pipeline().addFirst(new SslHandler(sslEngine));
	}

	/**
	 * Create SSL engine for remote socket address.
	 * 
	 * @param remoteAddress for SSL engine
	 * @return created SSL engine
	 */
	private SSLEngine createSllEngine(SocketAddress remoteAddress) {
		if (remoteAddress instanceof InetSocketAddress) {
			InetSocketAddress remote = (InetSocketAddress) remoteAddress;
			LOGGER.log(Level.INFO, "Connection to inet {0}", remote);
			return sslContext.createSSLEngine(remote.getHostString(), remote.getPort());
		} else {
			LOGGER.log(Level.INFO, "Connection to {0}", remoteAddress);
			return sslContext.createSSLEngine();
		}
	}
}
