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

import io.netty.channel.Channel;
import io.netty.handler.ssl.SslHandler;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A TCP client connector that establishes outbound TLS connections.
 */
public class TlsServerConnector extends TcpServerConnector {

	private static final Logger LOGGER = Logger.getLogger(TlsServerConnector.class.getName());

	private final SSLContext sslContext;

	/**
	 * Initializes SSLEngine with specified SSL engine.
	 */
	public TlsServerConnector(SSLContext sslContext, InetSocketAddress socketAddress, int numberOfThreads,
			int idleTimeout) {
		super(socketAddress, numberOfThreads, idleTimeout);
		this.sslContext = sslContext;
	}

	/**
	 * Initializes SSLEngine with specified SSL key management factory.
	 */
	public TlsServerConnector(KeyManagerFactory keyManagerFactory, InetSocketAddress socketAddress, int numberOfThreads,
			int idleTimeout) {
		super(socketAddress, numberOfThreads, idleTimeout);

		try {
			this.sslContext = SSLContext.getInstance("TLS");
			this.sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
		} catch (KeyManagementException | NoSuchAlgorithmException e) {
			throw new RuntimeException("Unable to initialize SSL engine", e);
		}
	}

	@Override protected void onNewChannelCreated(Channel ch) {
		SSLEngine sslEngine = createSllEngineForChannel(ch);
		sslEngine.setUseClientMode(false);
		ch.pipeline().addFirst(new SslHandler(sslEngine));
	}

	/**
	 * Create SSL engine for channel.
	 * 
	 * @param ch channel to determine remote host
	 * @return created SSL engine
	 */
	private SSLEngine createSllEngineForChannel(Channel ch) {
		SocketAddress remoteAddress = ch.remoteAddress();
		if (remoteAddress instanceof InetSocketAddress) {
			InetSocketAddress remote = (InetSocketAddress) remoteAddress;
			LOGGER.log(Level.INFO, "Connection from inet {0}", remote);
			return sslContext.createSSLEngine(remote.getHostString(), remote.getPort());
		} else {
			LOGGER.log(Level.INFO, "Connection from {0}", remoteAddress);
			return sslContext.createSSLEngine();
		}
	}

}
