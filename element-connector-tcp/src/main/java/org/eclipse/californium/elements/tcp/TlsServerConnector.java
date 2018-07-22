/*******************************************************************************
 * Copyright (c) 2016, 2017 Amazon Web Services and others.
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
 * Achim Kraus (Bosch Software Innovations GmbH) - introduce protocol,
 *                                                 remove scheme
 * Achim Kraus (Bosch Software Innovations GmbH) - add client authentication mode.
 * Bosch Software Innovations GmbH - migrate to SLF4J
 * Achim Kraus (Bosch Software Innovations GmbH) - add handshake timeout
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import java.net.InetSocketAddress;
import java.net.SocketAddress;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.netty.channel.Channel;
import io.netty.handler.ssl.SslHandler;

/**
 * A TLS server connector that accepts inbound TLS connections.
 */
public class TlsServerConnector extends TcpServerConnector {

	private static final Logger LOGGER = LoggerFactory.getLogger(TlsServerConnector.class.getName());
	/**
	 * Default handshake timeout.
	 */
	private static final int DEFAULT_HANDSHAKE_TIMEOUT_MILLIS = 10000;

	public static enum ClientAuthMode {
		NONE, WANTED, NEEDED
	}

	/**
	 * Client authentication mode.
	 */
	private final ClientAuthMode clientAuthMode;
	/**
	 * SSL context.
	 */
	private final SSLContext sslContext;
	/**
	 * Handshake timeout in milliseconds.
	 */
	private final long handshakeTimeoutMillis;

	/**
	 * Initializes SSLEngine with specified SSL engine, client authentication
	 * mode, and handshake timeout.
	 * 
	 * @param sslContext ssl context.
	 * @param clientAuthMode client authentication mode
	 * @param socketAddress local server socket address
	 * @param numberOfThreads number of thread for connection
	 * @param handshakeTimeoutMillis handshake timeout in milliseconds
	 * @param idleTimeout idle timeout in seconds to close unused connection
	 */
	public TlsServerConnector(SSLContext sslContext, ClientAuthMode clientAuthMode, InetSocketAddress socketAddress,
			int numberOfThreads, int handshakeTimeoutMillis, int idleTimeout) {
		super(socketAddress, numberOfThreads, idleTimeout, new TlsContextUtil(clientAuthMode == ClientAuthMode.NEEDED));
		this.sslContext = sslContext;
		this.clientAuthMode = clientAuthMode;
		this.handshakeTimeoutMillis = handshakeTimeoutMillis;
	}

	/**
	 * Initializes SSLEngine with specified SSL engine and client authentication
	 * mode.
	 * 
	 * @param sslContext ssl context.
	 * @param clientAuthMode client authentication mode
	 * @param socketAddress local server socket address
	 * @param numberOfThreads number of thread for connection
	 * @param idleTimeout idle timeout in seconds to close unused connection
	 */
	public TlsServerConnector(SSLContext sslContext, ClientAuthMode clientAuthMode, InetSocketAddress socketAddress,
			int numberOfThreads, int idleTimeout) {
		this(sslContext, clientAuthMode, socketAddress, numberOfThreads, DEFAULT_HANDSHAKE_TIMEOUT_MILLIS, idleTimeout);
	}

	/**
	 * Initializes SSLEngine with specified SSL engine.
	 * 
	 * @param sslContext ssl context.
	 * @param socketAddress local server socket address
	 * @param numberOfThreads number of thread for connection
	 * @param idleTimeout idle timeout in seconds to close unused connection
	 */
	public TlsServerConnector(SSLContext sslContext, InetSocketAddress socketAddress, int numberOfThreads,
			int idleTimeout) {
		this(sslContext, ClientAuthMode.NONE, socketAddress, numberOfThreads, DEFAULT_HANDSHAKE_TIMEOUT_MILLIS,
				idleTimeout);
	}

	@Override
	protected void onNewChannelCreated(Channel ch) {
		SSLEngine sslEngine = createSllEngineForChannel(ch);
		switch (clientAuthMode) {
		case NONE:
			break;
		case WANTED:
			sslEngine.setWantClientAuth(true);
			break;
		case NEEDED:
			sslEngine.setNeedClientAuth(true);
			break;
		}
		sslEngine.setUseClientMode(false);
		SslHandler sslHandler = new SslHandler(sslEngine);
		sslHandler.setHandshakeTimeoutMillis(handshakeTimeoutMillis);
		ch.pipeline().addFirst(sslHandler);
	}

	@Override
	public String getProtocol() {
		return "TLS";
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
			LOGGER.info("Connection from inet {}", remote);
			return sslContext.createSSLEngine(remote.getAddress().getHostAddress(), remote.getPort());
		} else {
			LOGGER.info("Connection from {}", remoteAddress);
			return sslContext.createSSLEngine();
		}
	}

}
