/*******************************************************************************
 * Copyright (c) 2016, 2017 Amazon Web Services and others.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * <p>
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.html.
 * <p>
 * Contributors:
 * Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 * Achim Kraus (Bosch Software Innovations GmbH) - create "remote aware" SSLEngine
 * Achim Kraus (Bosch Software Innovations GmbH) - introduce protocol,
 *                                                 remove scheme
 * Achim Kraus (Bosch Software Innovations GmbH) - delay sending message after complete
 *                                                 TLS handshake.
 * Bosch Software Innovations GmbH - migrate to SLF4J
 * Achim Kraus (Bosch Software Innovations GmbH) - add handshake timeout
 * Achim Kraus (Bosch Software Innovations GmbH) - change exception type to
 *                                                 IllegalStateException
 ******************************************************************************/
package org.eclipse.californium.elements.tcp.netty;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.concurrent.CancellationException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.TlsEndpointContext;
import org.eclipse.californium.elements.util.StringUtil;

import io.netty.channel.Channel;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;

/**
 * A TLS client connector that establishes outbound TLS connections.
 */
public class TlsClientConnector extends TcpClientConnector {

	private static final int DEFAULT_HANDSHAKE_TIMEOUT_MILLIS = 10000;

	/**
	 * Context to be used to for connections.
	 */
	private final SSLContext sslContext;
	/**
	 * Handshake timeout in milliseconds.
	 */
	private final int handshakeTimeoutMillis;

	/**
	 * Creates TLS client connector with custom SSL context. Useful for using
	 * client keys, or custom trust stores. The context must be initialized by
	 * the caller.
	 * 
	 * @param sslContext ssl context
	 * @param numberOfThreads number of thread used by connector
	 * @param connectTimeoutMillis tcp connect timeout in milliseconds
	 * @param idleTimeout idle timeout in seconds to close unused connection.
	 */
	public TlsClientConnector(SSLContext sslContext, int numberOfThreads, int connectTimeoutMillis, int idleTimeout) {
		this(sslContext, numberOfThreads, connectTimeoutMillis, DEFAULT_HANDSHAKE_TIMEOUT_MILLIS, idleTimeout);
	}

	/**
	 * Creates TLS client connector with custom SSL context. Useful for using
	 * client keys, or custom trust stores. The context must be initialized by
	 * the caller.
	 * 
	 * @param sslContext ssl context
	 * @param numberOfThreads number of thread used by connector
	 * @param connectTimeoutMillis tcp connect timeout in milliseconds
	 * @param handshakeTimeoutMillis handshake timeout in milliseconds
	 * @param idleTimeout idle timeout in seconds to close unused connection
	 */
	public TlsClientConnector(SSLContext sslContext, int numberOfThreads, int connectTimeoutMillis,
			int handshakeTimeoutMillis, int idleTimeout) {
		super(numberOfThreads, connectTimeoutMillis, idleTimeout, new TlsContextUtil(true));
		this.sslContext = sslContext;
		this.handshakeTimeoutMillis = handshakeTimeoutMillis;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Delay message sending after TLS handshake is completed.
	 */
	@Override
	protected void send(final Channel channel, final EndpointContextMatcher endpointMatcher, final RawData msg) {
		final SslHandler sslHandler = channel.pipeline().get(SslHandler.class);
		if (sslHandler == null) {
			msg.onError(new IllegalStateException("Missing SslHandler"));
		} else {
			/*
			 * Trigger handshake.
			 */
			Future<Channel> handshakeFuture = sslHandler.handshakeFuture();
			handshakeFuture.addListener(new GenericFutureListener<Future<Channel>>() {

				@Override
				public void operationComplete(Future<Channel> future) throws Exception {
					if (future.isSuccess()) {
						EndpointContext context = contextUtil.buildEndpointContext(channel);
						if (context == null || context.get(TlsEndpointContext.KEY_SESSION_ID) == null) {
							msg.onError(new IllegalStateException("Missing TlsEndpointContext " + context));
							return;
						}
						/*
						 * Handshake succeeded! 
						 * Call super.send() to actually send the message.
						 */
						TlsClientConnector.super.send(future.getNow(), endpointMatcher, msg);
					} else if (future.isCancelled()) {
						msg.onError(new CancellationException());
					} else {
						msg.onError(future.cause());
					}
				}
			});
		}
	}

	@Override
	protected void onNewChannelCreated(SocketAddress remote, Channel ch) {
		SSLEngine sslEngine = createSllEngine(remote);
		sslEngine.setUseClientMode(true);
		SslHandler sslHandler = new SslHandler(sslEngine);
		sslHandler.setHandshakeTimeoutMillis(handshakeTimeoutMillis);
		ch.pipeline().addFirst(sslHandler);
	}

	@Override
	public String getProtocol() {
		return "TLS";
	}

	/**
	 * Create SSL engine for remote socket address.
	 * 
	 * @param remoteAddress for SSL engine
	 * @return created SSL engine
	 */
	private SSLEngine createSllEngine(SocketAddress remoteAddress) {
		if (remoteAddress instanceof InetSocketAddress) {
			LOGGER.info("Connection to inet {}", StringUtil.toLog(remoteAddress));
			InetSocketAddress remote = (InetSocketAddress) remoteAddress;
			return sslContext.createSSLEngine(remote.getAddress().getHostAddress(), remote.getPort());
		} else {
			LOGGER.info("Connection to {}", StringUtil.toLog(remoteAddress));
			return sslContext.createSSLEngine();
		}
	}
}
