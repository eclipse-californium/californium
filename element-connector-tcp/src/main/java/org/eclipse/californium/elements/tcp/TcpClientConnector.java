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
 * Achim Kraus (Bosch Software Innovations GmbH) - add correlation context
 *                                                 use "any/0.0.0.0" instead
 *                                                 of "localhost/127.0.0.1".
 * Achim Kraus (Bosch Software Innovations GmbH) - add remote to onNewChannelCreated
 *                                                 for "remote aware" SSLEngine
 * Achim Kraus (Bosch Software Innovations GmbH) - dummy CorrelationContextMatcher
 *                                                 (implemented afterwards)
 * Achim Kraus (Bosch Software Innovations GmbH) - add TcpCorrelationContextMatcher
 *                                                 implementation
 * Achim Kraus (Bosch Software Innovations GmbH) - add onSent() and onError(). 
 *                                                 issue #305
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.pool.AbstractChannelPoolHandler;
import io.netty.channel.pool.AbstractChannelPoolMap;
import io.netty.channel.pool.ChannelPool;
import io.netty.channel.pool.FixedChannelPool;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.timeout.IdleStateHandler;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.CorrelationContext;
import org.eclipse.californium.elements.CorrelationContextMatcher;
import org.eclipse.californium.elements.CorrelationMismatchException;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URI;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * TCP client connection is used by CoapEndpoint when instantiated by the CoapClient. Per RFC the client can both
 * send and receive messages, but cannot accept new incoming connections.
 */
public class TcpClientConnector implements Connector {

	private static final Logger LOGGER = Logger.getLogger(TcpClientConnector.class.getName());

	private final URI listenUri;
	private final int numberOfThreads;
	private final int connectionIdleTimeoutSeconds;
	private final int connectTimeoutMillis;
	private final InetSocketAddress localSocketAddress = new InetSocketAddress(0);
	/**
	 * Correlation context matcher for outgoing messages.
	 * 
	 * @see #setCorrelationContextMatcher(CorrelationContextMatcher)
	 * @see #getCorrelationContextMatcher()
	 */
	private CorrelationContextMatcher correlationContextMatcher;
	private EventLoopGroup workerGroup;
	private RawDataChannel rawDataChannel;
	private AbstractChannelPoolMap<SocketAddress, ChannelPool> poolMap;

	public TcpClientConnector(int numberOfThreads, int connectTimeoutMillis, int idleTimeout) {
		this.numberOfThreads = numberOfThreads;
		this.connectionIdleTimeoutSeconds = idleTimeout;
		this.connectTimeoutMillis = connectTimeoutMillis;
		this.listenUri = URI.create(String.format("%s://%s:%d", getSupportedScheme(),
				localSocketAddress.getHostString(), localSocketAddress.getPort()));
	}

	@Override public synchronized void start() throws IOException {
		if (rawDataChannel == null) {
			throw new IllegalStateException("Cannot start without message handler.");
		}

		if (workerGroup != null) {
			throw new IllegalStateException("Connector already started");
		}

		workerGroup = new NioEventLoopGroup(numberOfThreads);
		poolMap = new AbstractChannelPoolMap<SocketAddress, ChannelPool>() {

			@Override protected ChannelPool newPool(SocketAddress key) {
				Bootstrap bootstrap = new Bootstrap().group(workerGroup).channel(NioSocketChannel.class)
						.option(ChannelOption.SO_KEEPALIVE, true).option(ChannelOption.AUTO_READ, true)
						.option(ChannelOption.CONNECT_TIMEOUT_MILLIS, connectTimeoutMillis).remoteAddress(key);

				// We multiplex over the same TCP connection, so don't acquire more than one connection per endpoint.
				// TODO: But perhaps we could make it a configurable property.
				return new FixedChannelPool(bootstrap, new MyChannelPoolHandler(key), 1);
			}
		};
	}

	@Override public synchronized void stop() {
		if (null != workerGroup) {
			workerGroup.shutdownGracefully(0, 1, TimeUnit.SECONDS).syncUninterruptibly();
			workerGroup = null;
		}
	}

	@Override public void destroy() {
		stop();
	}

	@Override
	public void send(final RawData msg) {
		InetSocketAddress addressKey = new InetSocketAddress(msg.getAddress(), msg.getPort());
		final CorrelationContextMatcher correlationMatcher = getCorrelationContextMatcher();
		/* check, if a new connection should be established */
		if (null != correlationMatcher && !poolMap.contains(addressKey)
				&& !correlationMatcher.isToBeSent(msg.getCorrelationContext(), null)) {
			if (LOGGER.isLoggable(Level.WARNING)) {
				LOGGER.log(Level.WARNING, "TcpConnector (drops {0} bytes to {1}:{2}",
						new Object[] { msg.getSize(), msg.getAddress(), msg.getPort() });
			}
			msg.onError(new CorrelationMismatchException());
			return;
		}
		final ChannelPool channelPool = poolMap.get(addressKey);
		Future<Channel> acquire = channelPool.acquire();
		acquire.addListener(new GenericFutureListener<Future<Channel>>() {

			@Override
			public void operationComplete(Future<Channel> future) throws Exception {
				if (future.isSuccess()) {
					Channel channel = future.getNow();
					CorrelationContext context = NettyContextUtils.buildCorrelationContext(channel);
					try {
						/* check, if the message should be sent with the established connection */
						if (null != correlationMatcher
								&& !correlationMatcher.isToBeSent(msg.getCorrelationContext(), context)) {
							if (LOGGER.isLoggable(Level.WARNING)) {
								LOGGER.log(Level.WARNING, "TcpConnector (drops {0} bytes to {1}:{2}",
										new Object[] { msg.getSize(), msg.getAddress(), msg.getPort() });
							}
							msg.onError(new CorrelationMismatchException());
							return;
						}
						msg.onContextEstablished(context);
						ChannelFuture channelFuture = channel.writeAndFlush(Unpooled.wrappedBuffer(msg.getBytes()));
						channelFuture.addListener(new GenericFutureListener<ChannelFuture>() {

							@Override
							public void operationComplete(ChannelFuture future) throws Exception {
								if (future.isSuccess()) {
									msg.onSent();
								} else if (future.isCancelled()) {
									msg.onError(new CancellationException());
								} else {
									msg.onError(future.cause());
								}
							}
						});
					} finally {
						channelPool.release(channel);
					}
				} else {
					LOGGER.log(Level.WARNING, "Unable to open connection to " + msg.getAddress(), future.cause());
				}
			}
		});
	}

	@Override public void setRawDataReceiver(RawDataChannel messageHandler) {
		if (rawDataChannel != null) {
			throw new IllegalStateException("Raw data channel already set.");
		}

		this.rawDataChannel = messageHandler;
	}

	@Override
	public synchronized void setCorrelationContextMatcher(CorrelationContextMatcher matcher) {
		correlationContextMatcher = matcher;
	}

	private synchronized CorrelationContextMatcher getCorrelationContextMatcher() {
		return correlationContextMatcher;
	}

	@Override public InetSocketAddress getAddress() {
		// Client TCP connector doesn't really have an address it binds to.
		return localSocketAddress;
	}

	/**
	 * Called when a new channel is created, Allows subclasses to add their own handlers first, like an SSL handler.
	 * At this stage the channel is not connected, and therefore the {@link Channel#remoteAddress()} is null. To create
	 * a "remote peer" aware SSLEngine, provide the remote address as additional parameter.
	 * @param remote remote address the channel will be connected to.
	 * @param ch new created channel
	 */
	protected void onNewChannelCreated(SocketAddress remote, Channel ch) {
	}

	protected String getSupportedScheme() {
		return "coap+tcp";
	}

	@Override
	public final boolean isSchemeSupported(String scheme) {
		return getSupportedScheme().equals(scheme);
	}

	@Override
	public final URI getUri() {
		return listenUri;
	}

	private class MyChannelPoolHandler extends AbstractChannelPoolHandler {

		private final SocketAddress key;

		MyChannelPoolHandler(SocketAddress key) {
			this.key = key;
		}

		@Override
		public void channelCreated(Channel ch) throws Exception {
			onNewChannelCreated(key, ch);

			// Handler order:
			// 1. Generate Idle events
			// 2. Close idle channels
			// 3. Remove pools when they are empty.
			// 4. Stream-to-message decoder
			// 5. Hand-off decoded messages to CoAP stack
			// 6. Close connections on errors
			ch.pipeline().addLast(new IdleStateHandler(0, 0, connectionIdleTimeoutSeconds));
			ch.pipeline().addLast(new CloseOnIdleHandler());
			ch.pipeline().addLast(new RemoveEmptyPoolHandler(key));
			ch.pipeline().addLast(new DatagramFramer());
			ch.pipeline().addLast(new DispatchHandler(rawDataChannel));
			ch.pipeline().addLast(new CloseOnErrorHandler());
		}
	}

	private class RemoveEmptyPoolHandler extends ChannelDuplexHandler {

		private final SocketAddress key;

		RemoveEmptyPoolHandler(SocketAddress key) {
			this.key = key;
		}

		@Override public void channelInactive(ChannelHandlerContext ctx) throws Exception {
			// TODO: This only works with fixed sized pool with connection one. Otherwise it's not save to remove and
			// close the pool as soon as a single channel is closed.
			poolMap.remove(key);
		}
	}
}
