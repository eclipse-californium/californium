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
 * Achim Kraus (Bosch Software Innovations GmbH) - introduce protocol,
 *                                                 remove scheme
 * Achim Kraus (Bosch Software Innovations GmbH) - add method send(), which is called after
 *                                                 acquire future, to delay sending the message
 *                                                 after TLS handshake completes overwriting
 *                                                 this method in a sub-class.
 * Bosch Software Innovations GmbH - migrate to SLF4J
 * Achim Kraus (Bosch Software Innovations GmbH) - add logs for create and close channel
 * Achim Kraus (Bosch Software Innovations GmbH) - adjust logging
 * Achim Kraus (Bosch Software Innovations GmbH) - add onConnect
 * Achim Kraus (Bosch Software Innovations GmbH) - close channel pool map before 
 *                                                 stop event loop group
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
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.EndpointMismatchException;
import org.eclipse.californium.elements.MulticastNotSupportedException;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.concurrent.CancellationException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TCP client connection is used by CoapEndpoint when instantiated by the
 * CoapClient. Per RFC the client can both send and receive messages, but cannot
 * accept new incoming connections.
 */
public class TcpClientConnector implements Connector {

	protected final Logger LOGGER = LoggerFactory.getLogger(getClass().getName());

	private final int numberOfThreads;
	private final int connectionIdleTimeoutSeconds;
	private final int connectTimeoutMillis;
	private final InetSocketAddress localSocketAddress = new InetSocketAddress(0);

	/**
	 * Endpoint context matcher for outgoing messages.
	 * 
	 * @see #setEndpointContextMatcher(EndpointContextMatcher)
	 * @see #getEndpointContextMatcher()
	 */
	private EndpointContextMatcher endpointContextMatcher;
	private EventLoopGroup workerGroup;
	private RawDataChannel rawDataChannel;
	private AbstractChannelPoolMap<SocketAddress, ChannelPool> poolMap;

	protected final TcpContextUtil contextUtil;

	public TcpClientConnector(int numberOfThreads, int connectTimeoutMillis, int idleTimeout) {
		this(numberOfThreads, connectTimeoutMillis, idleTimeout, new TcpContextUtil());
	}

	protected TcpClientConnector(int numberOfThreads, int connectTimeoutMillis, int idleTimeout, TcpContextUtil contextUtil) {
		this.numberOfThreads = numberOfThreads;
		this.connectionIdleTimeoutSeconds = idleTimeout;
		this.connectTimeoutMillis = connectTimeoutMillis;
		this.contextUtil = contextUtil;
	}

	@Override
	public synchronized void start() throws IOException {
		if (rawDataChannel == null) {
			throw new IllegalStateException("Cannot start without message handler.");
		}

		if (workerGroup != null) {
			throw new IllegalStateException("Connector already started");
		}

		workerGroup = new NioEventLoopGroup(numberOfThreads);
		poolMap = new AbstractChannelPoolMap<SocketAddress, ChannelPool>() {

			@Override
			protected ChannelPool newPool(SocketAddress key) {
				Bootstrap bootstrap = new Bootstrap()
						.group(workerGroup)
						.channel(NioSocketChannel.class)
						.option(ChannelOption.SO_KEEPALIVE, true)
						.option(ChannelOption.AUTO_READ, true)
						.option(ChannelOption.CONNECT_TIMEOUT_MILLIS, connectTimeoutMillis)
						.remoteAddress(key);

				// We multiplex over the same TCP connection, so don't acquire
				// more than one connection per endpoint.
				// TODO: But perhaps we could make it a configurable property.
				return new FixedChannelPool(bootstrap, new MyChannelPoolHandler(key), 1);
			}
		};
	}

	@Override
	public synchronized void stop() {
		if (poolMap != null) {
			poolMap.close();
		}
		if (workerGroup != null) {
			workerGroup.shutdownGracefully(0, 500, TimeUnit.MILLISECONDS).syncUninterruptibly();
			workerGroup = null;
		}
	}

	@Override
	public void destroy() {
		stop();
	}

	@Override
	public void send(final RawData msg) {
		if (msg == null) {
			throw new NullPointerException("Message must not be null");
		}
		if (msg.isMulticast()) {
			LOGGER.warn("TcpConnector drops {} bytes to multicast {}:{}", msg.getSize(), msg.getAddress(), msg.getPort());
			msg.onError(new MulticastNotSupportedException("TCP doesn't support multicast!"));
			return;
		}
		if (workerGroup == null) {
			msg.onError(new IllegalStateException("TCP client connector not running!"));
			return;
		}
		InetSocketAddress addressKey = msg.getInetSocketAddress();
		final boolean connected = poolMap.contains(addressKey);
		final EndpointContextMatcher endpointMatcher = getEndpointContextMatcher();
		/* check, if a new connection should be established */
		if (endpointMatcher != null && !connected && !endpointMatcher.isToBeSent(msg.getEndpointContext(), null)) {
			LOGGER.warn("TcpConnector drops {} bytes to new {}:{}", msg.getSize(), msg.getAddress(), msg.getPort());
			msg.onError(new EndpointMismatchException("no connection"));
			return;
		}
		if (!connected) {
			msg.onConnecting();
		}
		final ChannelPool channelPool = poolMap.get(addressKey);
		Future<Channel> acquire = channelPool.acquire();
		acquire.addListener(new GenericFutureListener<Future<Channel>>() {

			@Override
			public void operationComplete(Future<Channel> future) throws Exception {
				Throwable cause = null;
				if (future.isSuccess()) {
					Channel channel = future.getNow();
					try {
						send(channel, endpointMatcher, msg);
					} catch (Throwable t) {
						cause = t;
					} finally {
						try {
							channelPool.release(channel);
						} catch (RejectedExecutionException e) {
							LOGGER.debug("{}", e.getMessage());
						}
					}
				} else if (future.isCancelled()) {
					cause = new CancellationException();
				} else {
					cause = future.cause();
				}
				if (cause != null) {
					if (cause instanceof ConnectTimeoutException) {
						LOGGER.warn("{}", cause.getMessage());
					} else if (cause instanceof CancellationException) {
						LOGGER.debug("{}", cause.getMessage());
					} else {
						LOGGER.warn("Unable to open connection to {}", msg.getAddress(), future.cause());
					}
					msg.onError(future.cause());
				}
			}
		});
	}

	/**
	 * Send message with acquired channel.
	 * 
	 * Intended to be overridden, if message sending should be delayed to
	 * complete a TLS handshake.
	 * 
	 * @param channel acquired channel
	 * @param endpointMatcher endpoint matcher
	 * @param msg message to be send
	 */
	protected void send(final Channel channel, final EndpointContextMatcher endpointMatcher, final RawData msg) {
		EndpointContext context = contextUtil.buildEndpointContext(channel);
		/*
		 * check, if the message should be sent with the established connection
		 */
		if (endpointMatcher != null && !endpointMatcher.isToBeSent(msg.getEndpointContext(), context)) {
			LOGGER.warn("TcpConnector drops {} bytes to {}:{}", msg.getSize(), msg.getAddress(), msg.getPort());
			msg.onError(new EndpointMismatchException());
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
					LOGGER.warn("TcpConnector drops {} bytes to {}:{} caused by", msg.getSize(), msg.getAddress(), msg.getPort(), future.cause());
					msg.onError(future.cause());
				}
			}
		});
	}

	@Override
	public void setRawDataReceiver(RawDataChannel messageHandler) {
		if (rawDataChannel != null) {
			throw new IllegalStateException("Raw data channel already set.");
		}

		this.rawDataChannel = messageHandler;
	}

	@Override
	public synchronized void setEndpointContextMatcher(EndpointContextMatcher matcher) {
		endpointContextMatcher = matcher;
	}

	private synchronized EndpointContextMatcher getEndpointContextMatcher() {
		return endpointContextMatcher;
	}

	@Override
	public InetSocketAddress getAddress() {
		// Client TCP connector doesn't really have an address it binds to.
		return localSocketAddress;
	}

	/**
	 * Called when a new channel is created, Allows subclasses to add their own
	 * handlers first, like an SSL handler. At this stage the channel is not
	 * connected, and therefore the {@link Channel#remoteAddress()} is null. To
	 * create a "remote peer" aware SSLEngine, provide the remote address as
	 * additional parameter.
	 * 
	 * @param remote remote address the channel will be connected to.
	 * @param ch new created channel
	 */
	protected void onNewChannelCreated(SocketAddress remote, Channel ch) {
	}

	@Override
	public String getProtocol() {
		return "TCP";
	}

	@Override
	public String toString() {
		return getProtocol() + "-" + getAddress();
	}

	private class MyChannelPoolHandler extends AbstractChannelPoolHandler {

		private final SocketAddress key;

		MyChannelPoolHandler(SocketAddress key) {
			this.key = key;
		}

		@Override
		public void channelCreated(Channel ch) throws Exception {
			LOGGER.debug("new channel to {}", key);
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
			ch.pipeline().addLast(new DatagramFramer(contextUtil));
			ch.pipeline().addLast(new DispatchHandler(rawDataChannel));
			ch.pipeline().addLast(new CloseOnErrorHandler());
		}
	}

	private class RemoveEmptyPoolHandler extends ChannelDuplexHandler {

		private final SocketAddress key;

		RemoveEmptyPoolHandler(SocketAddress key) {
			this.key = key;
		}

		@Override
		public void channelInactive(ChannelHandlerContext ctx) throws Exception {
			// TODO: This only works with fixed sized pool with connection one.
			// Otherwise it's not save to remove and
			// close the pool as soon as a single channel is closed.
			if (poolMap.remove(key)) {
				LOGGER.debug("closed channel to {}", key);
			}
		}
	}
}
