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
package org.eclipse.californium.elements.tcp.netty;

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
import org.eclipse.californium.elements.exception.EndpointMismatchException;
import org.eclipse.californium.elements.exception.MulticastNotSupportedException;
import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.TcpConfig;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.ClosedChannelException;
import java.util.concurrent.CancellationException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TCP client connection is used by CoapEndpoint when instantiated by the
 * CoapClient. Per RFC the client can both send and receive messages, but cannot
 * accept new incoming connections.
 */
public class TcpClientConnector implements Connector {

	private static final AtomicInteger THREAD_COUNTER = new AtomicInteger();
	private static final ThreadGroup TCP_THREAD_GROUP = new ThreadGroup("Californium/TCP-Client"); //$NON-NLS-1$

	static {
		TCP_THREAD_GROUP.setDaemon(false);
	}

	/**
	 * The logger.
	 * 
	 * @deprecated scope will change to private.
	 */
	@Deprecated
	protected final Logger LOGGER = LoggerFactory.getLogger(getClass());

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
	private volatile EndpointContextMatcher endpointContextMatcher;

	protected volatile boolean running;

	private EventLoopGroup workerGroup;
	private RawDataChannel rawDataChannel;
	private AbstractChannelPoolMap<SocketAddress, ChannelPool> poolMap;

	protected final TcpContextUtil contextUtil;

	/**
	 * Create TCP client.
	 * 
	 * @param configuration configuration with {@link TcpConfig} definitions.
	 * @since 3.0
	 */
	public TcpClientConnector(Configuration configuration) {
		this(configuration, new TcpContextUtil());
	}

	/**
	 * Create TCP client with specific context utility.
	 * 
	 * @param configuration configuration with {@link TcpConfig} definitions.
	 * @param contextUtil context utility
	 * @since 3.0
	 */
	protected TcpClientConnector(Configuration configuration, TcpContextUtil contextUtil) {
		this.numberOfThreads = configuration.get(TcpConfig.TCP_WORKER_THREADS);
		this.connectionIdleTimeoutSeconds = configuration.getTimeAsInt(TcpConfig.TCP_CONNECTION_IDLE_TIMEOUT,
				TimeUnit.SECONDS);
		this.connectTimeoutMillis = configuration.getTimeAsInt(TcpConfig.TCP_CONNECT_TIMEOUT, TimeUnit.MILLISECONDS);
		this.contextUtil = contextUtil;
	}

	@Override
	public boolean isRunning() {
		return running;
	}

	@Override
	public synchronized void start() throws IOException {
		if (rawDataChannel == null) {
			throw new IllegalStateException("Cannot start without message handler.");
		}
		if (running || workerGroup != null) {
			throw new IllegalStateException("Connector already started");
		}
		running = true;
		workerGroup = new NioEventLoopGroup(numberOfThreads,
				new DaemonThreadFactory("TCP-Client-" + THREAD_COUNTER.incrementAndGet() + "#", TCP_THREAD_GROUP));
		poolMap = new AbstractChannelPoolMap<SocketAddress, ChannelPool>() {

			@Override
			protected ChannelPool newPool(SocketAddress key) {
				Bootstrap bootstrap = new Bootstrap().group(workerGroup).channel(NioSocketChannel.class)
						.option(ChannelOption.SO_KEEPALIVE, true).option(ChannelOption.AUTO_READ, true)
						.option(ChannelOption.CONNECT_TIMEOUT_MILLIS, connectTimeoutMillis).remoteAddress(key);

				// We multiplex over the same TCP connection, so don't acquire
				// more than one connection per endpoint.
				// TODO: But perhaps we could make it a configurable property.
				return new FixedChannelPool(bootstrap, new MyChannelPoolHandler(key), 1);
			}
		};
	}

	@Override
	public synchronized void stop() {
		if (running) {
			LOGGER.debug("Stopping {} client connector ...", getProtocol());
			running = false;
			if (poolMap != null) {
				poolMap.close();
			}
			if (workerGroup != null) {
				// FixedChannelPool requires a quietPeriod be larger than 0
				workerGroup.shutdownGracefully(50, 500, TimeUnit.MILLISECONDS).syncUninterruptibly();
				workerGroup = null;
			}
			LOGGER.debug("Stopped {} client connector", getProtocol());
		}
	}

	@Override
	public void destroy() {
		stop();
	}

	@Override
	public void processDatagram(DatagramPacket datagram) {
	}

	@Override
	public void send(final RawData msg) {
		if (msg == null) {
			throw new NullPointerException("Message must not be null");
		}
		if (msg.isMulticast()) {
			LOGGER.warn("TcpConnector drops {} bytes to multicast {}", msg.getSize(),
					StringUtil.toLog(msg.getInetSocketAddress()));
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
			LOGGER.warn("TcpConnector drops {} bytes to new {}", msg.getSize(),
					StringUtil.toLog(msg.getInetSocketAddress()));
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
						LOGGER.debug("{}", cause.getMessage());
					} else if (cause instanceof CancellationException) {
						if (isRunning()) {
							LOGGER.debug("{}", cause.getMessage());
						} else {
							LOGGER.trace("{}", cause.getMessage());
						}
					} else if (cause instanceof IllegalStateException) {
						if (isRunning()) {
							LOGGER.debug("{}", cause.getMessage());
						} else {
							LOGGER.trace("{}", cause.getMessage());
						}
					} else {
						LOGGER.warn("Unable to open connection to {}", StringUtil.toLog(msg.getInetSocketAddress()),
								future.cause());
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
			LOGGER.warn("TcpConnector drops {} bytes to {}", msg.getSize(),
					StringUtil.toLog(msg.getInetSocketAddress()));
			msg.onError(new EndpointMismatchException("TCP"));
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
					Throwable cause = future.cause();
					if (cause instanceof ClosedChannelException) {
						if (isRunning()) {
							LOGGER.debug("TcpConnector drops {} bytes to {}, connection closed!", msg.getSize(),
									StringUtil.toLog(msg.getInetSocketAddress()));
						} else {
							LOGGER.trace("TcpConnector drops {} bytes to {}, connection closed!", msg.getSize(),
									StringUtil.toLog(msg.getInetSocketAddress()));
						}
					} else {
						LOGGER.warn("TcpConnector drops {} bytes to {} caused by", msg.getSize(),
								StringUtil.toLog(msg.getInetSocketAddress()), cause);
					}
					msg.onError(cause);
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
	public void setEndpointContextMatcher(EndpointContextMatcher matcher) {
		endpointContextMatcher = matcher;
	}

	private EndpointContextMatcher getEndpointContextMatcher() {
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
		return getProtocol() + "-" + StringUtil.toString(getAddress());
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
			ch.pipeline().addLast(new RemoveEmptyPoolHandler(poolMap, key));
			ch.pipeline().addLast(new DatagramFramer(contextUtil));
			ch.pipeline().addLast(new DispatchHandler(rawDataChannel));
			ch.pipeline().addLast(new CloseOnErrorHandler());
		}
	}

	private class RemoveEmptyPoolHandler extends ChannelDuplexHandler {

		private final AbstractChannelPoolMap<SocketAddress, ChannelPool> poolMap;
		private final SocketAddress key;

		RemoveEmptyPoolHandler(AbstractChannelPoolMap<SocketAddress, ChannelPool> poolMap, SocketAddress key) {
			this.poolMap = poolMap;
			this.key = key;
		}

		@Override
		public void channelInactive(ChannelHandlerContext ctx) throws Exception {
			if (poolMap.remove(key)) {
				LOGGER.trace("removed channel pool for {}", key);
			}
		}
	}
}
