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
 * Achim Kraus (Bosch Software Innovations GmbH) - adjust port when bound.
 * Achim Kraus (Bosch Software Innovations GmbH) - use CloseOnErrorHandler.
 * Achim Kraus (Bosch Software Innovations GmbH) - add correlation context.
 * Achim Kraus (Bosch Software Innovations GmbH) - dummy CorrelationContextMatcher
 *                                                 (implemented afterwards)
 * Achim Kraus (Bosch Software Innovations GmbH) - add TcpCorrelationContextMatcher
 *                                                 implementation
 * Achim Kraus (Bosch Software Innovations GmbH) - add onSent() and onError(). 
 *                                                 issue #305
 * Achim Kraus (Bosch Software Innovations GmbH) - introduce protocol,
 *                                                 remove scheme
 * Bosch Software Innovations GmbH - migrate to SLF4J
 * Achim Kraus (Bosch Software Innovations GmbH) - move SO_KEEPALIVE to child options.
 ******************************************************************************/
package org.eclipse.californium.elements.tcp.netty;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.timeout.IdleStateHandler;
import io.netty.util.concurrent.GenericFutureListener;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.exception.EndpointMismatchException;
import org.eclipse.californium.elements.exception.EndpointUnconnectedException;
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
import java.util.concurrent.CancellationException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TCP server connection is used by CoapEndpoint when instantiated by the
 * CoapServer. Per RFC the server can both send and receive messages, but cannot
 * initiated new outgoing connections.
 */
public class TcpServerConnector implements Connector {

	private static final AtomicInteger THREAD_COUNTER = new AtomicInteger();
	private static final ThreadGroup TCP_THREAD_GROUP = new ThreadGroup("Californium/TCP-Server"); //$NON-NLS-1$

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
	private final InetSocketAddress localAddress;
	private final TcpContextUtil contextUtil;
	private final ConcurrentMap<SocketAddress, Channel> activeChannels = new ConcurrentHashMap<>();

	/**
	 * Endpoint context matcher for outgoing messages.
	 * 
	 * @see #setEndpointContextMatcher(EndpointContextMatcher)
	 * @see #getEndpointContextMatcher()
	 */
	private volatile EndpointContextMatcher endpointContextMatcher;
	private volatile InetSocketAddress effectiveLocalAddress;

	protected volatile boolean running;

	private RawDataChannel rawDataChannel;
	private EventLoopGroup bossGroup;
	private EventLoopGroup workerGroup;

	public TcpServerConnector(InetSocketAddress localAddress, Configuration configuration) {
		this(localAddress, configuration, new TcpContextUtil());
	}

	protected TcpServerConnector(InetSocketAddress localAddress, Configuration configuration,
			TcpContextUtil contextUtil) {
		this.numberOfThreads = configuration.get(TcpConfig.TCP_WORKER_THREADS);
		this.connectionIdleTimeoutSeconds = configuration.getTimeAsInt(TcpConfig.TCP_CONNECTION_IDLE_TIMEOUT,
				TimeUnit.SECONDS);
		this.localAddress = localAddress;
		this.contextUtil = contextUtil;
		this.effectiveLocalAddress = localAddress;
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
		if (running || bossGroup != null || workerGroup != null) {
			throw new IllegalStateException("Connector already started");
		}
		running = true;
		int id = THREAD_COUNTER.incrementAndGet();
		bossGroup = new NioEventLoopGroup(1, new DaemonThreadFactory("TCP-Server-" + id, TCP_THREAD_GROUP));
		workerGroup = new NioEventLoopGroup(numberOfThreads,
				new DaemonThreadFactory("TCP-Server-" + id + "#", TCP_THREAD_GROUP));

		ServerBootstrap bootstrap = new ServerBootstrap();
		// server socket
		bootstrap.group(bossGroup, workerGroup).channel(NioServerSocketChannel.class)
				.childHandler(new ChannelRegistry()).option(ChannelOption.SO_BACKLOG, 100)
				.option(ChannelOption.AUTO_READ, true).childOption(ChannelOption.SO_KEEPALIVE, true);

		// Start the server.
		ChannelFuture channelFuture = bootstrap.bind(localAddress).syncUninterruptibly();

		if (channelFuture.isSuccess() && 0 == localAddress.getPort()) {
			// replace port with the assigned one
			InetSocketAddress listenAddress = (InetSocketAddress) channelFuture.channel().localAddress();
			effectiveLocalAddress = new InetSocketAddress(localAddress.getAddress(), listenAddress.getPort());
		}
	}

	@Override
	public synchronized void stop() {
		if (running) {
			running = false;
			LOGGER.debug("Stopping {} server connector on [{}]", getProtocol(), effectiveLocalAddress);
			if (null != bossGroup) {
				bossGroup.shutdownGracefully(0, 500, TimeUnit.MILLISECONDS).syncUninterruptibly();
				bossGroup = null;
			}
			if (null != workerGroup) {
				workerGroup.shutdownGracefully(0, 500, TimeUnit.MILLISECONDS).syncUninterruptibly();
				workerGroup = null;
			}
			LOGGER.debug("Stopped {} server connector on [{}]", getProtocol(), effectiveLocalAddress);
			effectiveLocalAddress = localAddress;
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
		if (bossGroup == null) {
			msg.onError(new IllegalStateException("TCP server connector not running!"));
			return;
		}
		Channel channel = activeChannels.get(msg.getInetSocketAddress());
		if (channel == null) {
			// TODO: Is it worth allowing opening a new connection when in
			// server mode?
			LOGGER.debug("Attempting to send message to an address without an active connection {}",
					StringUtil.toLog(msg.getInetSocketAddress()));
			msg.onError(new EndpointUnconnectedException(getProtocol() + " client not connected!"));
			return;
		}
		EndpointContext context = contextUtil.buildEndpointContext(channel);
		final EndpointContextMatcher endpointMatcher = getEndpointContextMatcher();
		/*
		 * check, if the message should be sent with the established connection
		 */
		if (null != endpointMatcher && !endpointMatcher.isToBeSent(msg.getEndpointContext(), context)) {
			LOGGER.warn("TcpConnector drops {} bytes to {}", msg.getSize(),
					StringUtil.toLog(msg.getInetSocketAddress()));
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
					msg.onError(future.cause());
				}
			}
		});
	}

	@Override
	public void setRawDataReceiver(RawDataChannel messageHandler) {
		if (rawDataChannel != null) {
			throw new IllegalStateException("RawDataChannel already set");
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
		return effectiveLocalAddress;
	}

	/**
	 * Called when a new channel is created, Allows subclasses to add their own
	 * handlers first, like an SSL handler.
	 * 
	 * @param ch channel
	 */
	protected void onNewChannelCreated(Channel ch) {

	}

	@Override
	public String getProtocol() {
		return "TCP";
	}

	@Override
	public String toString() {
		return getProtocol() + "-" + StringUtil.toString(getAddress());
	}

	private class ChannelRegistry extends ChannelInitializer<SocketChannel> {

		@Override
		protected void initChannel(SocketChannel ch) throws Exception {
			onNewChannelCreated(ch);

			// Handler order:
			// 0. Register/unregister new channel: all messages can only be sent
			// over open connections.
			// 1. Generate Idle events
			// 2. Close idle channels.
			// 3. Stream-to-message decoder
			// 4. Hand-off decoded messages to CoAP stack
			// 5. Close connections on errors.
			ch.pipeline().addLast(new ChannelTracker());
			ch.pipeline().addLast(new IdleStateHandler(0, 0, connectionIdleTimeoutSeconds));
			ch.pipeline().addLast(new CloseOnIdleHandler());
			ch.pipeline().addLast(new DatagramFramer(contextUtil));
			ch.pipeline().addLast(new DispatchHandler(rawDataChannel));
			ch.pipeline().addLast(new CloseOnErrorHandler());
		}
	}

	/**
	 * Tracks active channels to send messages over them. TCPServer connector
	 * does not establish new connections.
	 */
	private class ChannelTracker extends ChannelInboundHandlerAdapter {

		@Override
		public void channelActive(ChannelHandlerContext ctx) throws Exception {
			activeChannels.put(ctx.channel().remoteAddress(), ctx.channel());
		}

		@Override
		public void channelInactive(ChannelHandlerContext ctx) throws Exception {
			activeChannels.remove(ctx.channel().remoteAddress());
		}
	}
}
