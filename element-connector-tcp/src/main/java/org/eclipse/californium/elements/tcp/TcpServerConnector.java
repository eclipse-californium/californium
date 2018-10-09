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
package org.eclipse.californium.elements.tcp;

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
import org.eclipse.californium.elements.EndpointMismatchException;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TCP server connection is used by CoapEndpoint when instantiated by the CoapServer. Per RFC the server can both
 * send and receive messages, but cannot initiated new outgoing connections.
 */
public class TcpServerConnector implements Connector {

	private static final Logger LOGGER = LoggerFactory.getLogger(TcpServerConnector.class.getName());

	private final int numberOfThreads;
	private final int connectionIdleTimeoutSeconds;
	private final TcpContextUtil contextUtil;
	private final ConcurrentMap<SocketAddress, Channel> activeChannels = new ConcurrentHashMap<>();

	/**
	 * Endpoint context matcher for outgoing messages.
	 * 
	 * @see #setEndpointContextMatcher(EndpointContextMatcher)
	 * @see #getEndpointContextMatcher()
	 */
	private EndpointContextMatcher endpointContextMatcher;

	private RawDataChannel rawDataChannel;
	private EventLoopGroup bossGroup;
	private EventLoopGroup workerGroup;
	private InetSocketAddress localAddress;

	public TcpServerConnector(InetSocketAddress localAddress, int numberOfThreads, int idleTimeout) {
		this(localAddress, numberOfThreads, idleTimeout, new TcpContextUtil());
	}

	protected TcpServerConnector(InetSocketAddress localAddress, int numberOfThreads, int idleTimeout, TcpContextUtil contextUtil) {
		this.numberOfThreads = numberOfThreads;
		this.connectionIdleTimeoutSeconds = idleTimeout;
		this.localAddress = localAddress;
		this.contextUtil = contextUtil;
	}

	@Override
	public synchronized void start() throws IOException {
		if (rawDataChannel == null) {
			throw new IllegalStateException("Cannot start without message handler.");
		}
		if (bossGroup != null) {
			throw new IllegalStateException("Connector already started");
		}
		if (workerGroup != null) {
			throw new IllegalStateException("Connector already started");
		}

		bossGroup = new NioEventLoopGroup(1);
		workerGroup = new NioEventLoopGroup(numberOfThreads);

		ServerBootstrap bootstrap = new ServerBootstrap();
		// server socket 
		bootstrap.group(bossGroup, workerGroup).channel(NioServerSocketChannel.class)
				.option(ChannelOption.SO_BACKLOG, 100).option(ChannelOption.AUTO_READ, true)
				.childHandler(new ChannelRegistry());
		// connection socket
		bootstrap.childOption(ChannelOption.SO_KEEPALIVE, true);

		// Start the server.
		ChannelFuture channelFuture = bootstrap.bind(localAddress).syncUninterruptibly();

		if (channelFuture.isSuccess() && 0 == localAddress.getPort()) {
			// replace port with the assigned one
			InetSocketAddress listenAddress = (InetSocketAddress) channelFuture.channel().localAddress();
			localAddress = new InetSocketAddress(localAddress.getAddress(), listenAddress.getPort());
		}
	}

	@Override
	public synchronized void stop() {
		if (null != bossGroup) {
			bossGroup.shutdownGracefully(0, 1, TimeUnit.SECONDS).syncUninterruptibly();
			bossGroup = null;
		}
		if (null != workerGroup) {
			workerGroup.shutdownGracefully(0, 1, TimeUnit.SECONDS).syncUninterruptibly();
			workerGroup = null;
		}
	}

	@Override
	public void destroy() {
		stop();
	}

	@Override
	public void send(final RawData msg) {
		Channel channel = activeChannels.get(msg.getInetSocketAddress());
		if (channel == null) {
			// TODO: Is it worth allowing opening a new connection when in server mode?
			LOGGER.warn("Attempting to send message to an address without an active connection {}",
					msg.getAddress());
			msg.onError(new EndpointMismatchException());
			return;
		}
		EndpointContext context = contextUtil.buildEndpointContext(channel);
		final EndpointContextMatcher endpointMatcher = getEndpointContextMatcher();
		/* check, if the message should be sent with the established connection */
		if (null != endpointMatcher
				&& !endpointMatcher.isToBeSent(msg.getEndpointContext(), context)) {
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
					msg.onError(future.cause());
				}
			}
		});
	}

	@Override
	public void setRawDataReceiver(RawDataChannel messageHandler) {
		if (rawDataChannel != null) {
			throw new IllegalStateException("RawDataChannel alrady set");
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
	public synchronized InetSocketAddress getAddress() {
		return localAddress;
	}

	/**
	 * Called when a new channel is created, Allows subclasses to add their own handlers first, like an SSL handler.
	 */
	protected void onNewChannelCreated(Channel ch) {
		
	}


	@Override
	public String getProtocol() {
		return "TCP";
	}

	@Override
	public String toString() {
		return getProtocol() + "-" + getAddress();
	}	

	private class ChannelRegistry extends ChannelInitializer<SocketChannel> {

		@Override
		protected void initChannel(SocketChannel ch) throws Exception {
			onNewChannelCreated(ch);

			// Handler order:
			// 0. Register/unregister new channel: all messages can only be sent over open connections.
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

	/** Tracks active channels to send messages over them. TCPServer connector does not establish new connections. */
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
