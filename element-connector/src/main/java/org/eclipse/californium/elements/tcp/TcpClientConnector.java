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
<<<<<<< master
=======
 * Achim Kraus (Bosch Software Innovations GmbH) - add correlation context
 *                                                 use "any/0.0.0.0" instead
 *                                                 of "localhost/127.0.0.1".
 * Achim Kraus (Bosch Software Innovations GmbH) - add remote to onNewChannelCreated
 *                                                 for "remote aware" SSLEngine
 *                                                 correct "localhost" to "any".
>>>>>>> 7c53b61 Add remote peer to SSLEngine.
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
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * TCP client connection is used by CoapEndpoint when instantiated by the CoapClient. Per RFC the client can both
 * send and receive messages, but cannot accept new incoming connections.
 */
public class TcpClientConnector implements Connector, TcpConnector {

	private final static Logger LOGGER = Logger.getLogger(TcpClientConnector.class.getName());

	private final int numberOfThreads;
	private final int connectionIdleTimeoutSeconds;
	private final int connectTimeoutMillis;
	private EventLoopGroup workerGroup;
	private RawDataChannel rawDataChannel;
	private AbstractChannelPoolMap<SocketAddress, ChannelPool> poolMap;

	public TcpClientConnector(int numberOfThreads, int connectTimeoutMillis, int idleTimeout) {
		this.numberOfThreads = numberOfThreads;
		this.connectionIdleTimeoutSeconds = idleTimeout;
		this.connectTimeoutMillis = connectTimeoutMillis;
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

	@Override public void send(final RawData msg) {
		final ChannelPool channelPool = poolMap.get(new InetSocketAddress(msg.getAddress(), msg.getPort()));
		Future<Channel> acquire = channelPool.acquire();
		acquire.addListener(new GenericFutureListener<Future<Channel>>() {

			@Override public void operationComplete(Future<Channel> future) throws Exception {
				if (future.isSuccess()) {
					Channel channel = future.getNow();
					try {
						channel.writeAndFlush(Unpooled.wrappedBuffer(msg.getBytes()));
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

	@Override public InetSocketAddress getAddress() {
		// Client TCP connector doesn't really have an address it binds to.
		return new InetSocketAddress(0);
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
