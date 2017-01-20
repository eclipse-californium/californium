/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations GmbH - initial implementation. 
 *                                      add support for correlation context and principal
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;

import java.security.Principal;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import org.eclipse.californium.elements.CorrelationContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.TcpCorrelationContext;
import org.eclipse.californium.elements.TlsCorrelationContext;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * Utils for building for TCP/TLS correlation context and principal from
 * channel.
 */
public class NettyContextUtils {

	private static final Logger LOGGER = Logger.getLogger(NettyContextUtils.class.getName());
	private static final Level LEVEL = Level.FINER;

	/**
	 * Get ssl handler related to the provided channel.
	 * 
	 * @param channel channel of ssl handler
	 * @return ssl handler, or null, if not available.
	 */
	private static SslHandler getSslHandler(Channel channel) {
		ChannelHandler handler = channel.pipeline().first();
		if (handler instanceof SslHandler) {
			return (SslHandler) handler;
		}
		return null;
	}

	/**
	 * Get principal related to the provided channel.
	 * 
	 * @param channel channel of principal
	 * @return principal, or null, if not available
	 */
	public static Principal getPrincipal(Channel channel) {
		SslHandler handler = getSslHandler(channel);
		if (null != handler) {
			SSLEngine sslEngine = handler.engine();
			SSLSession sslSession = sslEngine.getSession();
			if (null != sslSession) {
				try {
					Principal principal = sslSession.getPeerPrincipal();
					if (null == principal) {
						LOGGER.log(Level.WARNING, "Principal missing");
					} else {
						LOGGER.log(Level.FINER, "Principal {0}", principal.getName());
					}
					return principal;
				} catch (SSLPeerUnverifiedException e) {
					LOGGER.log(Level.WARNING, "Principal {0}", e.getMessage());
					/* ignore it */
				}
			}
		}
		return null;
	}

	/**
	 * Build correlation context related to the provided channel.
	 * 
	 * @param channel channel of correlation context
	 * @return correlation context, or null, if yet not available.
	 */
	public static CorrelationContext buildCorrelationContext(Channel channel) {
		String id = channel.id().asShortText();
		SslHandler handler = getSslHandler(channel);
		if (null != handler) {
			SSLEngine sslEngine = handler.engine();
			SSLSession sslSession = sslEngine.getSession();
			if (null != sslSession) {
				byte[] sessionId = sslSession.getId();
				if (null != sessionId && 0 < sessionId.length) {
					String sslId = toHexString(sessionId, 0);
					String cipherSuite = sslSession.getCipherSuite();
					LOGGER.log(LEVEL, "TLS({0},{1},{2})", new Object[] { StringUtil.trunc(sslId, 14), cipherSuite });
					return new TlsCorrelationContext(id, sslId, cipherSuite);
				}
			}
			// TLS handshake not finished
			LOGGER.log(LEVEL, "TLS*({0})", id);
			return null;
		}
		LOGGER.log(LEVEL, "TCP({0})", id);
		return new TcpCorrelationContext(id);
	}

	/**
	 * Report the correlation context related to the provided channel in future.
	 * 
	 * @param channel channel of correlation context
	 * @param msg message for callback, when context gets established.
	 */
	public static void futureCorrelationContext(Channel channel, final RawData msg) {
		if (null != msg.getMessageCallback()) {
			SslHandler sslHandler = getSslHandler(channel);
			if (null != sslHandler) {
				LOGGER.log(LEVEL, "TLS RAW waiting {0}", toHexString(msg.getBytes(), 16));
				Future<Channel> handshakeFuture = sslHandler.handshakeFuture();
				handshakeFuture.addListener(new GenericFutureListener<Future<Channel>>() {

					@Override
					public void operationComplete(Future<Channel> future) throws Exception {
						if (future.isSuccess()) {
							Channel channel = future.getNow();
							CorrelationContext context = NettyContextUtils.buildCorrelationContext(channel);
							if (null != context) {
								msg.onContextEstablished(context);
							} else {
								LOGGER.log(Level.WARNING, "Connection {0} still missing valid TLSsession!", channel
										.id().asShortText());
							}
						}
					}
				});
			}
		}
	}

	/**
	 * Byte array to hexadecimal string.
	 * 
	 * @param byteArray byte array to be converted to string
	 * @param max maximum bytes to be converted.
	 * @return hexadecimal string
	 */
	private static String toHexString(byte[] byteArray, int max) {

		if (byteArray != null && byteArray.length != 0) {
			if (0 == max || max > byteArray.length) {
				max = byteArray.length;
			}
			StringBuilder builder = new StringBuilder(max * 3);
			for (int i = 0; i < max; i++) {
				builder.append(String.format("%02X", 0xFF & byteArray[i]));

				if (i < max - 1) {
					builder.append(' ');
				}
			}
			return builder.toString();
		} else {
			return "--";
		}
	}

}
