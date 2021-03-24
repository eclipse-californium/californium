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
 * Achim Kraus (Bosch Software Innovations GmbH) - use comprehensive message
 *                                                 for security errors.
 * Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.elements.tcp.netty;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.concurrent.RejectedExecutionException;

import javax.net.ssl.SSLException;

import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.netty.channel.ChannelHandlerAdapter;
import io.netty.channel.ChannelHandlerContext;

/**
 * Channel handler that closes connection if an exception was raised. Use the
 * logging level of {@link CloseOnErrorHandler} to specify the amount of
 * stack-traces in cases of security errors. Common exceptions,
 * {@link SSLException}, {@link GeneralSecurityException}, or
 * {@link RejectedExecutionException} are logged with level WARN. If level DEBUG
 * is enabled, log also a stack-traces of the root cause for these common
 * exceptions. {@link IOException} are logged with WARN without stack trace and
 * all other exceptions are logged as ERROR with a stack trace of the provided
 * cause.
 */
class CloseOnErrorHandler extends ChannelHandlerAdapter {

	private final static Logger LOGGER = LoggerFactory.getLogger(CloseOnErrorHandler.class);

	@Override
	public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
		// Since we use length based framing, any exception reading in TCP
		// stream has the high likelihood of us getting out of sync on the
		// stream, and not being able to recover. So close the connection and
		// hope for the better luck next time.
		try {
			Throwable rootCause = cause;
			while (null != rootCause.getCause()) {
				rootCause = rootCause.getCause();
			}
			String error = rootCause.toString();
			String remote = StringUtil.toString((InetSocketAddress) ctx.channel().remoteAddress());
			if (rootCause instanceof SSLException || rootCause instanceof GeneralSecurityException
					|| rootCause instanceof RejectedExecutionException) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.warn("{} in channel handler chain for endpoint {}. Closing connection.", error, remote,
							rootCause);
				} else {
					LOGGER.warn("{} in channel handler chain for endpoint {}. Closing connection.", error, remote);
				}
			} else if (rootCause instanceof IOException) {
				LOGGER.warn("{} in channel handler chain for endpoint {}. Closing connection.", error, remote);
			} else {
				LOGGER.error("{} in channel handler chain for endpoint {}. Closing connection.", error, cause);
			}
		} finally {
			ctx.close();
		}
	}
}
