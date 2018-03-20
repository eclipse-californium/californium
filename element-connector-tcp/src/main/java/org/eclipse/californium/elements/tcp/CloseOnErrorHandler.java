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
 * Achim Kraus (Bosch Software Innovations GmbH) - use comprehensive message
 *                                                 for security errors.
 * Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import io.netty.channel.ChannelHandlerAdapter;
import io.netty.channel.ChannelHandlerContext;

import java.security.GeneralSecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLException;

/**
 * Channel handler that closes connection if an exception was raised.
 * Use the logging level of {@link CloseOnErrorHandler} to specify the amount
 * of stack-traces in cases of security errors.
 * Level FINER, log all stack-traces, Level WARNING, log stack-trace of the
 * root most cause, and SEVERE for message of root most cause only.
 * All logging is done with Level SEVERE, so the level only determines the amount
 * of information in cases of security errors.
 */
class CloseOnErrorHandler extends ChannelHandlerAdapter {

	private final static Logger LOGGER = LoggerFactory.getLogger(CloseOnErrorHandler.class.getName());

	@Override
	public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
		// Since we use length based framing, any exception reading in TCP stream has the high likelihood of us
		// getting out of sync on the stream, and not being able to recover. So close the connection and hope for the
		// better luck next time.
		try {
			Throwable rootCause = cause;
			while (null != rootCause.getCause()) {
				rootCause = rootCause.getCause();
			}
			if (!LOGGER.isDebugEnabled()
					&& (rootCause instanceof SSLException || rootCause instanceof GeneralSecurityException)) {
				/* comprehensive message for security exceptions */
				if (LOGGER.isWarnEnabled()) {
					LOGGER.error("Security Exception in channel handler chain for endpoint {}. Closing connection.",
							ctx.channel().remoteAddress(), rootCause);
				} else {
					LOGGER.error("{} in channel handler chain for endpoint {}. Closing connection.", rootCause,
							ctx.channel().remoteAddress());
				}
			} else {
				LOGGER.error("Exception in channel handler chain for endpoint {}. Closing connection.",
						ctx.channel().remoteAddress(), cause);
			}
		} finally {
			ctx.close();
		}
	}
}
