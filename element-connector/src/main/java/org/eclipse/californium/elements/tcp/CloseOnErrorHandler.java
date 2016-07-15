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
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import io.netty.channel.ChannelHandlerAdapter;
import io.netty.channel.ChannelHandlerContext;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Channel handler that closes connection if an exception was raised.
 */
class CloseOnErrorHandler extends ChannelHandlerAdapter {

	private final static Logger LOGGER = Logger.getLogger(CloseOnErrorHandler.class.getName());

	@Override public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
		// Since we use length based framing, any exception reading in TCP stream has the high likelihood of us
		// getting out of sync on the stream, and not being able to recover. So close the connection and hope for the
		// better luck next time.
		LOGGER.log(Level.SEVERE, "Exception in channel handler chain for endpoint " + ctx.channel().remoteAddress() +
				". Closing connection.", cause);
		ctx.close();
	}
}
