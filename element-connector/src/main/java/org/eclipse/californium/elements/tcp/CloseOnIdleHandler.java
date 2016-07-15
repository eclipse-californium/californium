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

import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.timeout.IdleStateEvent;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Channel handler that closes connection if an idle event was raised.
 */
class CloseOnIdleHandler extends ChannelDuplexHandler {

	private final static Logger LOGGER = Logger.getLogger(CloseOnIdleHandler.class.getName());

	@Override public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
		if (evt instanceof IdleStateEvent) {
			LOGGER.log(Level.FINER, "Closing channel with {0} due to idle time.",
					new Object[] { ctx.channel().remoteAddress() });
			ctx.channel().close();
		}
	}
}
