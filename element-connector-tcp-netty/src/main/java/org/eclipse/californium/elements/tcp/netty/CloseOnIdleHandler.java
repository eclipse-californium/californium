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
 * Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.elements.tcp.netty;

import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.timeout.IdleStateEvent;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Channel handler that closes connection if an idle event was raised.
 */
class CloseOnIdleHandler extends ChannelDuplexHandler {

	private final static Logger LOGGER = LoggerFactory.getLogger(CloseOnIdleHandler.class);

	@Override public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
		if (evt instanceof IdleStateEvent) {
			LOGGER.debug("Closing channel with {} due to idle time.", ctx.channel().remoteAddress());
			ctx.channel().close();
		}
	}
}
