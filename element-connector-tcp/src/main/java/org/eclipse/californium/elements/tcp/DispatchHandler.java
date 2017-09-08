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

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;

/**
 * Channel handler that dispatches framed raw messages to coap stack.
 */
public class DispatchHandler extends ChannelInboundHandlerAdapter {

	private final RawDataChannel rawDataChannel;

	public DispatchHandler(RawDataChannel rawDataChannel) {
		this.rawDataChannel = rawDataChannel;
	}

	@Override public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
		rawDataChannel.receiveData((RawData) msg);
	}
}
