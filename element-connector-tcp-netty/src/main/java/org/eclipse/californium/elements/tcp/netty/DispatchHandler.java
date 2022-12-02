/*******************************************************************************
 * Copyright (c) 2016 Amazon Web Services.
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
 ******************************************************************************/
package org.eclipse.californium.elements.tcp.netty;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;

import org.eclipse.californium.elements.ConnectionEventHandler;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;

/**
 * Channel handler that dispatches framed raw messages or events to coap stack.
 */
public class DispatchHandler extends ChannelInboundHandlerAdapter {

	private final RawDataChannel rawDataChannel;
	private final ConnectionEventHandler eventHandler;

	public DispatchHandler(RawDataChannel rawDataChannel, ConnectionEventHandler eventHandler) {
		this.rawDataChannel = rawDataChannel;
		this.eventHandler = eventHandler;
	}

	@Override public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
		rawDataChannel.receiveData((RawData) msg);
	}
	
	@Override
	public void channelActive(ChannelHandlerContext ctx) throws Exception {
		EndpointContext endpointContext = ctx.channel().attr(EndpointContextHandler.ENDPOINT_CONTEXT_ATTR).get();
		if (endpointContext == null)
			throw new IllegalStateException("endpoint context should not be null");

		if(eventHandler != null)
			eventHandler.connected(endpointContext);
		
		super.channelActive(ctx);
	}
	
	@Override
	public void channelInactive(ChannelHandlerContext ctx) throws Exception {
		EndpointContext endpointContext = ctx.channel().attr(EndpointContextHandler.ENDPOINT_CONTEXT_ATTR).get();
		if (endpointContext == null)
			throw new IllegalStateException("endpoint context should not be null");

		if(eventHandler != null)
			eventHandler.disconnected(endpointContext);
		
		super.channelInactive(ctx);
	}
}
