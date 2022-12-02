package org.eclipse.californium.elements.tcp.netty;

import org.eclipse.californium.elements.EndpointContext;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.AttributeKey;

public class EndpointContextHandler extends ChannelInboundHandlerAdapter {

	public static final AttributeKey<EndpointContext> ENDPOINT_CONTEXT_ATTR = AttributeKey.newInstance("endpoint");

	// TODO should  TcpContextUtil  be renamed in TcpEndpointContextFactory ?
	private TcpContextUtil tcpContextUtil;

	public EndpointContextHandler(TcpContextUtil contextUtil) {
		this.tcpContextUtil = contextUtil;
	}

	@Override
	public void channelActive(ChannelHandlerContext ctx) throws Exception {
		// create context
		EndpointContext endpointContext = tcpContextUtil.buildEndpointContext(ctx.channel());
		if (endpointContext == null) {
			throw new IllegalStateException("endpoint context must not be null");
		}

		// add it to the channel
		EndpointContext oldEndpointContext = ctx.channel().attr(ENDPOINT_CONTEXT_ATTR).setIfAbsent(endpointContext);
		if (oldEndpointContext != null) {
			throw new IllegalStateException(
					String.format("Can not create new endpoint context %s as %s already exists.", endpointContext,
							oldEndpointContext));
		}
		
		// TODO is other Handler should retrieve context in attribute map instead of Create a new one each time ? 

		super.channelActive(ctx);
	}
}
