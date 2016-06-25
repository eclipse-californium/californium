package org.eclipse.californium.elements.tcp;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;

/**
 * Channel handler that dispmatches framed raw messages to coap stac.
 */
public class DispatchHandler extends ChannelInboundHandlerAdapter {

    private final RawDataChannel rawDataChannel;

    public DispatchHandler(RawDataChannel rawDataChannel) {
        this.rawDataChannel = rawDataChannel;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        rawDataChannel.receiveData((RawData) msg);
    }
}
