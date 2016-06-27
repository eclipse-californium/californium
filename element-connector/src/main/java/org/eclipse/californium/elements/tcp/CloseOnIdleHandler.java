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

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof IdleStateEvent) {
            LOGGER.log(Level.FINER, "Closing channel with {0} due to idle time.", new Object[]{ctx.channel().remoteAddress()});
            ctx.channel().close();
        }
    }
}
