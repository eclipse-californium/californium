package org.eclipse.californium.elements.tcp;

import io.netty.channel.ChannelHandlerAdapter;
import io.netty.channel.ChannelHandlerContext;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Channel handler that closes connection if an idle event was raised.
 */
class CloseOnErrorHandler extends ChannelHandlerAdapter {

    private final static Logger LOGGER = Logger.getLogger(CloseOnErrorHandler.class.getName());

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        // Since we use length based framing, any exception reading in TCP stream has the high likelihood of us
        // getting out of sync on the stream, and not being able to recover. So close the connection and hope for the
        // better luck next time.
        LOGGER.log(Level.SEVERE, "Exception in channel handler chain", cause);
        ctx.close();
    }
}
