package org.eclipse.californium.benchmark;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;

public class ThroughputServer {

    public static void main(String[] args) {
        NetworkConfig net = NetworkConfig.createStandardWithoutFile()
                .setLong(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 16 * 1024)
                .setBoolean(NetworkConfig.Keys.USE_TCP_SERVER, true)
                .setInt(NetworkConfig.Keys.PROTOCOL_STAGE_THREAD_COUNT, 2)
                .setLong(NetworkConfig.Keys.EXCHANGE_LIFETIME, 10000);

        CoapServer server = new CoapServer(net);
        server.add(new Resource());
        server.start();
    }

    static class Resource extends CoapResource {

        public Resource() {
            super("Test");
        }

        @Override
        public void handlePUT(CoapExchange exchange) {
            exchange.respond(CoAP.ResponseCode.CONTENT, exchange.getRequestPayload());
        }
    }
}
