package org.eclipse.californium.benchmark;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.tcp.TcpServerConnector;

import java.net.InetSocketAddress;

public class TcpThroughputServer {

	public static void main(String[] args) {
		NetworkConfig net = NetworkConfig.createStandardWithoutFile()
				.setLong(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 16 * 1024)
				.setInt(NetworkConfig.Keys.PROTOCOL_STAGE_THREAD_COUNT, 2)
				.setLong(NetworkConfig.Keys.EXCHANGE_LIFETIME, 10000);

		Connector serverConnector = new TcpServerConnector(new InetSocketAddress(CoAP.DEFAULT_COAP_PORT), 1, 100);
		CoapEndpoint endpoint = new CoapEndpoint(serverConnector, net);

		CoapServer server = new CoapServer(net);
		server.addEndpoint(endpoint);
		server.add(new Resource());
		server.start();
	}

	static class Resource extends CoapResource {

		Resource() {
			super("echo");
		}

		@Override public void handlePUT(CoapExchange exchange) {
			exchange.respond(CoAP.ResponseCode.CONTENT, exchange.getRequestPayload());
		}
	}
}
