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
 * Achim Kraus (Bosch Software Innovations GmbH) - add NetworkConfig setup
 ******************************************************************************/

package org.eclipse.californium.benchmark;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.tcp.netty.TcpServerConnector;

import java.io.File;
import java.net.InetSocketAddress;

public class TcpThroughputServer {
	private static final File CONFIG_FILE = new File("CaliforniumTcpServer.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for TCP server";

	private static NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			config.setLong(Keys.MAX_MESSAGE_SIZE, 16 * 1024);
			config.setInt(Keys.PROTOCOL_STAGE_THREAD_COUNT, 2);
			config.setLong(Keys.EXCHANGE_LIFETIME, 10000);
		}
	};

	public static void main(String[] args) {
		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		int tcpThreads = config.getInt(Keys.TCP_WORKER_THREADS);
		int tcpIdleTimeout = config.getInt(Keys.TCP_CONNECTION_IDLE_TIMEOUT);
		int tcpPort = config.getInt(Keys.COAP_PORT);

		Connector serverConnector = new TcpServerConnector(new InetSocketAddress(tcpPort), tcpThreads, tcpIdleTimeout);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setConnector(serverConnector);
		builder.setNetworkConfig(config);
		CoapEndpoint endpoint = builder.build();

		CoapServer server = new CoapServer(config);
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
