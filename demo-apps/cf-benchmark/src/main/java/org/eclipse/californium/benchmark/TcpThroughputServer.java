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

import java.io.File;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.TcpConfig;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.tcp.netty.TcpServerConnector;

public class TcpThroughputServer {
	private static final File CONFIG_FILE = new File("CaliforniumTcpServer3.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for TCP server";

	private static DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(CoapConfig.MAX_MESSAGE_SIZE, 16 * 1024);
			config.set(CoapConfig.PROTOCOL_STAGE_THREAD_COUNT, 2);
			config.set(CoapConfig.EXCHANGE_LIFETIME, 10000, TimeUnit.MILLISECONDS);
		}
	};

	static {
		CoapConfig.register();
		TcpConfig.register();
	}

	public static void main(String[] args) {
		Configuration config = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		int tcpPort = config.get(CoapConfig.COAP_PORT);

		Connector serverConnector = new TcpServerConnector(new InetSocketAddress(tcpPort), config);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setConnector(serverConnector);
		builder.setConfiguration(config);
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
