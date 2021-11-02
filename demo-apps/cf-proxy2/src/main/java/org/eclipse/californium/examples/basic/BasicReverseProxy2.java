/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch.IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.examples.basic;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.config.SystemConfig;
import org.eclipse.californium.elements.config.TcpConfig;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.proxy2.ClientSingleEndpoint;
import org.eclipse.californium.proxy2.config.Proxy2Config;
import org.eclipse.californium.proxy2.resources.ProxyCoapResource;

/**
 * Demonstrates a simple coap2coap reverse proxy.
 *
 * Translates requests:
 * 
 * <pre>
 * coap://localhost/reverse[?param]
 * </pre>
 * 
 * into
 * 
 * <pre>
 * coap://localhost:5685/coap-target[?param]
 * </pre>
 * 
 */
public class BasicReverseProxy2 {

	/**
	 * File name for configuration.
	 */
	private static final File CONFIG_FILE = new File("CaliforniumProxy3.properties");
	/**
	 * Header for configuration.
	 */
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Simple Reverse Proxy";
	/**
	 * Default maximum resource size.
	 */
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 8192;
	/**
	 * Default block size.
	 */
	private static final int DEFAULT_BLOCK_SIZE = 1024;

	static {
		CoapConfig.register();
		UdpConfig.register();
		TcpConfig.register();
		Proxy2Config.register();
	}

	/**
	 * Special configuration defaults handler.
	 */
	private static final DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(CoapConfig.MAX_ACTIVE_PEERS, 20000);
			config.set(CoapConfig.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.set(CoapConfig.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.DEDUPLICATOR, CoapConfig.DEDUPLICATOR_PEERS_MARK_AND_SWEEP);
			config.set(CoapConfig.MAX_PEER_INACTIVITY_PERIOD, 24, TimeUnit.HOURS);
			config.set(Proxy2Config.HTTP_CONNECTION_IDLE_TIMEOUT, 10, TimeUnit.SECONDS);
			config.set(Proxy2Config.HTTP_CONNECT_TIMEOUT, 15, TimeUnit.SECONDS);
			config.set(Proxy2Config.HTTPS_HANDSHAKE_TIMEOUT, 30, TimeUnit.SECONDS);
			config.set(UdpConfig.UDP_RECEIVE_BUFFER_SIZE, 8192);
			config.set(UdpConfig.UDP_SEND_BUFFER_SIZE, 8192);
			config.set(SystemConfig.HEALTH_STATUS_INTERVAL, 60, TimeUnit.SECONDS);
		}

	};

	private CoapServer coapProxyServer;

	public BasicReverseProxy2(Configuration config) throws IOException, URISyntaxException {
		// initialize coap outgoing endpoint
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setConfiguration(config);
		ClientSingleEndpoint outgoingEndpoint = new ClientSingleEndpoint(builder.build());

		int port = config.get(CoapConfig.COAP_PORT);
		coapProxyServer = new CoapServer(config, port);
		URI destination = new URI("coap://localhost:5685/coap-target");
		ProxyCoapResource coap2coap = ProxyCoapResource.createReverseProxy("reverse", true, false, true, destination, outgoingEndpoint);
		coapProxyServer.add(coap2coap);
		coapProxyServer.start();
		System.out.println("** CoAP Proxy at: coap://localhost:" + port);
	}

	public static void main(String args[]) throws IOException, URISyntaxException {
		Configuration proxyConfig = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		BasicReverseProxy2 proxy = new BasicReverseProxy2(proxyConfig);
		System.out.println(BasicReverseProxy2.class.getSimpleName() + " started.");
	}
}
