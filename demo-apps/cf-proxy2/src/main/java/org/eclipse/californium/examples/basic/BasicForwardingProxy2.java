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

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.proxy2.HttpClientFactory;
import org.eclipse.californium.proxy2.resources.ForwardProxyMessageDeliverer;
import org.eclipse.californium.proxy2.resources.ProxyCoapResource;
import org.eclipse.californium.proxy2.resources.ProxyHttpClientResource;

/**
 * Demonstrates a basic coap2http forwarding proxy.
 *
 * CoAP2Http:
 * <pre>
 * coap://destination:port/uri-path, proxy-scheme=http
 * </pre>
 */
public class BasicForwardingProxy2 {

	/**
	 * File name for network configuration.
	 */
	private static final File CONFIG_FILE = new File("Californium.properties");
	/**
	 * Header for network configuration.
	 */
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Simple Forwarding Proxy";
	/**
	 * Default maximum resource size.
	 */
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 8192;
	/**
	 * Default block size.
	 */
	private static final int DEFAULT_BLOCK_SIZE = 1024;

	/**
	 * Special network configuration defaults handler.
	 */
	private static final NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			config.setInt(Keys.MAX_ACTIVE_PEERS, 20000);
			config.setInt(Keys.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.setString(Keys.DEDUPLICATOR, Keys.DEDUPLICATOR_PEERS_MARK_AND_SWEEP);
			config.setInt(Keys.MAX_PEER_INACTIVITY_PERIOD, 60 * 60 * 24); // 24h
			config.setInt(Keys.TCP_CONNECTION_IDLE_TIMEOUT, 10); // 10s
			config.setInt(Keys.TCP_CONNECT_TIMEOUT, 15 * 1000); // 15s
			config.setInt(Keys.TLS_HANDSHAKE_TIMEOUT, 30 * 1000); // 30s
			config.setInt(Keys.UDP_CONNECTOR_RECEIVE_BUFFER, 8192);
			config.setInt(Keys.UDP_CONNECTOR_SEND_BUFFER, 8192);
			config.setInt(Keys.HEALTH_STATUS_INTERVAL, 60);
		}

	};

	private static final String COAP2HTTP = "coap2http";

	private CoapServer coapProxyServer;

	public BasicForwardingProxy2(NetworkConfig config) throws IOException {
		// initialize http clients
		HttpClientFactory.setNetworkConfig(config);
		// initialize coap-server
		int port = config.getInt(Keys.COAP_PORT);
		coapProxyServer = new CoapServer(config, port);
		// initialize proxy resource
		ProxyCoapResource coap2http = new ProxyHttpClientResource(COAP2HTTP, false, false, null);
		// initialize proxy message deviverer
		ForwardProxyMessageDeliverer proxyMessageDeliverer = new ForwardProxyMessageDeliverer(coap2http);
		// set proxy message deviverer
		coapProxyServer.setMessageDeliverer(proxyMessageDeliverer);
		coapProxyServer.start();
		System.out.println("** CoAP Proxy at: coap://localhost:" + port);
	}

	public static void main(String args[]) throws IOException {
		NetworkConfig proxyConfig = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		BasicForwardingProxy2 proxy = new BasicForwardingProxy2(proxyConfig);
		System.out.println(BasicForwardingProxy2.class.getSimpleName() + " started.");
	}
}
