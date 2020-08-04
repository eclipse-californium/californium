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

import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.proxy2.ClientSingleEndpoint;
import org.eclipse.californium.proxy2.ProxyHttpServer;
import org.eclipse.californium.proxy2.resources.ForwardProxyMessageDeliverer;
import org.eclipse.californium.proxy2.resources.ProxyCoapClientResource;
import org.eclipse.californium.proxy2.resources.ProxyCoapResource;

/**
 * Demonstrates a simple coap2http forwarding proxy.
 *
 * Http2CoAP:
 * <pre>
 * http://destination:port/uri-path/coap:
 * </pre>
 */
public class BasicHttpForwardingProxy2 {

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

	private static final String COAP2COAP = "coap2coap";

	private ProxyHttpServer httpProxyServer;

	public BasicHttpForwardingProxy2(NetworkConfig config) throws IOException {

		// initialize coap outgoing endpoint
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setNetworkConfig(config);
		ClientSingleEndpoint outgoingEndpoint = new ClientSingleEndpoint(builder.build());

		int port = config.getInt(Keys.HTTP_PORT);

		httpProxyServer = new ProxyHttpServer(config, port);

		ProxyCoapResource coap2coap = new ProxyCoapClientResource(COAP2COAP, false, false, null, outgoingEndpoint);

		ForwardProxyMessageDeliverer proxyMessageDeliverer = new ForwardProxyMessageDeliverer(coap2coap);

		httpProxyServer.setProxyCoapDeliverer(proxyMessageDeliverer);
		httpProxyServer.start();

		System.out.println("** HTTP Proxy at: http://localhost:" + port);
	}

	public static void main(String args[]) throws IOException {
		NetworkConfig proxyConfig = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		BasicHttpForwardingProxy2 proxy = new BasicHttpForwardingProxy2(proxyConfig);
		System.out.println(BasicHttpForwardingProxy2.class.getSimpleName() + " started.");
	}
}
