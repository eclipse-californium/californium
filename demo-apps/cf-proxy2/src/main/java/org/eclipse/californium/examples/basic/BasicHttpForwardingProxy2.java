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
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.config.SystemConfig;
import org.eclipse.californium.elements.config.TcpConfig;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.proxy2.ClientSingleEndpoint;
import org.eclipse.californium.proxy2.config.Proxy2Config;
import org.eclipse.californium.proxy2.http.server.ProxyHttpServer;
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
	 * File name for configuration.
	 */
	private static final File CONFIG_FILE = new File("CaliforniumProxy3.properties");
	/**
	 * Header for configuration.
	 */
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Simple Http Forwarding Proxy";
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

	private static final String COAP2COAP = "coap2coap";

	private ProxyHttpServer httpProxyServer;

	public BasicHttpForwardingProxy2(Configuration config) throws IOException {

		// initialize coap outgoing endpoint
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setConfiguration(config);
		CoapEndpoint endpoint = builder.build();
		ClientSingleEndpoint outgoingEndpoint = new ClientSingleEndpoint(endpoint);

		ProxyCoapResource coap2coap = new ProxyCoapClientResource(COAP2COAP, false, false, null, outgoingEndpoint);
		ForwardProxyMessageDeliverer proxyMessageDeliverer = new ForwardProxyMessageDeliverer(coap2coap);

		httpProxyServer = ProxyHttpServer.buider()
				.setConfiguration(config)
				.setExecutor(endpoint)
				.setProxyCoapDeliverer(proxyMessageDeliverer)
				.build();

		httpProxyServer.start();

		System.out.println("** HTTP Proxy at: http://" + httpProxyServer.getInterface());
	}

	public static void main(String args[]) throws IOException {
		Configuration proxyConfig = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		BasicHttpForwardingProxy2 proxy = new BasicHttpForwardingProxy2(proxyConfig);
		System.out.println(BasicHttpForwardingProxy2.class.getSimpleName() + " started.");
	}
}
