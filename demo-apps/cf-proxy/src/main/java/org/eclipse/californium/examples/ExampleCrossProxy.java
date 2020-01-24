/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.proxy.EndpointPool;
import org.eclipse.californium.proxy.HttpTranslator;
import org.eclipse.californium.proxy.Coap2CoapTranslator;
import org.eclipse.californium.proxy.ProxyHttpServer;
import org.eclipse.californium.proxy.resources.Proxy2CoapClientResource;
import org.eclipse.californium.proxy.resources.Proxy2HttpClientResource;
import org.eclipse.californium.proxy.resources.ProxyMessageDeliverer;

/**
 * Http2CoAP: Insert in browser: URI:
 * http://localhost:8080/proxy/coap://localhost:PORT/target
 * 
 * Http2LocalCoAPResource: Insert in browser: URI:
 * http://localhost:8080/local/target
 * 
 * Http2CoAP: configure browser to use the proxy "localhost:8080". Insert in
 * browser: ("localhost" requests are not send to a proxy, so use the hostname
 * or none-local-ip-address) URI: http://<hostname>:5683/target/coap:
 * 
 * CoAP2CoAP: Insert in Copper: URI: coap://localhost:PORT/coap2coap Proxy:
 * coap://localhost:PORT/targetA
 *
 * CoAP2Http: Insert in Copper: URI: coap://localhost:PORT/coap2http Proxy:
 * http://lantersoft.ch/robots.txt
 */
public class ExampleCrossProxy {

	private static final int PORT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.COAP_PORT);

	static final String COAP2COAP = "coap2coap";
	static final String COAP2HTTP = "coap2http";

	private CoapServer targetServerA;
	private ProxyHttpServer httpServer;

	public ExampleCrossProxy() throws IOException {
		NetworkConfig config = NetworkConfig.getStandard();
		int threads = config.getInt(NetworkConfig.Keys.PROTOCOL_STAGE_THREAD_COUNT);
		ScheduledExecutorService mainExecutor = ExecutorsUtil.newScheduledThreadPool(threads,
				new DaemonThreadFactory("Proxy#"));
		ScheduledExecutorService secondaryExecutor = ExecutorsUtil.newDefaultSecondaryScheduler("ProxyTimer#");
		NetworkConfig outgoingConfig = new NetworkConfig(config);
		outgoingConfig.setInt(NetworkConfig.Keys.NETWORK_STAGE_RECEIVER_THREAD_COUNT, 1);
		outgoingConfig.setInt(NetworkConfig.Keys.NETWORK_STAGE_SENDER_THREAD_COUNT, 1);
		EndpointPool pool = new EndpointPool(1000, 250, outgoingConfig, mainExecutor, secondaryExecutor);
		Coap2CoapTranslator translater = new Coap2CoapTranslator();
		CoapResource coap2coap = new Proxy2CoapClientResource(COAP2COAP, true, translater, pool);
		CoapResource coap2http = new Proxy2HttpClientResource(COAP2HTTP, true, new HttpTranslator());

		// Create CoAP Server on PORT with proxy resources form CoAP to CoAP and HTTP
		targetServerA = new CoapServer(config, PORT);
		targetServerA.setExecutors(mainExecutor, secondaryExecutor, false);
		targetServerA.add(coap2coap);
		targetServerA.add(coap2http);
		targetServerA.add(new TargetResource("target"));
		MessageDeliverer local = targetServerA.getMessageDeliverer();
		Map<String, Resource> map = new ConcurrentHashMap<>();
		map.put("http", coap2http);
		map.put("https", coap2http);
		map.put("coap", coap2coap);
		map.put("coaps", coap2coap);
		MessageDeliverer proxy = new ProxyMessageDeliverer(targetServerA.getRoot(), translater, map, new InetSocketAddress(PORT));
		targetServerA.setMessageDeliverer(proxy);
		targetServerA.start();

		httpServer = new ProxyHttpServer(config, 8080);
		httpServer.setLocalCoapDeliverer(local);
		httpServer.setProxyCoapDeliverer(proxy);
		httpServer.start();

		System.out.println(
				"CoAP resource \"target\" available over HTTP at: http://localhost:8080/proxy/coap://localhost:PORT/target");
		System.out.println("CoAP resource \"target\" available over HTTP at: http://localhost:8080/local/target");
	}

	public void stop() {
		httpServer.stop();
		targetServerA.destroy();
	}

	/**
	 * A simple resource that responds to GET requests with a small response
	 * containing the resource's name.
	 */
	private static class TargetResource extends CoapResource {

		private final AtomicInteger counter = new AtomicInteger();

		public TargetResource(String name) {
			super(name);
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			int count = counter.incrementAndGet();
			exchange.respond("Response " + count + " from resource " + getName());
		}
	}

	public static void main(String[] args) throws Exception {
		new ExampleCrossProxy();
	}

}
