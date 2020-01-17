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
import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.core.server.ServerMessageDeliverer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.proxy.ProxyHttpServer;
import org.eclipse.californium.proxy.resources.ProxyCoapClientResource;
import org.eclipse.californium.proxy.resources.ProxyHttpClientResource;

/**
 * Http2CoAP: Insert in browser:
 *     URI: http://localhost:8080/proxy/coap://localhost:PORT/target
 * 
 * CoAP2CoAP: Insert in Copper:
 *     URI: coap://localhost:PORT/coap2coap
 *     Proxy: coap://localhost:PORT/targetA
 *
 * CoAP2Http: Insert in Copper:
 *     URI: coap://localhost:PORT/coap2http
 *     Proxy: http://lantersoft.ch/robots.txt
 */
public class ExampleCrossProxy {
	
	private static final int PORT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.COAP_PORT);

	private static final String COAP2COAP = "coap2coap";
	private static final String COAP2HTTP = "coap2http";

	private CoapServer targetServerA;

	public ExampleCrossProxy() throws IOException {
		NetworkConfig config = NetworkConfig.getStandard();
		int threads = config.getInt(NetworkConfig.Keys.PROTOCOL_STAGE_THREAD_COUNT);
		ScheduledExecutorService mainExecutor = ExecutorsUtil.newScheduledThreadPool(threads, new DaemonThreadFactory("Proxy#"));
		ScheduledExecutorService secondaryExecutor = ExecutorsUtil.newDefaultSecondaryScheduler("ProxyTimer#");
		CoapResource coap2coap = new ProxyCoapClientResource(config, COAP2COAP, mainExecutor, secondaryExecutor);
		CoapResource coap2http = new ProxyHttpClientResource(COAP2HTTP);

		// Create CoAP Server on PORT with proxy resources form CoAP to CoAP and HTTP
		targetServerA = new CoapServer(config, PORT);
		targetServerA.setExecutors(mainExecutor, secondaryExecutor, false);
		targetServerA.add(coap2coap);
		targetServerA.add(coap2http);
		targetServerA.add(new TargetResource("target"));
		MessageDeliverer local = targetServerA.getMessageDeliverer();
		MessageDeliverer proxy = new ProxyMessageDeliverer(targetServerA.getRoot());
		targetServerA.setMessageDeliverer(proxy);
		targetServerA.start();

		ProxyHttpServer httpServer = new ProxyHttpServer(8080);
		httpServer.setLocalCoapDeliverer(local);
		httpServer.setProxyCoapDeliverer(proxy);

		System.out.println("CoAP resource \"target\" available over HTTP at: http://localhost:8080/proxy/coap://localhost:PORT/target");
	}

	private static class ProxyMessageDeliverer extends ServerMessageDeliverer {

		private ProxyMessageDeliverer(Resource root) {
			super(root);
		}

		@Override
		protected Resource findResource(Request request) {
			if (request.getOptions().hasProxyUri()) {
				try {
					URI uri = new URI(request.getOptions().getProxyUri());
					String scheme = uri.getScheme();
					scheme = scheme.toLowerCase();
					if (scheme.equals("http") || scheme.equals("https")) {
						return getRootResource().getChild(COAP2HTTP);
					} else if (CoAP.isSupportedScheme(scheme)) {
						return getRootResource().getChild(COAP2COAP);
					}
				} catch (URISyntaxException e) {
				}
			}
			return super.findResource(request);
		}
	}

	/**
	 * A simple resource that responds to GET requests with a small response
	 * containing the resource's name.
	 */
	private static class TargetResource extends CoapResource {

		private int counter = 0;

		public TargetResource(String name) {
			super(name);
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			exchange.respond("Response "+(++counter)+" from resource " + getName());
		}
	}

	public static void main(String[] args) throws Exception {
		new ExampleCrossProxy();
	}

}
