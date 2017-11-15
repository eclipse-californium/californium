/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.io.IOException;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;

import org.eclipse.californium.proxy.ProxyHttpServer;
import org.eclipse.californium.proxy.resources.ForwardingResource;
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
	private static final int HTTP_PORT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.HTTP_PORT);

	private CoapServer coapProxy;
	
	public ExampleCrossProxy() throws IOException {
		ForwardingResource coap2coap = new ProxyCoapClientResource(NetworkConfig.getStandard().getLong(NetworkConfig.Keys.HTTP_SERVER_SOCKET_TIMEOUT));
		ForwardingResource coap2http = new ProxyHttpClientResource(NetworkConfig.getStandard().getLong(NetworkConfig.Keys.HTTP_SERVER_SOCKET_TIMEOUT));
		
		// Create CoAP Server on PORT with proxy resources form CoAP to CoAP and HTTP
		coapProxy = new CoapServer(PORT);
		
		coapProxy.setMessageDeliverer(new ProxyMessageDeliverer(coapProxy.getRoot(), coap2coap, coap2http));
		
		coapProxy.add(new TargetResource("test"));
		coapProxy.start();
		
		ProxyHttpServer httpServer = new ProxyHttpServer(coap2coap, HTTP_PORT);
		
		System.out.println("CoAP resource \"test\" available over HTTP at: http://localhost:"+HTTP_PORT+"/proxy/coap://localhost:"+PORT+"/test");
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
