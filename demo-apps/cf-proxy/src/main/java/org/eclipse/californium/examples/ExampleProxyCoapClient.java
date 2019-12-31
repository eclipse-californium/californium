/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.io.IOException;
import java.net.InetSocketAddress;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.proxy.resources.ProxyHttpClientResource;

/**
 * Class ExampleProxyCoapClient. <br/>
 * Example CoAP client which sends a request to Proxy Coap server with a
 * {@link ProxyHttpClientResource} to get the response from HttpServer. <br/>
 * 
 * For testing Coap2Http:<br/>
 * Destination: localhost:5685 (proxy's address)<br/>
 * Coap Uri: {@code coap://localhost:8000/http-target}<br/>
 * Proxy Scheme: {@code http}.
 * 
 * or <br/>
 * 
 * Destination: localhost:5685 (proxy's address)<br/>
 * Proxy Uri: {@code http://user@localhost:8000/http-target}.<br/>
 * 
 * For testing Coap2coap: <br/>
 * Destination: localhost:5685 (proxy's address)<br/>
 * Coap Uri: {@code coap://localhost:5683/coap-target}.<br/>
 * 
 * Deprecated modes:<br/>
 * Uri: {@code coap://localhost:8000/coap2http}. <br/>
 * Proxy Uri: {@code http://localhost:8000/http-target}.<br/>
 * 
 * For testing Coap2coap: <br/>
 * Uri: {@code coap://localhost:5685/coap2coap}. <br/>
 * Proxy Uri: {@code coap://localhost:5683/coap-target}.<br/>
 * 
 */
public class ExampleProxyCoapClient {

	private static final int PROXY_PORT = 5685;

	private static void request(CoapClient client, Request request) {
		try {
			CoapResponse response = client.advanced(request);
			if (response != null) {
				int format = response.getOptions().getContentFormat();
				if (format != MediaTypeRegistry.TEXT_PLAIN) {
					System.out.print(MediaTypeRegistry.toString(format));
				}
				System.out.println(response.getResponseText());
			}
		} catch (ConnectorException | IOException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {

		CoapClient client = new CoapClient();
		// deprecated proxy request - use CoAP and Proxy URI together
		Request request = Request.newGet();
		request.setURI("coap://localhost:" + PROXY_PORT + "/coap2http");
		request.getOptions().setProxyUri("http://localhost:8000/http-target");
		request(client, request);

		// deprecated proxy request - use CoAP and Proxy URI together
		request = Request.newGet();
		request.setURI("coap://localhost:" + PROXY_PORT + "/coap2coap");
		request.getOptions().setProxyUri("coap://localhost:5683/coap-target");
		request(client, request);

		// RFC7252 proxy request - use CoAP-URI, proxy scheme, and destination to proxy
		request = Request.newGet();
		request.setDestinationContext(new AddressEndpointContext(new InetSocketAddress("localhost", PROXY_PORT)));
		request.setScheme("coap");
		request.getOptions().setUriHost("localhost");
		request.getOptions().setUriPort(8000);
		request.getOptions().setUriPath("http-target");
		request.getOptions().setProxyScheme("http");
		request(client, request);

		// RFC7252 proxy request - use CoAP-URI, and destination to proxy
		request = Request.newGet();
		request.setDestinationContext(new AddressEndpointContext(new InetSocketAddress("localhost", PROXY_PORT)));
		request.setScheme("coap");
		request.getOptions().setUriHost("localhost");
		request.getOptions().setUriPort(5683);
		request.getOptions().setUriPath("coap-target");
		request(client, request);

		// RFC7252 proxy request - use Proxy-URI, and destination to proxy
		request = Request.newGet();
		request.setDestinationContext(new AddressEndpointContext(new InetSocketAddress("localhost", PROXY_PORT)));
		request.getOptions().setProxyUri("http://user@localhost:8000/http-target");
		request.setType(Type.NON);
		request(client, request);

		client.shutdown();
	}
}
