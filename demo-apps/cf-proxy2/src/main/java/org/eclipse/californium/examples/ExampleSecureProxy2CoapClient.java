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

package org.eclipse.californium.examples;

import java.io.IOException;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.config.TcpConfig;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.examples.util.CoapResponsePrinter;
import org.eclipse.californium.examples.util.SecureEndpointPool;
import org.eclipse.californium.scandium.config.DtlsConfig;

/**
 * Example for a coap2coaps proxy.
 * 
 * Setup a {@link SecureEndpointPool} for outgoing traffic.
 */
public class ExampleSecureProxy2CoapClient {

	private static final int PROXY_PORT = 5683;

	static {
		CoapConfig.register();
		UdpConfig.register();
		DtlsConfig.register();
		TcpConfig.register();
	}

	private static void request(CoapClient client, Request request) {
		try {
			CoapResponse response = client.advanced(request);
			CoapResponsePrinter.printResponse(response);
		} catch (ConnectorException | IOException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {

		CoapClient client = new CoapClient();

		AddressEndpointContext proxy = new AddressEndpointContext("localhost", PROXY_PORT);
		// RFC7252 proxy request - use CoAP-URI, proxy scheme and destination to
		// proxy
		Request request = Request.newGet();
		request.setDestinationContext(proxy);
		request.setURI("coap://californium.eclipseprojects.io:5684/test");
		request.setProxyScheme("coaps");
		request(client, request);

		request = Request.newGet();
		request.setDestinationContext(proxy);
		request.setURI("coap://localhost:5686/coap-target");
		request.setProxyScheme("coaps");
		request(client, request);

		// reverse proxy
		request = Request.newGet();
		request.setURI("coap://localhost/targets/destination1");
		request(client, request);

		client.shutdown();
	}
}
