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
import java.net.InetSocketAddress;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.examples.util.SecureEndpointPool;

/**
 * Example for a coap2coaps proxy.
 * 
 * Setup a {@link SecureEndpointPool} for outgoing traffic.
 */
public class ExampleSecureProxy2CoapClient {

	private static final int PROXY_PORT = 5683;

	private static void request(CoapClient client, Request request) {
		try {
			CoapResponse response = client.advanced(request);
			if (response != null) {
				int format = response.getOptions().getContentFormat();
				if (format != MediaTypeRegistry.TEXT_PLAIN && format != MediaTypeRegistry.UNDEFINED) {
					System.out.print(MediaTypeRegistry.toString(format));
				}
				String text = response.getResponseText();
				if (text.isEmpty()) {
					System.out.println(response.getCode() + "/" + response.getCode().name());
				} else {
					System.out.println(response.getCode() + "/" + response.getCode().name() + " --- "
							+ response.getResponseText());
				}
			}
		} catch (ConnectorException | IOException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {

		CoapClient client = new CoapClient();

		AddressEndpointContext proxy = new AddressEndpointContext(new InetSocketAddress("localhost", PROXY_PORT));
		// RFC7252 proxy request - use CoAP-URI, proxy scheme and destination to proxy
		Request request = Request.newGet();
		request.setDestinationContext(proxy);
		request.setURI("coap://californium.eclipseprojects.io:5684/test");
		request.setProxyScheme("coaps");
		request(client, request);

		client.shutdown();
	}
}
