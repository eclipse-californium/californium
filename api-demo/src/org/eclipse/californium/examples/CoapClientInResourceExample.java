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
 *    Martin Lanter - architect and initial implementation
 ******************************************************************************/
package org.eclipse.californium.examples;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.ConcurrentCoapResource;

public class CoapClientInResourceExample extends ConcurrentCoapResource {

	public CoapClientInResourceExample(String name) {
		super(name, SINGLE_THREADED);
	}

	@Override
	public void handleGET(final CoapExchange exchange) {
		exchange.accept();
		
		CoapClient client = createClient("localhost:5683/target");
		client.get(new CoapHandler() {
			@Override
			public void onLoad(CoapResponse response) {
				exchange.respond(response.getCode(), response.getPayload());
			}
			
			@Override
			public void onError() {
				exchange.respond(ResponseCode.BAD_GATEWAY);
			}
		});
		
		// exchange has not been responded yet
	}
	
	@Override
	public void handlePOST(CoapExchange exchange) {
		exchange.accept();
	
		ResponseCode response;
		synchronized (this) {
			// critical section
			response = ResponseCode.CHANGED;
		}

		exchange.respond(response);
	}

	public static void main(String[] args) {
		CoapServer server = new CoapServer();
		server.add(new CoapClientInResourceExample("example"));
		server.add(new CoapResource("target") {
			@Override
			public void handleGET(CoapExchange exchange) {
				exchange.respond("Target payload");
//				exchange.reject();
			}
		});
		server.start();
		
		CoapClient client = new CoapClient("coap://localhost:5683/example");
		System.out.println( client.get().getResponseText() );
	}
}
