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
 *    Martin Dzieżyc - implementation of observable resources
 ******************************************************************************/
package org.eclipse.californium.benchmark.observe;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.server.resources.CoapExchange;

public class ShutDownResource extends CoapResource {

	public ShutDownResource(String name) {
		super(name);
	}
	
	public void handleGET(CoapExchange exchange) {
		exchange.respond("Send a POST request to this resource to shutdown the server");
	}
	
	public void handlePOST(CoapExchange exchange) {
		System.out.println("Shutting down everything in 1 second");
		exchange.respond(ResponseCode.CHANGED, "Shutting down");
		try{
			Thread.sleep(1000);
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.exit(0);
	}

}
