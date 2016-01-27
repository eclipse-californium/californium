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

import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.server.resources.CoapExchange;

public class AnnounceResource extends CoapResource {
	
	private HashMap<InetSocketAddress, CoapObserveRelation> relationStorage;
	private CoapHandler handler;
	
	public AnnounceResource (String name) {
		super(name);
		relationStorage = new HashMap<InetSocketAddress, CoapObserveRelation>();
		handler = new CoapHandler() {
			private AtomicBoolean testdump = new AtomicBoolean(false);
			@Override public void onLoad(CoapResponse response) {
				if (response.getCode() == ResponseCode.NOT_FOUND) {
					CoapObserveRelation cor;
					synchronized (relationStorage) {
						if (!testdump.get()) {
							testdump.set(true);
							System.out.println("Used Memory: " + (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / 1024 + "kb (" + relationStorage.size() + " clients).");
						}
						if ((cor = relationStorage.get(new InetSocketAddress(response.advanced().getSource(), response.advanced().getSourcePort()))) != null) {
							cor.reactiveCancel();
							relationStorage.remove(new InetSocketAddress(response.advanced().getSource(), response.advanced().getSourcePort()));
							cor = null;
						}
						if (relationStorage.size() == 0)
							testdump.set(false);
					}
					return;
				}
			}
			@Override public void onError() { }
		};
	}
	
	@Override
	public void handleGET(CoapExchange exchange) {
		Response response = new Response(ResponseCode.CONTENT);
		response.setPayload(new Integer(0).toString());
		exchange.respond(response);
	}
	
	@Override
	public void handlePOST(CoapExchange exchange) {
		CoapClient client = this.createClient(exchange.getRequestText());
		CoapObserveRelation relation;
		relation = client.observe(handler);
		synchronized(relationStorage) {
			relationStorage.put(new InetSocketAddress(exchange.getSourceAddress(), exchange.getSourcePort()), relation);
		}
		
		Response response = new Response(ResponseCode.VALID);
		exchange.respond(response);
	}
}
