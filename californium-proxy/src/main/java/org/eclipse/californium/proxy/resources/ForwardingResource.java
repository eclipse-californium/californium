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
 *    Martin Lanter - architect and re-implementation
 *    Francesco Corazza - HTTP cross-proxy
 ******************************************************************************/
package org.eclipse.californium.proxy.resources;

import org.eclipse.californium.compat.CompletableFuture;
import org.eclipse.californium.compat.Consumer;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;


public abstract class ForwardingResource extends CoapResource {

	public ForwardingResource(String resourceIdentifier) {
		super(resourceIdentifier);
	}

	public ForwardingResource(String resourceIdentifier, boolean hidden) {
		super(resourceIdentifier, hidden);
	}

	@Override
	public void handleRequest(final Exchange exchange) {
		exchange.sendAccept();
		forwardRequest(exchange.getRequest()).thenAccept(new Consumer<Response>() {
			@Override
			public void accept(Response response) {
				exchange.sendResponse(response);
			}
		});
	}

	public abstract CompletableFuture<Response> forwardRequest(Request request);
}
