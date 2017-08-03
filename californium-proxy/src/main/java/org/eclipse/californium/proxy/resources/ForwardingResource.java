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

import java.util.concurrent.Executors;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.resources.ConcurrentCoapResource;

/**
 * The ForwardingResource uses an unlimited thread pool to handle requests,
 * as it is unknown how long individual requests might take.
 */
public abstract class ForwardingResource extends ConcurrentCoapResource {

	public ForwardingResource(String resourceIdentifier) {
		super(resourceIdentifier, Executors.newCachedThreadPool());
		this.setVisible(false);
	}

	@Override
	public void handleRequest(Exchange exchange) {
		exchange.sendAccept();
		Response response = forwardRequest(exchange.getRequest());
		exchange.sendResponse(response);
	}

	public abstract Response forwardRequest(Request request);
}
