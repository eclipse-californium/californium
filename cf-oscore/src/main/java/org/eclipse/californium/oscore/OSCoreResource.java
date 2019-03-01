/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
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
 *    Tobias Andersson (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Response;

/**
 * 
 * Extending the CoapResource to add OSCORE mechanics at resource level.
 *
 */
public class OSCoreResource extends CoapResource {

	private final boolean isProtected;

	public OSCoreResource(String name, final boolean isProtected) {
		super(name);
		this.isProtected = isProtected;
	}

	@Override
	public void handleRequest(final Exchange exchange) {
		if (isProtected) {
			OptionSet options = exchange.getRequest().getOptions();
			if (!options.hasOscore()) {
				Response r = new Response(ResponseCode.UNAUTHORIZED);
				r.setType(Type.RST);
				exchange.sendResponse(r);
				return;
			}
		}
		exchange.getRequest().getOptions().removeOscore();
		super.handleRequest(exchange);
	}

	public boolean isProtected() {
		return this.isProtected;
	}

}
