/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 ******************************************************************************/
package org.eclipse.californium.plugtests.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CHANGED;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.FORBIDDEN;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;

public class ObserveReset extends CoapResource {

	/**
	 * URI query parameter to specify response length.
	 */
	private static final String URI_QUERY_OPTION_NOTFOUND = "notfound";

	public ObserveReset() {
		super("obs-reset");
	}

	@Override
	public void handlePOST(CoapExchange exchange) {
		if (exchange.getRequestText().equals("sesame")) {
			System.out.println("obs-reset received POST. Clearing observers");
			ResponseCode code = exchange.getQueryParameter(URI_QUERY_OPTION_NOTFOUND) != null ? ResponseCode.NOT_FOUND
					: null;
			for (Resource child : this.getParent().getChildren()) {
				if (child.isObservable() && child instanceof CoapResource) {
					((CoapResource) child).clearAndNotifyObserveRelations(code);
				}
			}
			exchange.respond(CHANGED);
		} else {
			exchange.respond(FORBIDDEN);
		}
	}

}
