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
 ******************************************************************************/
package org.eclipse.californium.plugtests.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.*;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.server.resources.CoapExchange;

public class ObserveReset extends CoapResource {

	public ObserveReset() {
		super("obs-reset");
	}
	
	@Override
	public void handlePOST(CoapExchange exchange) {
		if (exchange.getRequestText().equals("sesame")) {
			System.out.println("obs-reset received POST. Clearing observers");
			
			// clear observers of the obs resources
			Observe obs = (Observe) this.getParent().getChild("obs");
			ObserveNon obsNon = (ObserveNon) this.getParent().getChild("obs-non");
			obs.clearObserveRelations();
			obsNon.clearObserveRelations();
			
			exchange.respond(CHANGED);
			
		} else {
			exchange.respond(FORBIDDEN);
		}
	}
	
}
