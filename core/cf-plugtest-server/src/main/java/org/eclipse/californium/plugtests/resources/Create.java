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
import static org.eclipse.californium.core.coap.MediaTypeRegistry.*;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.server.resources.CoapExchange;


/**
 * This resource implements a test of specification for the ETSI IoT CoAP Plugtests, London, UK, 7--9 Mar 2014.
 */
public class Create extends CoapResource {

	// Members ////////////////////////////////////////////////////////////////

	private byte[] data = null;
	private int dataCf = UNDEFINED;

	public Create() {
		super("create1");
		getAttributes().setTitle("Resource which does not exist yet (to perform atomic PUT)");
		setVisible(false);
	}
	
	@Override
	public void handlePUT(CoapExchange exchange) {
		if (data!=null && exchange.getRequestOptions().hasIfNoneMatch()) {
			exchange.respond(PRECONDITION_FAILED);
			
			// automatically reset
			data = null;
		} else {
			if (exchange.getRequestOptions().hasContentFormat()) {
				storeData(exchange.getRequestPayload(), exchange.getRequestOptions().getContentFormat());
				exchange.respond(CREATED);
			} else {
				exchange.respond(BAD_REQUEST, "Content-Format not set");
			}
		}
	}
	
	@Override
	public void handleGET(CoapExchange exchange) {
		if (data!=null) {
			exchange.respond(CONTENT, data, dataCf);
		} else {
			exchange.respond(NOT_FOUND);
		}
	}

	@Override
	public void handleDELETE(CoapExchange exchange) {
		data = null;
		setVisible(false);
		exchange.respond(DELETED);
	}
	
	// Internal ////////////////////////////////////////////////////////////////
	
	/*
	 * Convenience function to store data contained in a 
	 * PUT/POST-Request. Notifies observing endpoints about
	 * the change of its contents.
	 */
	private synchronized void storeData(byte[] payload, int cf) {

		// set payload and content type
		data = payload;
		dataCf = cf;
		getAttributes().clearContentType();
		getAttributes().addContentType(dataCf);
		getAttributes().setMaximumSizeEstimate(data.length);
		
		setVisible(true);

		// signal that resource state changed
		changed();
	}
}
