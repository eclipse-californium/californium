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
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.server.resources.CoapExchange;

/**
 * This resource implements a test of specification for the
 * ETSI IoT CoAP Plugtests, London, UK, 7--9 Mar 2014.
 */
public class LargeUpdate extends CoapResource {

// Members ////////////////////////////////////////////////////////////////

	private byte[] data = null;
	private int dataCf = TEXT_PLAIN;

// Constructors ////////////////////////////////////////////////////////////
	
	/*
	 * Default constructor.
	 */
	public LargeUpdate() {
		this("large-update");
		
		StringBuilder builder = new StringBuilder();
		builder.append("/-------------------------------------------------------------\\\n");
		builder.append("|                 RESOURCE BLOCK NO. 1 OF 5                   |\n");
		builder.append("|               [each line contains 64 bytes]                 |\n");
		builder.append("\\-------------------------------------------------------------/\n");
		builder.append("/-------------------------------------------------------------\\\n");
		builder.append("|                 RESOURCE BLOCK NO. 2 OF 5                   |\n");
		builder.append("|               [each line contains 64 bytes]                 |\n");
		builder.append("\\-------------------------------------------------------------/\n");
		builder.append("/-------------------------------------------------------------\\\n");
		builder.append("|                 RESOURCE BLOCK NO. 3 OF 5                   |\n");
		builder.append("|               [each line contains 64 bytes]                 |\n");
		builder.append("\\-------------------------------------------------------------/\n");
		builder.append("/-------------------------------------------------------------\\\n");
		builder.append("|                 RESOURCE BLOCK NO. 4 OF 5                   |\n");
		builder.append("|               [each line contains 64 bytes]                 |\n");
		builder.append("\\-------------------------------------------------------------/\n");
		builder.append("/-------------------------------------------------------------\\\n");
		builder.append("|                 RESOURCE BLOCK NO. 5 OF 5                   |\n");
		builder.append("|               [each line contains 64 bytes]                 |\n");
		builder.append("\\-------------------------------------------------------------/\n");
		
		data = builder.toString().getBytes();
	}
	
	/*
	 * Constructs a new storage resource with the given resourceIdentifier.
	 */
	public LargeUpdate(String resourceIdentifier) {
		super(resourceIdentifier);
		getAttributes().setTitle("Large resource that can be updated using PUT method");
		getAttributes().addResourceType("block");
		getAttributes().setMaximumSizeEstimate(1280);
	}

	// REST Operations /////////////////////////////////////////////////////////
	
	@Override
	public void handleGET(CoapExchange exchange) {

		if (exchange.getRequestOptions().hasAccept() && exchange.getRequestOptions().getAccept() != dataCf) {
			exchange.respond(NOT_ACCEPTABLE, MediaTypeRegistry.toString(dataCf) + " only");
		} else {
			exchange.respond(CONTENT, data, dataCf);
		}
	}
	
	@Override
	public void handlePUT(CoapExchange exchange) {
		
		if (exchange.getRequestOptions().hasContentFormat()) {
			storeData(exchange.getRequestPayload(), exchange.getRequestOptions().getContentFormat());
			exchange.respond(CHANGED);
		} else {
			exchange.respond(BAD_REQUEST, "Content-Format not set");
		}
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

		// signal that resource state changed
		changed();
	}
}
