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
import org.eclipse.californium.core.coap.LinkFormat;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.server.resources.CoapExchange;

/**
 * This resource implements a test of specification for the
 * ETSI IoT CoAP Plugtests, London, UK, 7--9 Mar 2014.
 */
public class LargeCreate extends CoapResource {

// Members /////////////////////////////////////////////////////////////////
	
	private int counter = 0;

// Constructors ////////////////////////////////////////////////////////////

	/*
	 * Default constructor.
	 */
	public LargeCreate() {
		this("large-create");
	}
	
	/*
	 * Constructs a new storage resource with the given resourceIdentifier.
	 */
	public LargeCreate(String resourceIdentifier) {
		super(resourceIdentifier);
		getAttributes().setTitle("Large resource that can be created using POST method");
		getAttributes().addResourceType("block");
	}

	// REST Operations /////////////////////////////////////////////////////////

	/*
	 * GET Link Format list of created sub-resources.
	 */
	@Override
	public void handleGET(CoapExchange exchange) {
		String subtree = LinkFormat.serializeTree(this);
		exchange.respond(CONTENT, subtree, APPLICATION_LINK_FORMAT);
	}
	
	/*
	 * POST content to create a sub-resource.
	 */
	@Override
	public void handlePOST(CoapExchange exchange) {
		
		if (exchange.getRequestOptions().hasContentFormat()) {
			exchange.setLocationPath( storeData(exchange.getRequestPayload(), exchange.getRequestOptions().getContentFormat()) );
			exchange.respond(CREATED);
		} else {
			exchange.respond(BAD_REQUEST, "Content-Format not set");
		}
	}

	// Internal ////////////////////////////////////////////////////////////////
	
	private class StorageResource extends CoapResource {
		
		byte[] data = null;
		int dataCt = UNDEFINED;
		
		public StorageResource(String name, byte[] post, int ct) {
			super(name);
			
			this.data = post;
			this.dataCt = ct;
			
			getAttributes().addContentType(dataCt);
			getAttributes().setMaximumSizeEstimate(data.length);
		}
		
		@Override
		public void handleGET(CoapExchange exchange) {

			if (exchange.getRequestOptions().hasAccept() && exchange.getRequestOptions().getAccept() != dataCt) {
				exchange.respond(NOT_ACCEPTABLE, MediaTypeRegistry.toString(dataCt) + " only");
			} else {
				exchange.respond(CONTENT, data, dataCt);
			}
		}

		@Override
		public void handleDELETE(CoapExchange exchange) {
			this.delete();
		}
	}
	
	/*
	 * Convenience function to store data contained in a 
	 * PUT/POST-Request. Notifies observing endpoints about
	 * the change of its contents.
	 */
	private synchronized String storeData(byte[] payload, int cf) {
		
		String name = new Integer(++counter).toString();

		// set payload and content type
		StorageResource sub = new StorageResource(name, payload, cf);
		
		add(sub);
		
		return sub.getURI();
	}
}
