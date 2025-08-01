/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.plugtests.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CHANGED;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_ACCEPTABLE;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_JSON;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_OCTET_STREAM;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.UNDEFINED;

import org.eclipse.californium.core.CoapExchange;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.MediaTypeRegistry;

/**
 * This resource implements a simple test for hono clients.
 * 
 * @since 2.5
 */
public class Hono extends CoapResource {

	public Hono(String name) {
		super(name, false);
		getAttributes().setTitle("Hono test request for " + name);
		addSupportedContentFormats(APPLICATION_JSON, TEXT_PLAIN, APPLICATION_OCTET_STREAM);
	}

	@Override
	public void handlePOST(CoapExchange exchange) {
		int accept = exchange.getRequestOptions().getAccept();
		if (accept == TEXT_PLAIN || accept == UNDEFINED) {
			exchange.respond(CHANGED, getName() + " published!", TEXT_PLAIN);
		} else if (accept == APPLICATION_JSON) {
			exchange.respond(CHANGED, "{ \"type\" : \"" + getName() + "\", \"msg\" : \"published!\" }",
					APPLICATION_JSON);
		} else if (accept == APPLICATION_OCTET_STREAM) {
			exchange.respond(CHANGED, (getName() + " published!").getBytes(), APPLICATION_OCTET_STREAM);
		} else {
			String ct = MediaTypeRegistry.toString(accept);
			exchange.respond(NOT_ACCEPTABLE, "Type \"" + ct + "\" is not supported for this resource!", TEXT_PLAIN);
		}
	}

}
