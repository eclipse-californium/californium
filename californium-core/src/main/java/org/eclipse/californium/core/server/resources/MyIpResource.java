/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 *                    moved from cf-plugtest-server
 ******************************************************************************/
package org.eclipse.californium.core.server.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_ACCEPTABLE;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_JSON;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_XML;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.UNDEFINED;

import java.net.InetSocketAddress;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * My IP resource.
 * 
 * In (too) many cases CoAP depends on the used components on the messages IP
 * route. Especially unaware NATs cause communication problems after a quiet
 * period. Using this resource enables a coap-client to check, if the address
 * the server is aware of it, is stable or changing over the time.
 * 
 * @since 3.0 (moved from plugtest-server)
 */
public class MyIpResource extends CoapResource {

	public static final String RESOURCE_NAME = "myip";

	public MyIpResource(String name, boolean visible) {
		super(name, visible);
		getAttributes().setTitle("MyIP");
		getAttributes().addContentType(TEXT_PLAIN);
		getAttributes().addContentType(APPLICATION_JSON);
		getAttributes().addContentType(APPLICATION_XML);
	}

	@Override
	public void handleGET(CoapExchange exchange) {

		// get request to read out details
		Request request = exchange.advanced().getRequest();

		int accept = request.getOptions().getAccept();
		if (accept == UNDEFINED) {
			accept = TEXT_PLAIN;
		}

		Response response = new Response(CONTENT);
		response.getOptions().setContentFormat(accept);

		byte[] payload = null;
		switch (accept) {
		case TEXT_PLAIN:
			payload = handleGetFormat(exchange, "%1$s");
			break;
		case APPLICATION_JSON:
			payload = handleGetFormat(exchange, "{ \"ip\" : \"%2$s\",\n \"port\" : %3$d }");
			break;
		case APPLICATION_XML:
			payload = handleGetFormat(exchange, "<ip host=\"%2$s\" port=\"%3$d\" />");
			break;
		default:
			String ct = MediaTypeRegistry.toString(accept);
			exchange.respond(NOT_ACCEPTABLE, "Type \"" + ct + "\" is not supported for this resource!", TEXT_PLAIN);
			return;
		}
		response.setPayload(payload);
		exchange.respond(response);
	}

	private byte[] handleGetFormat(CoapExchange exchange, String format) {
		InetSocketAddress source = exchange.advanced().getRequest().getSourceContext().getPeerAddress();
		String address = StringUtil.toString(source);
		String host = StringUtil.toString(source.getAddress());
		return String.format(format, address, host, source.getPort()).getBytes();
	}
}
