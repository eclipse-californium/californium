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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.plugtests.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_ACCEPTABLE;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_CBOR;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_JSON;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_XML;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.UNDEFINED;

import java.net.InetSocketAddress;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.util.StringUtil;

import com.upokecenter.cbor.CBORObject;

/**
 * My IP resource.
 * 
 * @since 2.5
 */
public class MyIp extends CoapResource {

	public static final String RESOURCE_NAME = "myip";

	public MyIp(String name, boolean visible) {
		super(name, visible);
		getAttributes().setTitle("MyIp");
		getAttributes().addContentType(TEXT_PLAIN);
		getAttributes().addContentType(APPLICATION_CBOR);
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
			payload = handleGetFormat(exchange, "ip:%s\nport:%d");
			break;
		case APPLICATION_CBOR:
			payload = handleGetCbor(exchange);
			break;
		case APPLICATION_JSON:
			payload = handleGetFormat(exchange, "{ \"ip\" : \"%s\",\n \"port\" : %d }");
			break;
		case APPLICATION_XML:
			payload = handleGetFormat(exchange, "<ip host=\"%s\" port=\"%d\" />");
			break;
		default:
			String ct = MediaTypeRegistry.toString(accept);
			exchange.respond(NOT_ACCEPTABLE, "Type \"" + ct + "\" is not supported for this resource!", TEXT_PLAIN);
			return;
		}
		response.setPayload(payload);
		exchange.respond(response);
	}

	private byte[] handleGetCbor(CoapExchange exchange) {
		InetSocketAddress source = exchange.advanced().getRequest().getSourceContext().getPeerAddress();

		CBORObject map = CBORObject.NewMap();
		map.set("ip", CBORObject.FromObject(StringUtil.toString(source.getAddress())));
		map.set("port", CBORObject.FromObject(source.getPort()));
		return map.EncodeToBytes();
	}

	private byte[] handleGetFormat(CoapExchange exchange, String format) {
		InetSocketAddress source = exchange.advanced().getRequest().getSourceContext().getPeerAddress();
		String host = StringUtil.toString(source.getAddress());
		return String.format(format, host, source.getPort()).getBytes();
	}
}
