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
package org.eclipse.californium.extplugtests.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_ACCEPTABLE;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_CBOR;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_JSON;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.UNDEFINED;

import java.net.InetSocketAddress;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.util.StringUtil;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.upokecenter.cbor.CBORObject;

/**
 * My Ip resource.
 */
public class MyIp extends CoapResource {

	private static final String RESOURCE_NAME = "myip";

	public MyIp() {
		super(RESOURCE_NAME);
		getAttributes().setTitle("MyIp");
		getAttributes().addContentType(TEXT_PLAIN);
		getAttributes().addContentType(APPLICATION_CBOR);
		getAttributes().addContentType(APPLICATION_JSON);
	}

	@Override
	public void handleGET(CoapExchange exchange) {

		// get request to read out details
		Request request = exchange.advanced().getRequest();

		int accept = request.getOptions().getAccept();
		if (accept == UNDEFINED) {
			accept = TEXT_PLAIN;
		}
		switch (accept) {
		case UNDEFINED:
			handleGetText(exchange);
			break;
		case TEXT_PLAIN:
			handleGetText(exchange);
			break;
		case APPLICATION_CBOR:
			handleGetCbor(exchange);
			break;
		case APPLICATION_JSON:
			handleGetJson(exchange);
			break;
		default:
			exchange.respond(NOT_ACCEPTABLE);
			break;
		}
	}

	private void handleGetText(CoapExchange exchange) {
		InetSocketAddress source = exchange.advanced().getRequest().getSourceContext().getPeerAddress();
		StringBuilder builder = new StringBuilder();
		builder.append("ip:").append(StringUtil.toString(source.getAddress())).append("\n");
		builder.append("port:").append(source.getPort());
		exchange.respond(builder.toString());
	}

	private void handleGetCbor(CoapExchange exchange) {
		InetSocketAddress source = exchange.advanced().getRequest().getSourceContext().getPeerAddress();

		CBORObject map = CBORObject.NewMap();
		map.set("ip", CBORObject.FromObject(StringUtil.toString(source.getAddress())));
		map.set("port", CBORObject.FromObject(source.getPort()));
		byte[] payload = map.EncodeToBytes();
		exchange.respond(CONTENT, payload, APPLICATION_CBOR);
	}

	private void handleGetJson(CoapExchange exchange) {
		InetSocketAddress source = exchange.advanced().getRequest().getSourceContext().getPeerAddress();
		JsonObject element = new JsonObject();
		element.addProperty("ip", StringUtil.toString(source.getAddress()));
		element.addProperty("port", source.getPort());
		GsonBuilder builder = new GsonBuilder();
		Gson gson = builder.create();
		exchange.respond(CONTENT, gson.toJson(element), APPLICATION_JSON);
	}
}
