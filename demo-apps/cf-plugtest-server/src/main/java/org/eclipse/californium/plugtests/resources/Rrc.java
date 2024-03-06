/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
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
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.util.StandardCharsets;
import org.eclipse.californium.elements.util.StringUtil;

import com.upokecenter.cbor.CBORObject;

/**
 * Return routability check.
 * 
 * @since 3.11
 */
public class Rrc extends CoapResource {

	public static final String RESOURCE_NAME = "rrc";

	public Rrc(String name,  boolean visible) {
		super(name, visible);
		getAttributes().setTitle("Return Routability Check");
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
			payload = handleGet(exchange, new Text());
			break;
		case APPLICATION_CBOR:
			payload = handleGet(exchange, new Cbor());
			break;
		case APPLICATION_JSON:
			payload = handleGet(exchange, new Json());
			break;
		case APPLICATION_XML:
			payload = handleGet(exchange, new Xml("context"));
			break;
		default:
			String ct = MediaTypeRegistry.toString(accept);
			exchange.respond(NOT_ACCEPTABLE, "Type \"" + ct + "\" is not supported for this resource!", TEXT_PLAIN);
			return;
		}
		response.setPayload(payload);
		EndpointContext context = exchange.advanced().getCurrentRequest().getSourceContext();
		Boolean rrc = context.get(DtlsEndpointContext.KEY_RETURN_ROUTABILITY_CHECK);
		if (rrc != null) {
			context = MapBasedEndpointContext.addEntries(context,
					DtlsEndpointContext.ATTRIBUE_FORCED_RETURN_ROUTABILITY_CHECK);
			response.setDestinationContext(context);
		}
		exchange.respond(response);
	}

	private byte[] handleGet(CoapExchange coapExchange, Formatter formatter) {
		Exchange exchange = coapExchange.advanced();
		EndpointContext context = exchange.getRequest().getSourceContext();
		InetSocketAddress source = context.getPeerAddress();

		formatter.add("ip", StringUtil.toString(source));
		Boolean rrc = context.get(DtlsEndpointContext.KEY_RETURN_ROUTABILITY_CHECK);
		if (rrc != null) {
			formatter.add("rrc", rrc);
		}
		return formatter.getPayload();
	}

	private static interface Formatter {
		void add(String name, String value);

		void add(String name, Long value);

		void add(String name, Boolean value);

		byte[] getPayload();
	}

	private static class Text implements Formatter {
		private StringBuilder payload = new StringBuilder();

		@Override
		public void add(String name, String value) {
			payload.append(name).append(": ").append(value).append("\n");
		}

		@Override
		public void add(String name, Long value) {
			payload.append(name).append(": ").append(value).append("\n");
		}

		@Override
		public void add(String name, Boolean value) {
			payload.append(name).append(": ").append(value).append("\n");
		}

		@Override
		public byte[] getPayload() {
			if (payload.length() > 0) {
				payload.setLength(payload.length() - 1);
			}
			return payload.toString().getBytes(StandardCharsets.UTF_8);
		}

	}

	private static class Cbor implements Formatter {
		CBORObject map = CBORObject.NewMap();

		@Override
		public void add(String name, String value) {
			map.set(name, CBORObject.FromObject(value));
		}

		@Override
		public void add(String name, Long value) {
			map.set(name, CBORObject.FromObject(value));
		}

		@Override
		public void add(String name, Boolean value) {
			map.set(name, CBORObject.FromObject(value));
		}

		@Override
		public byte[] getPayload() {
			return map.EncodeToBytes();
		}

	}

	private static class Json implements Formatter {
		private StringBuilder payload = new StringBuilder("{\n");

		@Override
		public void add(String name, String value) {
			payload.append("  \"").append(name).append("\": \"").append(value).append("\",\n");
		}

		@Override
		public void add(String name, Long value) {
			payload.append("  \"").append(name).append("\": ").append(value).append(",\n");
		}

		@Override
		public void add(String name, Boolean value) {
			payload.append("  \"").append(name).append("\": ").append(value).append(",\n");
		}

		@Override
		public byte[] getPayload() {
			if (payload.length() > 0) {
				// remove last ",\n"
				payload.setLength(payload.length() - 2);
			}
			payload.append("\n}");
			return payload.toString().getBytes(StandardCharsets.UTF_8);
		}

	}

	private static class Xml implements Formatter {
		private StringBuilder payload = new StringBuilder();

		Xml(String element) {
			payload.append("<").append(element).append(" ");
		}

		@Override
		public void add(String name, String value) {
			payload.append(name).append("=\"").append(value).append("\" ");
		}

		@Override
		public void add(String name, Long value) {
			payload.append(name).append("=\"").append(value).append("\" ");
		}

		@Override
		public void add(String name, Boolean value) {
			payload.append(name).append("=\"").append(value).append("\" ");
		}

		@Override
		public byte[] getPayload() {
			payload.append("/>");
			return payload.toString().getBytes(StandardCharsets.UTF_8);
		}

	}

}
