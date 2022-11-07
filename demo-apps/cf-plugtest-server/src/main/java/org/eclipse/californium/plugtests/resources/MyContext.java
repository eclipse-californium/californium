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
import java.security.Principal;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.TlsEndpointContext;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.StandardCharsets;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.config.DtlsConfig;

import com.upokecenter.cbor.CBORObject;

/**
 * Context resource.
 * 
 * @since 3.0 (renamed, was Context)
 */
public class MyContext extends CoapResource {

	public static final String RESOURCE_NAME = "mycontext";

	private final String version;

	public MyContext(String name, String version, boolean visible) {
		super(name, visible);
		getAttributes().setTitle("Communication Context");
		getAttributes().addContentType(TEXT_PLAIN);
		getAttributes().addContentType(APPLICATION_CBOR);
		getAttributes().addContentType(APPLICATION_JSON);
		getAttributes().addContentType(APPLICATION_XML);
		this.version = version;
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
		exchange.respond(response);
	}

	private byte[] handleGet(CoapExchange coapExchange, Formatter formatter) {
		Exchange exchange = coapExchange.advanced();
		EndpointContext context = exchange.getRequest().getSourceContext();
		InetSocketAddress source = context.getPeerAddress();

		formatter.add("ip", StringUtil.toString(source.getAddress()));
		formatter.add("port", new Long(source.getPort()));
		Endpoint endpoint = exchange.getEndpoint();
		if (endpoint != null) {
			Configuration config = endpoint.getConfig();
			Integer nodeId = config.get(DtlsConfig.DTLS_CONNECTION_ID_NODE_ID);
			if (nodeId != null) {
				formatter.add("node-id", nodeId.toString());
			}
		}
		Principal peerIdentity = context.getPeerIdentity();
		if (peerIdentity != null) {
			formatter.add("peer", peerIdentity.getName());
		}
		String cipherSuite = context.getString(DtlsEndpointContext.KEY_CIPHER);
		if (cipherSuite == null) {
			cipherSuite = context.getString(TlsEndpointContext.KEY_CIPHER);
		}
		if (cipherSuite != null) {
			formatter.add("cipher-suite", cipherSuite);
		}
		String sessionId = context.getString(DtlsEndpointContext.KEY_SESSION_ID);
		if (sessionId == null) {
			sessionId = context.getString(TlsEndpointContext.KEY_SESSION_ID);
		}
		if (sessionId != null) {
			formatter.add("session-id", sessionId);
		}
		String cid = context.getString(DtlsEndpointContext.KEY_READ_CONNECTION_ID);
		if (cid != null) {
			formatter.add("read-cid", cid);
		}
		cid = context.getString(DtlsEndpointContext.KEY_WRITE_CONNECTION_ID);
		if (cid != null) {
			formatter.add("write-cid", cid);
		}
		String via = context.getString(DtlsEndpointContext.KEY_VIA_ROUTER);
		if (via != null) {
			formatter.add("via", via);
		}
		Boolean secureRenegotiation = context.get(DtlsEndpointContext.KEY_SECURE_RENEGOTIATION);
		if (secureRenegotiation != null) {
			formatter.add("secure-renegotiation", secureRenegotiation);
		}
		Boolean extendedMasterSecret = context.get(DtlsEndpointContext.KEY_EXTENDED_MASTER_SECRET);
		if (extendedMasterSecret != null) {
			formatter.add("ext-master-secret", extendedMasterSecret);
		}
		Boolean newest = context.get(DtlsEndpointContext.KEY_NEWEST_RECORD);
		if (newest != null) {
			formatter.add("newest-record", newest);
		}
		Integer limit = context.get(DtlsEndpointContext.KEY_MESSAGE_SIZE_LIMIT);
		if (limit != null) {
			formatter.add("message-size-limit", new Long(limit));
		}
		InetSocketAddress previous = context.get(DtlsEndpointContext.KEY_PREVIOUS_ADDRESS);
		if (previous != null) {
			formatter.add("prev-ip", StringUtil.toString(previous.getAddress()));
			formatter.add("prev-port", new Long(previous.getPort()));
		}
		if (version != null) {
			formatter.add("server", "Cf " + version);
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
