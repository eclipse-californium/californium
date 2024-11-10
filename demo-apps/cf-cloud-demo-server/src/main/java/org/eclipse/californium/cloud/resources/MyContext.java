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
package org.eclipse.californium.cloud.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_ACCEPTABLE;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_CBOR;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_JSON;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_XML;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.UNDEFINED;

import java.net.InetSocketAddress;
import java.security.Principal;

import org.eclipse.californium.cloud.util.Formatter;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.TlsEndpointContext;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.config.DtlsConfig;

/**
 * Context resource.
 * 
 * @since 3.12
 */
public class MyContext extends ProtectedCoapResource {

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

		int accept = exchange.getRequestOptions().getAccept();
		if (accept == UNDEFINED) {
			accept = TEXT_PLAIN;
		}

		Response response = new Response(CONTENT);
		response.getOptions().setContentFormat(accept);

		byte[] payload = null;
		switch (accept) {
		case TEXT_PLAIN:
			payload = handleGet(exchange, new Formatter.Text());
			break;
		case APPLICATION_CBOR:
			payload = handleGet(exchange, new Formatter.Cbor());
			break;
		case APPLICATION_JSON:
			payload = handleGet(exchange, new Formatter.Json());
			break;
		case APPLICATION_XML:
			payload = handleGet(exchange, new Formatter.Xml("context"));
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

}
