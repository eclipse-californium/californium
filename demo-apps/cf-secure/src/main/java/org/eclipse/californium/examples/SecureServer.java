/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - use credentials util to setup
 *                                                    DtlsConnectorConfig.Builder.
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.List;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.examples.CredentialsUtil.Mode;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;

public class SecureServer {

	public static final List<Mode> SUPPORTED_MODES = Arrays
			.asList(new Mode[] { Mode.PSK, Mode.RPK, Mode.X509, Mode.NO_AUTH });

	// allows configuration via Californium.properties
	public static final int DTLS_PORT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.COAP_SECURE_PORT);

	public static void main(String[] args) {

		System.out.println("Usage: java -jar ... [PSK] [RPK] [X509] [NO_AUTH]");
		System.out.println("Default :            [PSK] [RPK] [X509]");
		
		CoapServer server = new CoapServer();
		server.add(new CoapResource("secure") {

			@Override
			public void handleGET(CoapExchange exchange) {
				exchange.respond(ResponseCode.CONTENT, "hello security");
			}
		});
		// ETSI Plugtest environment
		// server.addEndpoint(new CoAPEndpoint(new DTLSConnector(new InetSocketAddress("::1", DTLS_PORT)), NetworkConfig.getStandard()));
		// server.addEndpoint(new CoAPEndpoint(new DTLSConnector(new InetSocketAddress("127.0.0.1", DTLS_PORT)), NetworkConfig.getStandard()));
		// server.addEndpoint(new CoAPEndpoint(new DTLSConnector(new InetSocketAddress("2a01:c911:0:2010::10", DTLS_PORT)), NetworkConfig.getStandard()));
		// server.addEndpoint(new CoAPEndpoint(new DTLSConnector(new InetSocketAddress("10.200.1.2", DTLS_PORT)), NetworkConfig.getStandard()));

		DtlsConnectorConfig.Builder config = new DtlsConnectorConfig.Builder();
		config.setAddress(new InetSocketAddress(DTLS_PORT));
		List<Mode> modes = CredentialsUtil.parse(args, CredentialsUtil.DEFAULT_MODES, SUPPORTED_MODES);
		CredentialsUtil.setupCredentials(config, CredentialsUtil.SERVER_NAME, modes);
		DTLSConnector connector = new DTLSConnector(config.build());
		CoapEndpoint.CoapEndpointBuilder builder = new CoapEndpoint.CoapEndpointBuilder();
		builder.setConnector(connector);
		server.addEndpoint(builder.build());
		server.start();

		// add special interceptor for message traces
		for (Endpoint ep : server.getEndpoints()) {
			ep.addInterceptor(new MessageTracer());
		}

		System.out.println("Secure CoAP server powered by Scandium (Sc) is listening on port " + DTLS_PORT);
	}

}
