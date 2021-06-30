/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.examples.CredentialsUtil.Mode;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;

public class SecureServer {

	public static final List<Mode> SUPPORTED_MODES = Arrays.asList(Mode.PSK, Mode.ECDHE_PSK, Mode.RPK, Mode.X509,
			Mode.WANT_AUTH, Mode.NO_AUTH);

	// allows configuration via Californium.properties
	public static final int DTLS_PORT = Configuration.getStandard().get(CoapConfig.COAP_SECURE_PORT);

	public static void main(String[] args) {

		System.out.println("Usage: java -jar ... [PSK] [ECDHE_PSK] [RPK] [X509] [WANT_AUTH|NO_AUTH]");
		System.out.println("Default :            [PSK] [ECDHE_PSK] [RPK] [X509]");
		
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

		Configuration configuration = new Configuration()
				.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false);
		DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder(configuration)
				.setAddress(new InetSocketAddress(DTLS_PORT));
		CredentialsUtil.setupCid(args, builder);
		List<Mode> modes = CredentialsUtil.parse(args, CredentialsUtil.DEFAULT_SERVER_MODES, SUPPORTED_MODES);
		CredentialsUtil.setupCredentials(builder, CredentialsUtil.SERVER_NAME, modes);
		DTLSConnector connector = new DTLSConnector(builder.build());
		CoapEndpoint.Builder coapBuilder = new CoapEndpoint.Builder()
				.setConfiguration(configuration)
				.setConnector(connector);
		server.addEndpoint(coapBuilder.build());
		server.start();

		// add special interceptor for message traces
		for (Endpoint ep : server.getEndpoints()) {
			ep.addInterceptor(new MessageTracer());
		}

		System.out.println("Secure CoAP server powered by Scandium (Sc) is listening on port " + DTLS_PORT);
	}

}
