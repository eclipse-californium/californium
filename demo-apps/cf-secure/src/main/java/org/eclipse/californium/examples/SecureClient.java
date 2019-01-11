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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.examples.CredentialsUtil.Mode;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;

public class SecureClient {

	public static final List<Mode> SUPPORTED_MODES = Arrays
			.asList(new Mode[] { Mode.PSK, Mode.ECDHE_PSK, Mode.RPK, Mode.X509, Mode.RPK_TRUST, Mode.X509_TRUST });
	private static final String SERVER_URI = "coaps://127.0.0.1:5684/secure";

	private final DTLSConnector dtlsConnector;

	public SecureClient(DTLSConnector dtlsConnector) {
		this.dtlsConnector = dtlsConnector;
	}

	public void test() {
		CoapResponse response = null;
		try {
			URI uri = new URI(SERVER_URI);
			CoapClient client = new CoapClient(uri);
			CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
			builder.setConnector(dtlsConnector);
			
			client.setEndpoint(builder.build());
			response = client.get();
			client.shutdown();
		} catch (URISyntaxException e) {
			System.err.println("Invalid URI: " + e.getMessage());
			System.exit(-1);
		}

		if (response != null) {

			System.out.println(response.getCode());
			System.out.println(response.getOptions());
			System.out.println(response.getResponseText());

			System.out.println("\nADVANCED\n");
			System.out.println(Utils.prettyPrint(response));

		} else {
			System.out.println("No response received.");
		}
	}

	public static void main(String[] args) throws InterruptedException {
		System.out.println("Usage: java -cp ... org.eclipse.californium.examples.SecureClient [PSK|ECDHE_PSK] [RPK|RPK_TRUST] [X509|X509_TRUST]");
		System.out.println("Default:            [PSK] [RPK] [X509]");

		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
		CredentialsUtil.setupCid(args, builder);
		builder.setClientOnly();
		builder.setSniEnabled(false);
		List<Mode> modes = CredentialsUtil.parse(args, CredentialsUtil.DEFAULT_CLIENT_MODES, SUPPORTED_MODES);
		if (modes.contains(CredentialsUtil.Mode.PSK) || modes.contains(CredentialsUtil.Mode.ECDHE_PSK)) {
			builder.setPskStore(new StaticPskStore(CredentialsUtil.OPEN_PSK_IDENTITY, CredentialsUtil.OPEN_PSK_SECRET));
		} else {
			builder.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
		}
		CredentialsUtil.setupCredentials(builder, CredentialsUtil.CLIENT_NAME, modes);
		DTLSConnector dtlsConnector = new DTLSConnector(builder.build());

		SecureClient client = new SecureClient(dtlsConnector);
		client.test();
	}
}
