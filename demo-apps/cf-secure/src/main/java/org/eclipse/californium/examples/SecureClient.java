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

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.Arrays;
import java.util.List;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.examples.CredentialsUtil.Mode;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConfig.DtlsRole;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedSinglePskStore;

public class SecureClient {
	private static final File CONFIG_FILE = new File("Californium3SecureClient.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Secure Client";

	static {
		CoapConfig.register();
		DtlsConfig.register();
	}

	private static DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(CoapConfig.MAX_ACTIVE_PEERS, 10);
			config.set(DtlsConfig.DTLS_ROLE, DtlsRole.CLIENT_ONLY);
			config.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, false);
			config.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false);
			config.set(DtlsConfig.DTLS_PRESELECTED_CIPHER_SUITES, CipherSuite.STRONG_ENCRYPTION_PREFERENCE);
			config.setTransient(DtlsConfig.DTLS_CIPHER_SUITES);
		}
	};

	public static final List<Mode> SUPPORTED_MODES = Arrays.asList(Mode.PSK, Mode.ECDHE_PSK, Mode.RPK, Mode.X509,
			Mode.RPK_TRUST, Mode.X509_TRUST);
	private static final String SERVER_URI = "coaps://127.0.0.1:5684/secure";

	private final DTLSConnector dtlsConnector;
	private final Configuration configuration;

	public SecureClient(DTLSConnector dtlsConnector, Configuration configuration) {
		this.dtlsConnector = dtlsConnector;
		this.configuration = configuration;
	}

	public void test() {
		CoapResponse response = null;
		try {
			URI uri = new URI(SERVER_URI);
			CoapClient client = new CoapClient(uri);
			CoapEndpoint.Builder builder = new CoapEndpoint.Builder()
					.setConfiguration(configuration)
					.setConnector(dtlsConnector);

			client.setEndpoint(builder.build());
			response = client.get();
			client.shutdown();
		} catch (URISyntaxException e) {
			System.err.println("Invalid URI: " + e.getMessage());
			System.exit(-1);
		} catch (ConnectorException | IOException e) {
			System.err.println("Error occurred while sending request: " + e);
			System.exit(-1);
		}

		if (response != null) {

			System.out.println(response.getCode() + " - " + response.getCode().name());
			System.out.println(response.getOptions());
			System.out.println(response.getResponseText());
			System.out.println();
			System.out.println("ADVANCED:");
			EndpointContext context = response.advanced().getSourceContext();
			Principal identity = context.getPeerIdentity();
			if (identity != null) { 
				System.out.println(context.getPeerIdentity());
			} else {
				System.out.println("anonymous");
			}
			System.out.println(context.get(DtlsEndpointContext.KEY_CIPHER));
			System.out.println(Utils.prettyPrint(response));
		} else {
			System.out.println("No response received.");
		}
	}

	public static void main(String[] args) throws InterruptedException {
		System.out.println("Usage: java -cp ... org.eclipse.californium.examples.SecureClient [PSK|ECDHE_PSK] [RPK|RPK_TRUST] [X509|X509_TRUST]");
		System.out.println("Default:            [PSK] [RPK] [X509]");

		Configuration configuration = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		Configuration.setStandard(configuration);

		DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder(configuration);
		CredentialsUtil.setupCid(args, builder);
		List<Mode> modes = CredentialsUtil.parse(args, CredentialsUtil.DEFAULT_CLIENT_MODES, SUPPORTED_MODES);
		if (modes.contains(CredentialsUtil.Mode.PSK) || modes.contains(CredentialsUtil.Mode.ECDHE_PSK)) {
			builder.setAdvancedPskStore(new AdvancedSinglePskStore(CredentialsUtil.OPEN_PSK_IDENTITY, CredentialsUtil.OPEN_PSK_SECRET));
		}
		CredentialsUtil.setupCredentials(builder, CredentialsUtil.CLIENT_NAME, modes);
		// uncomment next line to load pem file for the example
		// CredentialsUtil.loadCredentials(builder, "client.pem");
		DTLSConnector dtlsConnector = new DTLSConnector(builder.build());

		SecureClient client = new SecureClient(dtlsConnector, configuration);
		client.test();
	}
}
