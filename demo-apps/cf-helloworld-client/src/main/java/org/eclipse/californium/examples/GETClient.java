/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add saving payload
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.exception.ConnectorException;


public class GETClient {

	private static final File CONFIG_FILE = new File("Californium3.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for client";
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 2 * 1024 * 1024; // 2 MB
	private static final int DEFAULT_BLOCK_SIZE = 512;

	static {
		CoapConfig.register();
		UdpConfig.register();
	}

	private static DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(CoapConfig.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.set(CoapConfig.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
		}
	};

	/*
	 * Application entry point.
	 */	
	public static void main(String args[]) {
		Configuration config = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		Configuration.setStandard(config);

		URI uri = null; // URI parameter of the request

		if (args.length > 0) {

			// input URI from command line arguments
			try {
				uri = new URI(args[0]);
			} catch (URISyntaxException e) {
				System.err.println("Invalid URI: " + e.getMessage());
				System.exit(-1);
			}

			CoapClient client = new CoapClient(uri);

			try {
				CoapResponse response = client.get();
				if (response != null) {

					System.out.println(response.getCode());
					System.out.println(response.getOptions());
					if (args.length > 1) {
						try (FileOutputStream out = new FileOutputStream(args[1])) {
							out.write(response.getPayload());
						} catch (IOException e) {
							e.printStackTrace();
						}
					} else {
						System.out.println(response.getResponseText());

						System.out.println(System.lineSeparator() + "ADVANCED" + System.lineSeparator());
						// access advanced API with access to more details through
						// .advanced()
						System.out.println(Utils.prettyPrint(response));
					}
				} else {
					System.out.println("No response received.");
				}
			} catch (ConnectorException | IOException e) {
				System.err.println("Got an error: " + e);
			}

			client.shutdown();
		} else {
			// display help
			System.out.println("Californium (Cf) GET Client");
			System.out.println("(c) 2014, Institute for Pervasive Computing, ETH Zurich");
			System.out.println();
			System.out.println("Usage : " + GETClient.class.getSimpleName() + " URI [file]");
			System.out.println("  URI : The CoAP URI of the remote resource to GET");
			System.out.println("  file: optional filename to save the received payload");
		}
	}

}
