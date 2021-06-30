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
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.Semaphore;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.config.CoapConfig.CongestionControlMode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.elements.config.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CocoaClient {

	/** The logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(CocoaClient.class);

	public static void main(String[] args) {
		CoapConfig.register();

		// get URI from command line arguments
		URI uri = null;
		try {
			if (args.length > 0) {
				uri = new URI(args[0]);
			} else {
				uri = new URI("coap://californium.eclipseprojects.io/test");
			}
		} catch (URISyntaxException e) {
			LOGGER.error("Invalid URI: {}", e.getMessage());
			System.exit(-1);
		}

		Configuration config = Configuration.createStandardWithoutFile()
				// see class names in
				// org.eclipse.californium.core.network.stack.congestioncontrol
				.set(CoapConfig.CONGESTION_CONTROL_ALGORITHM, CongestionControlMode.COCOA)
				// set NSTART to four
				.set(CoapConfig.NSTART, 4);

		// create an endpoint with this configuration
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setConfiguration(config);
		CoapEndpoint cocoaEndpoint = builder.build();
		// all CoapClients will use the default endpoint (unless
		// CoapClient#setEndpoint() is used)
		EndpointManager.getEndpointManager().setDefaultEndpoint(cocoaEndpoint);

		CoapClient client = new CoapClient(uri);

		final int NUMBER = 50;
		final Semaphore semaphore = new Semaphore(0);

		for (int i = 0; i < NUMBER; ++i) {
			client.get(new CoapHandler() {

				@Override
				public void onLoad(CoapResponse response) {
					semaphore.release();
					LOGGER.info("Received {}", semaphore.availablePermits());
				}

				@Override
				public void onError() {
					LOGGER.warn("Request failed!");
				}
			});
		}

		// wait until all requests finished
		try {
			semaphore.acquire(NUMBER);
		} catch (InterruptedException e) {
		}
		client.shutdown();
	}
}
