/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.Semaphore;
import java.util.logging.Level;

import org.eclipse.californium.core.CaliforniumLogger;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.stack.congestioncontrol.Cocoa;

public class CocoaClient {
	
	static {
		CaliforniumLogger.initialize();
		CaliforniumLogger.setLevel(Level.CONFIG);
	}

    public static void main(String[] args) {
    	
		// get URI from command line arguments
    	URI uri = null;
		try {
    		if (args.length > 0) {
				uri = new URI(args[0]);
			} else {
				uri = new URI("coap://iot.eclipse.org/test");
			}
		} catch (URISyntaxException e) {
			System.err.println("Invalid URI: " + e.getMessage());
			System.exit(-1);
		}
    	
    	NetworkConfig config = new NetworkConfig()
    		// enable congestion control (can also be done cia Californium.properties)
    		.setBoolean(NetworkConfig.Keys.USE_CONGESTION_CONTROL, true)
	    	// see class names in org.eclipse.californium.core.network.stack.congestioncontrol
	    	.setString(NetworkConfig.Keys.CONGESTION_CONTROL_ALGORITHM, Cocoa.class.getSimpleName())
	    	// set NSTART to four
	    	.setInt(NetworkConfig.Keys.NSTART, 4);
    	
    	// create an endpoint with this configuration
    	CoapEndpoint cocoaEndpoint = new CoapEndpoint(config);
    	// all CoapClients will use the default endpoint (unless CoapClient#setEndpoint() is used)
    	EndpointManager.getEndpointManager().setDefaultEndpoint(cocoaEndpoint);
        
		CoapClient client = new CoapClient(uri);
		
		final int NUMBER = 50;
		final Semaphore semaphore = new Semaphore(0);
		
		for (int i=0; i<NUMBER; ++i) {
			client.get(new CoapHandler() {
				@Override
				public void onLoad(CoapResponse response) {
					semaphore.release();
					System.out.println("Received " + semaphore.availablePermits());
				}
				
				@Override
				public void onError() {
					System.out.println("Failed");
				}
			});
		}
		
		// wait until all requests finished
		try {
			semaphore.acquire(NUMBER);
		} catch (InterruptedException e) {}
	}
}
