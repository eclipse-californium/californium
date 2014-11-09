/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.CaliforniumLogger;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.network.CoAPEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigDefaults;

public class CocoaClient {
	
	static {
		CaliforniumLogger.initialize();
		// For more information in lossy environments
		//CaliforniumLogger.setLevel(Level.FINER);
	}

    public static void main(String[] args) {
    	
		// input URI from command line arguments
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
    	
    	NetworkConfig config = new NetworkConfig();
    	config.setBoolean(NetworkConfigDefaults.USE_COCOA, true);
    	config.setInt(NetworkConfigDefaults.NSTART, 4);
    	
    	CoAPEndpoint cocoaEndpoint = new CoAPEndpoint(config);
    	EndpointManager.getEndpointManager().setDefaultEndpoint(cocoaEndpoint);
    	
        System.out.println("Using Congestion Control Advanced (CoCoA)");
        
		CoapClient client = new CoapClient(uri);
		
		final AtomicInteger count = new AtomicInteger();
		
		for (int i=0; i<50; ++i) {
		client.get(new CoapHandler() {
				@Override
				public void onLoad(CoapResponse response) {
					System.out.println("Received " + count.incrementAndGet());
				}
				
				@Override
				public void onError() {
					System.out.println("Failed");
				}
			});
		}
		
		try {
			System.in.read();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }

}
