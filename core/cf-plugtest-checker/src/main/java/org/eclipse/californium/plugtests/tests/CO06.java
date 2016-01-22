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
package org.eclipse.californium.plugtests.tests;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.logging.Level;

import org.eclipse.californium.core.CaliforniumLogger;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;

import org.eclipse.californium.plugtests.PlugtestChecker.TestClientAbstract;

/**
 * TD_COAP_OBS_06: Server detection of deregistration (explicit RST).
 */
public class CO06 extends TestClientAbstract {
	

	static {
		CaliforniumLogger.setLevel(Level.FINER);
	}

	public static final String RESOURCE_URI = "/obs";
	public final ResponseCode EXPECTED_RESPONSE_CODE = ResponseCode.CONTENT;

	public CO06(String serverURI) {
		super(CO06.class.getSimpleName());

		// create the request
		Request request = new Request(Code.GET, Type.CON);
		// set Observe option
		request.setObserve();
		// set the parameters and execute the request
		executeRequest(request, serverURI, RESOURCE_URI);
	}

	@Override
	protected synchronized void executeRequest(Request request, String serverURI, String resourceUri) {

		// defensive check for slash
		if (!serverURI.endsWith("/") && !resourceUri.startsWith("/")) {
			resourceUri = "/" + resourceUri;
		}

		URI uri = null;
		try {
			uri = new URI(serverURI + resourceUri);
		} catch (URISyntaxException use) {
			throw new IllegalArgumentException("Invalid URI: "
					+ use.getMessage());
		}

		request.setURI(uri);

        // for observing
        int observeLoop = 2;

        // print request info
        if (verbose) {
            System.out.println("Request for test " + this.testName + " sent");
			Utils.prettyPrint(request);
        }

        // execute the request
        try {
            Response response = null;
            boolean success = true;
            long time = 5000;

			request.send();
            
            System.out.println();
            System.out.println("**** TEST: " + testName + " ****");
            System.out.println("**** BEGIN CHECK ****");

			response = request.waitForResponse(time);
            if (response != null) {
				success &= checkType(Type.ACK, response.getType());
				success &= checkInt(EXPECTED_RESPONSE_CODE.value, response.getCode().value, "code");
				success &= checkToken(request.getToken(), response.getToken());
				success &= hasContentType(response);
				success &= hasNonEmptyPalyoad(response);
				success &= hasObserve(response);
                
                if (success) {

                	time = response.getOptions().getMaxAge() * 1000;
    				System.out.println("+++++ Max-Age: "+time+" +++++");
    				if (time==0) time = 5000;
	            
		            for (int l = 0; success && (l < observeLoop); ++l) {
		
						response = request.waitForResponse(time + 1000);
		                
						// checking the response
						if (response != null) {
							System.out.println("Received notification " + l);
		                	
		                    // print response info
		                    if (verbose) {
		                        System.out.println("Response received");
		                        System.out.println("Time elapsed (ms): " + response.getRTT());
		                        Utils.prettyPrint(response);
		                    }
		
		                    success &= checkResponse(request, response);

						} else {
			            	System.out.println("FAIL: Notifications stopped");
							success = false;
							break;
						} // response != null
					} // observeLoop
					
					if (response!=null) {
						
			            System.out.println("+++++++ Canceling +++++++");
			            request.cancel(); // stack should send RST
	
			            Thread.sleep(time + time/2);
						
					} else {
	                    System.out.println("FAIL: Notifications stopped");
						success = false;
					}
                }
            } else {
            	System.out.println("FAIL: No notification after registration");
				success = false;
            }
			
            if (success) {
                System.out.println("**** TEST PASSED ****");
                addSummaryEntry(testName + ": PASSED (conditionally)");
            } else {
                System.out.println("**** TEST FAILED ****");
                addSummaryEntry(testName + ": --FAILED--");
            }

            tickOffTest();
			
		} catch (InterruptedException e) {
			System.err.println("Interupted during receive: "
					+ e.getMessage());
			System.exit(-1);
		}
	}

	protected boolean checkResponse(Request request, Response response) {
		boolean success = true;

		success &= checkType(Type.CON, response.getType());
		success &= checkInt(EXPECTED_RESPONSE_CODE.value, response.getCode().value, "code");
		success &= checkToken(request.getToken(), response.getToken());
		success &= hasContentType(response);
		success &= hasNonEmptyPalyoad(response);
		success &= hasObserve(response);

		return success;
	}
}
