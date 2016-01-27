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

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;

import org.eclipse.californium.plugtests.PlugtestChecker.TestClientAbstract;

/**
 * TD_COAP_OBS_04: Client detection of deregistration (Max-Age).
 */
public class CO04 extends TestClientAbstract {

	public static final String RESOURCE_URI = "/obs";
	public final ResponseCode EXPECTED_RESPONSE_CODE = ResponseCode.CONTENT;

	public CO04(String serverURI) {
		super(CO04.class.getSimpleName());

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
        int observeLoop = 10;

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
            boolean timedOut = false;

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
							System.out.println("+++++++ Received notification " + l + " +++++++");
		                	
		                    // print response info
		                    if (verbose) {
		                        System.out.println("Response received");
		                        System.out.println("Time elapsed (ms): " + response.getRTT());
		                        Utils.prettyPrint(response);
		                    }
		
		                    success &= checkResponse(request, response);

							// update timeout
							time = response.getOptions().getMaxAge() * 1000;

							if (!timedOut && l >= 2) {
								System.out.println("+++++++++++++++++++++++");
								System.out.println("++++ REBOOT SERVER ++++");
								System.out.println("+++++++++++++++++++++++");

								System.out.println("++++ obs-reset PUT ++++");
								Request asyncRequest = new Request(Code.POST, Type.CON);
								asyncRequest.setPayload("sesame");
								asyncRequest.setURI(serverURI + "/obs-reset");
								asyncRequest.addMessageObserver(new MessageObserverAdapter() {
										public void onResponse(Response response) {
												if (response != null) {
													System.out.println("Received: " + response.getCode());
													System.out.println("+++++++++++++++++++++++");
												}
											}
										});
								asyncRequest.send();
							}

						} else if (!timedOut) {
							timedOut = true;
							l = observeLoop / 2;
							System.out.println("PASS: Max-Age timed out");
							
							// automatic re-registration is done through CoapClient
							// with "advanced" (i.e., raw) Requests we need to do it manually
							System.out.println("+++++ Re-registering +++++");
							Request reregister = Request.newGet();
							reregister.setURI(uri);
							reregister.setToken(request.getToken());
							reregister.setObserve();
							request = reregister;
							request.send();
							
							response = request.waitForResponse(time);
				            if (response != null) {
								success &= checkType(Type.ACK, response.getType());
								success &= checkInt(EXPECTED_RESPONSE_CODE.value, response.getCode().value, "code");
								success &= checkToken(request.getToken(), response.getToken());
								success &= hasContentType(response);
								success &= hasNonEmptyPalyoad(response);
								success &= hasObserve(response);
				            } else {
				            	System.out.println("FAIL: Re-registration failed");
								success = false;
								break;
				            }
						} else {
							System.out.println("+++++++++++++++++++++++");
							System.out.println("++++ START SERVER +++++");
							System.out.println("+++++++++++++++++++++++");
						} // response != null
					} // observeLoop
		            
		            if (!timedOut) {
		            	System.out.println("FAIL: Server not rebooted");
						success = false;
		            }
					
					if (response!=null) {
		            
			            // RST to cancel
			            System.out.println("+++++++ Canceling +++++++");
			            
			            request.cancel();
			            
			            // wait here and let ReliabilityLayer send RST for canceled request
						Thread.sleep(time + time/2);
						response = request.getResponse();
	
						if (response != null) {
							System.out.println("FAIL: Notification after canceling");
							success = false;
						} else {
				            System.out.println("+++++++ No notification +++++++");
						}
					} else {
	                    System.out.println("FAIL: No notification after re-registration");
						success = false;
					}
                }
            } else {
            	System.out.println("FAIL: No notification after registration");
				success = false;
            }
			
            if (success) {
                System.out.println("**** TEST PASSED ****");
                addSummaryEntry(testName + ": PASSED");
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
