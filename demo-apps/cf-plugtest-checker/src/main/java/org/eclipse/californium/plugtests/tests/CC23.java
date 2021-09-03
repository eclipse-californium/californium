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
 ******************************************************************************/
package org.eclipse.californium.plugtests.tests;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.plugtests.TestClientAbstract;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;

/**
 * TD_COAP_CORE_23: Perform PUT transaction containing the If-None-Match option
 * (CON mode)
 */
public class CC23 extends TestClientAbstract {

	public static final String RESOURCE_URI = "/create1";

	public static final ResponseCode EXPECTED_RESPONSE_CODE_A = ResponseCode.CREATED;
	public static final ResponseCode EXPECTED_RESPONSE_CODE_B = ResponseCode.PRECONDITION_FAILED;

	private char part = 'A';

	public CC23(String serverURI) {
		super(CC23.class.getSimpleName());

		Request request = createRequest();

		executeRequest(request, serverURI, RESOURCE_URI);

	}

	private Request createRequest() {
		Request request = Request.newPut();
		request.setConfirmable(true);
		// request.setIfNoneMatch();
		request.getOptions().setIfNoneMatch(true);
		request.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		request.setPayload("TD_COAP_CORE_23 Part " + part);
		addContextObserver(request);
		++part;
		return request;
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
			setUseTcp(uri.getScheme());
		} catch (URISyntaxException use) {
			throw new IllegalArgumentException("Invalid URI: " + use.getMessage());
		}

		addContextObserver(request);
		request.setURI(uri);

		// print request info
		if (verbose) {
			System.out.println("Request for test " + this.testName + " sent");
			Utils.prettyPrint(request);
		}

		// execute the request
		try {
			Response response = null;
			boolean success = true;

			System.out.println();
			System.out.println("**** TEST: " + testName + " ****");
			System.out.println("**** BEGIN CHECK ****");

			// Part A
			request.send();
			response = request.waitForResponse(6000);

			if (response != null && response.getCode() == ResponseCode.PRECONDITION_FAILED) {
				// test pre-condition out-of-sync ... try to synchronize ...
				System.out.println("**** TEST OUT-OF-SYNC, RETRY ****");
				request = createRequest();
				request.setURI(uri);
				request.send();
				response = request.waitForResponse(6000);
			}
			// checking the response
			if (response != null) {

				// print response info
				if (verbose) {
					System.out.println("Response received");
					System.out.println(
							"Time elapsed (ms): " + TimeUnit.NANOSECONDS.toMillis(response.getApplicationRttNanos()));
					Utils.prettyPrint(response);
				}

				success &= checkType(Type.ACK, response.getType());
				success &= checkCode(EXPECTED_RESPONSE_CODE_A, response.getCode());

				// Part B
				request = createRequest();
				request.setURI(uri);
				request.send();
				response = request.waitForResponse(6000);

				// checking the response
				if (response != null) {

					// print response info
					if (verbose) {
						System.out.println("Response received");
						System.out.println("Time elapsed (ms): "
								+ TimeUnit.NANOSECONDS.toMillis(response.getApplicationRttNanos()));
						Utils.prettyPrint(response);
					}

					success &= checkType(Type.ACK, response.getType());
					success &= checkCode(EXPECTED_RESPONSE_CODE_B, response.getCode());

				}
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
			System.err.println("Interupted during receive: " + e.getMessage());
			System.exit(-1);
		}
	}

	protected boolean checkResponse(Request request, Response response) {
		return false;
	}
}
