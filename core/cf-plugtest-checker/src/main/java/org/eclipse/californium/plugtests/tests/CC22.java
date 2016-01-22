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
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;

import org.eclipse.californium.plugtests.PlugtestChecker.TestClientAbstract;

/**
 * TD_COAP_CORE_22: Perform GET transaction with responses containing the
 * ETag option and requests containing the If-Match option (CON mode)
 */
public class CC22 extends TestClientAbstract {

	public static final String RESOURCE_URI = "/validate";
	public final ResponseCode EXPECTED_RESPONSE_CODE_PREAMBLE = ResponseCode.CONTENT;
	public final ResponseCode EXPECTED_RESPONSE_CODE_A = ResponseCode.CHANGED;
	public final ResponseCode EXPECTED_RESPONSE_CODE_B = ResponseCode.PRECONDITION_FAILED;

	public byte[] etag1;
	public byte[] etag2;

	public CC22(String serverURI) {
		super(CC22.class.getSimpleName());

		Request request = new Request(Code.GET, Type.CON);
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

		// print request info
		if (verbose) {
			System.out.println("Request for test " + this.testName
					+ " sent");
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

			// checking the response
			if (response != null) {

				// print response info
				if (verbose) {
					System.out.println("Response received");
					System.out.println("Time elapsed (ms): "
							+ response.getRTT());
					Utils.prettyPrint(response);
				}

				success &= checkInt(EXPECTED_RESPONSE_CODE_PREAMBLE.value,
						response.getCode().value, "code");
				success &= hasEtag(response);
				success &= hasNonEmptyPalyoad(response);
				success &= hasContentType(response);

				if (success) {
					etag1 = response.getOptions().getETags().get(0);

					// Part A
					request = new Request(Code.PUT, Type.CON);
					request.getOptions().addIfMatch(etag1);
					request.setPayload("TD_COAP_CORE_22 Part A");
					request.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);

					request.setURI(uri);

					request.send();
					response = request.waitForResponse(6000);

					// checking the response
					if (response != null) {

						// print response info
						if (verbose) {
							System.out.println("Response received");
							System.out.println("Time elapsed (ms): "
									+ response.getRTT());
							Utils.prettyPrint(response);
						}

						success &= checkInt(EXPECTED_RESPONSE_CODE_A.value,
								response.getCode().value, "code");
						success &= hasContentType(response);

						// check new ETag
						request = new Request(Code.GET, Type.CON);
						request.setURI(uri);
						request.send();

						response = request.waitForResponse(6000);

						// checking the response
						if (response != null) {

							etag2 = response.getOptions().getETags().get(0);

							success &= checkInt(EXPECTED_RESPONSE_CODE_PREAMBLE.value, response.getCode().value, "code");
							success &= hasEtag(response);
							success &= hasNonEmptyPalyoad(response);
							success &= hasContentType(response);
							success &= checkDifferentOption(etag1, etag2, "ETag");

							if (success) {

								// change server resource
								request = new Request(Code.PUT, Type.CON);
								request.setURI(uri);
								request.setPayload("It should change " + Math.random());
								request.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
								request.send();
								Thread.sleep(1000);

								// Part B
								request = new Request(Code.PUT, Type.CON);
								request.getOptions().addIfMatch(etag1);
								request.setPayload("TD_COAP_CORE_22 Part B");
								request.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);

								request.setURI(uri);

								request.send();
								response = request.waitForResponse(6000);

								// checking the response
								if (response != null) {

									// print response info
									if (verbose) {
										System.out.println("Response received");
										System.out.println("Time elapsed (ms): " + response.getRTT());
										Utils.prettyPrint(response);
									}

									success &= checkType(Type.ACK, response.getType());
									success &= checkInt(EXPECTED_RESPONSE_CODE_B.value, response.getCode().value, "code");
								}
							}
						}
					}
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

			// } catch (IOException e) {
			// System.err.println("Failed to execute request: " +
			// e.getMessage());
			// System.exit(-1);
		} catch (InterruptedException e) {
			System.err.println("Interupted during receive: "
					+ e.getMessage());
			System.exit(-1);
		}
	}

	protected boolean checkResponse(Request request, Response response) {
		return false;
	}
}
