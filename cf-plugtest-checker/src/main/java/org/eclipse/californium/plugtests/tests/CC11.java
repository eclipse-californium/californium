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
package org.eclipse.californium.plugtests.tests;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;

import org.eclipse.californium.plugtests.PlugtestChecker.TestClientAbstract;

/**
 * TD_COAP_CORE_11: Handle request not containing Token option.
 */
public class CC11 extends TestClientAbstract {

	public static final String RESOURCE_URI = "/test";
	public final ResponseCode EXPECTED_RESPONSE_CODE = ResponseCode.CONTENT;

	public CC11(String serverURI) {
		super(CC11.class.getSimpleName());

		// create the request
		Request request = new Request(Code.GET, Type.CON);
		// Length of the token should be between 1 to 8 B
		// request.setToken(TokenManager.getInstance().acquireToken(false));
		// // TODO
		// set the parameters and execute the request
		executeRequest(request, serverURI, RESOURCE_URI);
	}

	protected boolean checkResponse(Request request, Response response) {
		boolean success = true;

		success &= checkType(Type.ACK, response.getType());
		success &= checkInt(EXPECTED_RESPONSE_CODE.value,
				response.getCode().value, "code");
		// Token value = the same value as in the request sent by the client
		// in step 2
		success &= checkToken(request.getToken(), response.getToken());
		success &= hasContentType(response);
		success &= hasNonEmptyPalyoad(response);

		return success;
	}
}
