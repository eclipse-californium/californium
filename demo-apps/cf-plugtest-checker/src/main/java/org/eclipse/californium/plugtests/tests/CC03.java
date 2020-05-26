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

import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.plugtests.TestClientAbstract;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;

/**
 * TD_COAP_CORE_03: Perform PUT transaction (CON mode).
 */
public class CC03 extends TestClientAbstract {

	public static final String RESOURCE_URI = "/test";
	private final ResponseCode[] expectedResponseCodes = new ResponseCode[] {
			ResponseCode.CREATED, ResponseCode.CHANGED };

	public CC03(String serverURI) {
		super(CC03.class.getSimpleName());

		// create the request
		Request request = Request.newPut();
		// add payload
		request.setPayload("TD_COAP_CORE_03");
		request.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		// set the parameters and execute the request
		executeRequest(request, serverURI, RESOURCE_URI);
	}

	protected boolean checkResponse(Request request, Response response) {
		boolean success = true;

		success &= checkType(Type.ACK, response.getType());
		// Code = 68 (2.04 Changed) or 65 (2.01 Created)
		success &= checkCodes(expectedResponseCodes, response.getCode());
		success &= checkInt(request.getMID(), response.getMID(), "MID");

		return success;
	}
}
