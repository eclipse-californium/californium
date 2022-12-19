/*******************************************************************************
 * Copyright (c) 2022 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.plugtests.tests;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.plugtests.OscoreTest;
import org.eclipse.californium.plugtests.TestClientAbstract;

/**
 * Perform GET transaction.
 * 
 * @since 3.5
 */
public class OC01 extends TestClientAbstract implements OscoreTest {

	public static final String RESOURCE_URI = "/oscore";
	public final ResponseCode EXPECTED_RESPONSE_CODE = ResponseCode.CONTENT;

	public OC01(String serverURI) {
		super(OC01.class.getSimpleName());

		// create the request
		Request request = Request.newGet();
		request.getOptions().setOscore(Bytes.EMPTY);

		// set the parameters and execute the request
		executeRequest(request, serverURI, RESOURCE_URI);
	}

	protected boolean checkResponse(Request request, Response response) {
		boolean success = true;

		success &= checkType(Type.ACK, response.getType());
		success &= checkCode(EXPECTED_RESPONSE_CODE, response.getCode());
		success &= checkInt(request.getMID(), response.getMID(), "MID");
		success &= hasOption(response, StandardOptionRegistry.OSCORE, false);
		success &= hasContentType(response);
		success &= hasNonEmptyPayload(response);

		return success;
	}
}
