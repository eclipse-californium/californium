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

import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;

import org.eclipse.californium.plugtests.PlugtestChecker;
import org.eclipse.californium.plugtests.PlugtestChecker.TestClientAbstract;

public class CB04 extends TestClientAbstract {

	// Handle POST blockwise transfer for creating large resource
	String data = PlugtestChecker.getLargeRequestPayload();
	private ResponseCode EXPECTED_RESPONSE_CODE = ResponseCode.CREATED;

	public CB04(String serverURI) {
		super(CB04.class.getSimpleName());

		Request request = Request.newPost();
		request.setPayload(data);
		request.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);

		// set the parameters and execute the request
		executeRequest(request, serverURI, "/large-create");

		// TODO: verify resource creation (optional): send GET request to
		// location path of response
	}

	@Override
	protected boolean checkResponse(Request request, Response response) {
		boolean success = response.getOptions().hasBlock1();

		if (!success) {
			System.out.println("FAIL: no Block1 option");
		} else {
			int maxNUM = response.getOptions().getBlock1().getNum();
			success &= checkInt(EXPECTED_RESPONSE_CODE.value,
					response.getCode().value, "code");
			success &= checkOption(new BlockOption(PlugtestChecker.PLUGTEST_BLOCK_SZX,
					false, maxNUM), response.getOptions().getBlock1(),
					"Block1");
			success &= hasLocation(response);
		}

		return success;
	}
}
