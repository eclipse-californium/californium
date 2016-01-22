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
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;

import org.eclipse.californium.plugtests.PlugtestChecker;
import org.eclipse.californium.plugtests.PlugtestChecker.TestClientAbstract;

public class CB01 extends TestClientAbstract {

	// Handle GET blockwise transfer for large resource (early negotiation)
	public final ResponseCode EXPECTED_RESPONSE_CODE = ResponseCode.CONTENT;

	public CB01(String serverURI) {
		super(CB01.class.getSimpleName());

		Request request = Request.newGet();
		request.getOptions().setBlock2(BlockOption.size2Szx(64), false, 0);

		// set the parameters and execute the request
		executeRequest(request, serverURI, "/large");
	}

	@Override
	protected boolean checkResponse(Request request, Response response) {
		boolean success = response.getOptions().hasBlock2();

		if (!success) {
			System.out.println("FAIL: no Block2 option");
		} else {
			int maxNUM = response.getOptions().getBlock2().getNum();
			success &= checkType(Type.ACK, response.getType());
			success &= checkInt(EXPECTED_RESPONSE_CODE.value,
					response.getCode().value, "code");
			success &= checkOption(new BlockOption(PlugtestChecker.PLUGTEST_BLOCK_SZX,
					false, maxNUM), response.getOptions().getBlock2(),
					"Block2");
			success &= hasNonEmptyPalyoad(response);
			success &= hasContentType(response);
		}
		return success;
	}
}
