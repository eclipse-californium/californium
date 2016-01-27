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

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;

import org.eclipse.californium.plugtests.PlugtestChecker.TestClientAbstract;

public class CB02 extends TestClientAbstract {

	// Handle GET blockwise transfer for large resource (late negotiation)
	
    public static final String RESOURCE_URI = "/large";
	public final ResponseCode EXPECTED_RESPONSE_CODE = ResponseCode.CONTENT;

	public CB02(String serverURI) {
		super(CB02.class.getSimpleName());

        // create the request
		Request request = new Request(Code.GET, Type.CON);
        // set the parameters and execute the request
        executeRequest(request, serverURI, RESOURCE_URI);
	}

	@Override
	protected boolean checkResponse(Request request, Response response) {
		boolean success = response.getOptions().hasBlock2();
        
        if (!success) {
            System.out.println("FAIL: no Block2 option");
        } else {
            success &= hasNonEmptyPalyoad(response);
            success &= hasContentType(response);
        }
        return success;
	}
}
