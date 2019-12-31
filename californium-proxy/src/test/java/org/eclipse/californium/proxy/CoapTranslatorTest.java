/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.proxy;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

import java.net.InetSocketAddress;

import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.junit.Test;

/**
 * This tests checks the functionality of the CoapTranslator.
 */
public class CoapTranslatorTest {

	@Test
	public void testTranslateDeprecatedRequest() throws TranslationException {
		Request request = Request.newGet();
		request.setURI("coap://localhost:5685/coap2coap");
		request.getOptions().setProxyUri("coap://localhost:5683/targetResource");
		request.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);

		Request translatedRequest = CoapTranslator.getRequest(request);

		assertThat(translatedRequest.getOptions().getContentFormat(), is(MediaTypeRegistry.TEXT_PLAIN));
		assertThat(translatedRequest.getCode(), is(Code.GET));
		assertThat(translatedRequest.getOptions().getUriHost(), is("localhost"));
		assertThat(translatedRequest.getOptions().getUriPort(), is(nullValue()));
		assertThat(translatedRequest.getOptions().getUriPathString(), is("targetResource"));
		assertThat(translatedRequest.getOptions().hasObserve(), is(request.getOptions().hasObserve()));
	}

	@Test
	public void testTranslateRequest() throws TranslationException {
		Request request = Request.newGet();
		request.setDestinationContext(new AddressEndpointContext(new InetSocketAddress("localhost", 5684)));
		request.setScheme("coap");
		request.getOptions().setUriHost("localhost");
		request.getOptions().setUriPort(5686);
		request.getOptions().setUriPath("targetResource");
		request.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);

		Request translatedRequest = CoapTranslator.getRequest(request);

		assertThat(translatedRequest.getOptions().getContentFormat(), is(MediaTypeRegistry.TEXT_PLAIN));
		assertThat(translatedRequest.getCode(), is(Code.GET));
		assertThat(translatedRequest.getOptions().getUriHost(), is("localhost"));
		assertThat(translatedRequest.getOptions().getUriPort(), is(nullValue()));
		assertThat(translatedRequest.getOptions().getUriPathString(), is("targetResource"));
		assertThat(translatedRequest.getOptions().hasObserve(), is(request.getOptions().hasObserve()));
	}
}
