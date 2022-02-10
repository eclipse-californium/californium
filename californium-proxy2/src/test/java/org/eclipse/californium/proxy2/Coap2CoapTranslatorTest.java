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
package org.eclipse.californium.proxy2;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;

import java.net.InetSocketAddress;
import java.net.URI;

import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * This tests checks the functionality of the CoapTranslator.
 */
@Category(Small.class)
public class Coap2CoapTranslatorTest {

	@Test
	public void testTranslateDeprecatedRequest() throws TranslationException {
		Coap2CoapTranslator translator = new Coap2CoapTranslator();

		Request request = Request.newGet();
		request.setURI("coap://localhost:5685/coap2coap");
		request.getOptions().setProxyUri("coap://localhost:5683/targetResource");
		request.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);

		URI uri = translator.getDestinationURI(request, null);
		Request translatedRequest = translator.getRequest(uri, request);

		assertThat(translatedRequest.getOptions().getContentFormat(), is(MediaTypeRegistry.TEXT_PLAIN));
		assertThat(translatedRequest.getCode(), is(Code.GET));
		assertThat(translatedRequest.getOptions().getUriHost(), is("localhost"));
		assertThat(translatedRequest.getOptions().getUriPort(), is(nullValue()));
		assertThat(translatedRequest.getOptions().getUriPathString(), is("targetResource"));
		assertThat(translatedRequest.getOptions().hasObserve(), is(request.getOptions().hasObserve()));
	}

	@Test
	public void testTranslateRequest() throws TranslationException {
		Coap2CoapTranslator translator = new Coap2CoapTranslator();

		Request request = Request.newGet();
		request.setDestinationContext(new AddressEndpointContext(new InetSocketAddress("localhost", 5684)));
		request.setURI("coap://localhost:5686/targetResource");
		request.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);

		URI uri = translator.getDestinationURI(request, null);
		Request translatedRequest = translator.getRequest(uri, request);

		assertThat(translatedRequest.getOptions().getContentFormat(), is(MediaTypeRegistry.TEXT_PLAIN));
		assertThat(translatedRequest.getCode(), is(Code.GET));
		assertThat(translatedRequest.getOptions().getUriHost(), is("localhost"));
		assertThat(translatedRequest.getOptions().getUriPort(), is(nullValue()));
		assertThat(translatedRequest.getOptions().getUriPathString(), is("targetResource"));
		assertThat(translatedRequest.getOptions().hasObserve(), is(request.getOptions().hasObserve()));
	}
}
