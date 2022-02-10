/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.proxy2.http;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;

import org.apache.hc.core5.http.EntityDetails;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.nio.RequestChannel;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.proxy2.TranslationException;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * This tests checks the functionality of the CoapTranslator.
 */
@Category(Small.class)
public class Coap2HttpTranslatorTest {

	private Coap2HttpTranslator translator;

	@Before
	public void init() {
		MappingProperties defaultMappings = new MappingProperties();
		CrossProtocolTranslator crossTranslator = new CrossProtocolTranslator(defaultMappings);
		translator = new Coap2HttpTranslator(crossTranslator, new CrossProtocolTranslator.HttpServerEtagTranslator());
	}

	@Test
	public void testTranslateRequestWithConversion()
			throws TranslationException, HttpException, IOException, URISyntaxException {

		Request request = Request.newPut();
		request.setDestinationContext(new AddressEndpointContext(new InetSocketAddress("localhost", 5684)));
		request.setProxyScheme("http");
		request.setURI("coap://localhost:5686/targetResource");
		request.setPayload("hÄllÖ");
		request.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);

		URI uri = translator.getDestinationURI(request, null);
		ProxyRequestProducer translatedRequest = translator.getHttpRequest(uri, request);
		HttpRequest httpRequest = translatedRequest.getHttpRequest();
		TestRequestChannel channel = new TestRequestChannel();
		translatedRequest.sendRequest(channel, null);
		EntityDetails details = channel.getEntityDetails();

		assertThat(details.getContentType(), is("text/plain; charset=ISO-8859-1"));
		assertThat(details.getContentLength(), is(5L));
		assertThat(httpRequest.getUri().toString(), is("http://localhost:5686/targetResource"));
		assertThat(httpRequest.getMethod(), is("PUT"));
		assertThat(httpRequest.getScheme(), is("http"));
		assertThat(httpRequest.getPath(), is("/targetResource"));
	}

	@Test
	public void testTranslateRequestWithoutConversion()
			throws TranslationException, HttpException, IOException, URISyntaxException {

		Request request = Request.newPut();
		request.setDestinationContext(new AddressEndpointContext(new InetSocketAddress("localhost", 5684)));
		request.setProxyScheme("http");
		request.setURI("coap://localhost:5686/targetResource?v=a");
		request.setPayload("{ \"hÄllÖ\" : 0 }");
		request.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_JSON);

		URI uri = translator.getDestinationURI(request, null);
		ProxyRequestProducer translatedRequest = translator.getHttpRequest(uri, request);
		HttpRequest httpRequest = translatedRequest.getHttpRequest();
		TestRequestChannel channel = new TestRequestChannel();
		translatedRequest.sendRequest(channel, null);
		EntityDetails details = channel.getEntityDetails();

		assertThat(details.getContentType(), is("application/json; charset=UTF-8"));
		assertThat(details.getContentLength(), is((long) request.getPayloadSize()));
		assertThat(httpRequest.getUri().toString(), is("http://localhost:5686/targetResource?v=a"));
		assertThat(httpRequest.getMethod(), is("PUT"));
		assertThat(httpRequest.getScheme(), is("http"));
		assertThat(httpRequest.getPath(), is("/targetResource?v=a"));
	}

	@Test
	public void testTranslateRequestUrlEncoding()
			throws TranslationException, HttpException, IOException, URISyntaxException {

		Request request = Request.newPut();
		request.setDestinationContext(new AddressEndpointContext(new InetSocketAddress("localhost", 5684)));
		request.setProxyScheme("https");
		request.setURI("coap://localhost:5686/target%2fResource?v=a&w=b");
		request.setPayload("<?xml version='1.0' encoding='UTF-8'?><body>message</body>");
		request.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_XML);

		URI uri = translator.getDestinationURI(request, null);
		ProxyRequestProducer translatedRequest = translator.getHttpRequest(uri, request);
		HttpRequest httpRequest = translatedRequest.getHttpRequest();
		TestRequestChannel channel = new TestRequestChannel();
		translatedRequest.sendRequest(channel, null);
		EntityDetails details = channel.getEntityDetails();

		assertThat(details.getContentType(), is("application/xml"));
		assertThat(details.getContentLength(), is((long) request.getPayloadSize()));
		assertThat(httpRequest.getUri().toString(), is("https://localhost:5686/target/Resource?v=a&w=b"));
		assertThat(httpRequest.getMethod(), is("PUT"));
		assertThat(httpRequest.getScheme(), is("https"));
		assertThat(httpRequest.getPath(), is("/target/Resource?v=a&w=b"));
	}

	private static class TestRequestChannel implements RequestChannel {

		private EntityDetails entityDetails;

		public EntityDetails getEntityDetails() {
			return entityDetails;
		}

		@Override
		public void sendRequest(HttpRequest request, EntityDetails entityDetails, HttpContext context)
				throws HttpException, IOException {
			this.entityDetails = entityDetails;
		}
	}
}
