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
 *    Paul LeMarquand - initial creation
 ******************************************************************************/
package org.eclipse.californium.proxy2;

import static org.hamcrest.core.StringContains.*;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;

import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestFactory;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.DefaultHttpRequestFactory;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.util.ExpectedExceptionWrapper;
import org.eclipse.californium.elements.util.StandardCharsets;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class HttpTranslatorTest {
	/**
	 * No exception expected by default
	 */
	@Rule
	public ExpectedException exception = ExpectedExceptionWrapper.none();

	@Test
	public void testPutHttpEntity() throws Exception {
		Request req = new Request(Code.PUT);
		req.setPayload("payload");
		req.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);

		validateCharset(req, StandardCharsets.ISO_8859_1);
	}

	@Test
	public void testPutHttpEntityWithJSON() throws Exception {
		Request req = new Request(Code.PUT);
		req.setPayload("{}");
		req.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_JSON);

		// Charset should be modified to be ISO_8859_1 unless the contentFormat
		// is APPLICATION_JSON, in which case it should stay UTF-8
		validateCharset(req, StandardCharsets.UTF_8);
	}

//	public Request getCoapRequest(HttpRequest httpRequest, String httpResource, boolean proxyingEnabled) throws TranslationException {

	@Test
	public void testHttp2CoapLocalUri() throws Exception {
		HttpRequestFactory factory = new DefaultHttpRequestFactory();
		HttpRequest request = factory.newHttpRequest("GET", "/local/l-target?para1=1&para2=t");

		Request coapRequest = new Http2CoapTranslator().getCoapRequest(request, "local", false);
		assertThat(coapRequest.getCode(), is(CoAP.Code.GET));
		assertThat(coapRequest.getURI(), is("coap://localhost/l-target?para1=1&para2=t"));
	}

	@Test
	public void testHttp2CoapLocalMalformedUri() throws Exception {
		exception.expect(TranslationException.class);
		exception.expectMessage(containsString("scheme"));
		HttpRequestFactory factory = new DefaultHttpRequestFactory();
		HttpRequest request = factory.newHttpRequest("GET", "/local/coap://destination/target?para1=1&para2=t");

		new Http2CoapTranslator().getCoapRequest(request, "local", false);
	}

	@Test
	public void testHttp2CoapProxyUri() throws Exception {
		HttpRequestFactory factory = new DefaultHttpRequestFactory();
		HttpRequest request = factory.newHttpRequest("PUT", "/proxy/coap://destination:5683/target?para1=1&para2=t");
		addEntity(request, "put");

		Request coapRequest = new Http2CoapTranslator().getCoapRequest(request, "proxy", true);
		assertThat(coapRequest.getCode(), is(CoAP.Code.PUT));
		assertThat(coapRequest.getOptions().getProxyUri(), is("coap://destination:5683/target?para1=1&para2=t"));
		assertThat(coapRequest.getPayloadString(), is("put"));
	}

	@Test
	public void testHttp2CoapProxyMalformedUri() throws Exception {
		exception.expect(TranslationException.class);
		exception.expectMessage(containsString("scheme"));
		HttpRequestFactory factory = new DefaultHttpRequestFactory();
		HttpRequest request = factory.newHttpRequest("PUT", "/proxy/coap//destination:5683/target?para1=1&para2=t");
		addEntity(request, "put");

		new Http2CoapTranslator().getCoapRequest(request, "proxy", true);
	}

	@Test
	public void testHttp2CoapHttpProxyUri() throws Exception {
		HttpRequestFactory factory = new DefaultHttpRequestFactory();
		HttpRequest request = factory.newHttpRequest("POST", "http://destination:5683/target/coap:?para1=1&para2=t");
		addEntity(request, "post");

		Request coapRequest = new Http2CoapTranslator().getCoapRequest(request, "proxy", true);
		assertThat(coapRequest.getCode(), is(CoAP.Code.POST));
		assertThat(coapRequest.getOptions().getProxyUri(), is("coap://destination:5683/target?para1=1&para2=t"));
		assertThat(coapRequest.getPayloadString(), is("post"));
	}

	@Test
	public void testHttp2CoapHttpProxyMalformedUri() throws Exception {
		exception.expect(TranslationException.class);
		exception.expectMessage(containsString("scheme"));
		HttpRequestFactory factory = new DefaultHttpRequestFactory();
		HttpRequest request = factory.newHttpRequest("POST", "http://destination:5683/target?para1=1&para2=t");
		addEntity(request, "post");

		new Http2CoapTranslator().getCoapRequest(request, "proxy", true);
	}

	private void validateCharset(Message request, Charset charset) throws TranslationException {
		HttpEntity httpEntity = new HttpTranslator().getHttpEntity(request);
		Charset httpEntityCharset = ContentType.parse(httpEntity.getContentType().getValue()).getCharset();

		assertThat(httpEntityCharset, equalTo(charset));
	}

	private void addEntity(HttpRequest request, String message) throws UnsupportedEncodingException {
		if (request instanceof HttpEntityEnclosingRequest) {
			HttpEntity entity = new StringEntity(message);
			((HttpEntityEnclosingRequest)request).setEntity(entity);
		}
	}
}
