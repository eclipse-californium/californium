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
 *                      (was HttpTranslatorTest)
 ******************************************************************************/
package org.eclipse.californium.proxy2.http;

import static org.eclipse.californium.elements.util.StandardCharsets.ISO_8859_1;
import static org.eclipse.californium.elements.util.StandardCharsets.UTF_8;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;

import java.nio.charset.Charset;

import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.Message;
import org.apache.hc.core5.http.message.BasicHttpRequest;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.ExpectedExceptionWrapper;
import org.eclipse.californium.proxy2.TranslationException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.ExpectedException;

@Category(Small.class)
public class Http2CoapTranslatorTest {

	/**
	 * No exception expected by default
	 */
	@Rule
	public ExpectedException exception = ExpectedExceptionWrapper.none();

	private CrossProtocolTranslator crossTranslator;
	private Http2CoapTranslator translator;

	@Before
	public void init() {
		MappingProperties defaultMappings = new MappingProperties();
		crossTranslator = new CrossProtocolTranslator(defaultMappings);
		translator = new Http2CoapTranslator(crossTranslator, new CrossProtocolTranslator.CoapServerEtagTranslator());
	}

	@Test
	public void testPutHttpEntity() throws Exception {
		Request req = new Request(Code.PUT);
		req.setPayload("payload");
		req.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);

		validateCharset(req, ISO_8859_1);
	}

	@Test
	public void testPutHttpEntityWithJSON() throws Exception {
		Request req = new Request(Code.PUT);
		req.setPayload("{ \"body\": \"message\" }");
		req.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_JSON);

		// Charset should be modified to be ISO_8859_1 unless
		// the media type is not convertible,
		// in which case it should stay UTF-8
		validateCharset(req, UTF_8);
	}

	@Test
	public void testPutHttpEntityWithXML() throws Exception {
		Request req = new Request(Code.PUT);
		req.setPayload("<?xml version='1.0' encoding='UTF-8'?><body>message</body>");
		req.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_XML);

		// For XML no Charset is provided nor is the content converted
		validateCharset(req, null);
	}

	// public Request getCoapRequest(HttpRequest httpRequest, String
	// httpResource, boolean proxyingEnabled) throws TranslationException {

	@Test
	public void testHttp2CoapLocalUri() throws Exception {
		Message<HttpRequest, ContentTypedEntity> request = create("GET", "/local/l-target?para1=1&para2=t");

		Request coapRequest = translator.getCoapRequest(request, "local", false);
		assertThat(coapRequest.getCode(), is(CoAP.Code.GET));
		assertThat(coapRequest.getURI(), is("coap://localhost/l-target?para1=1&para2=t"));
	}

	@Test
	public void testHttp2CoapLocalMalformedUri() throws Exception {
		exception.expect(TranslationException.class);
		exception.expectMessage(containsString("scheme"));
		Message<HttpRequest, ContentTypedEntity> request = create("GET",
				"/local/coap://destination/target?para1=1&para2=t");

		translator.getCoapRequest(request, "local", false);
	}

	@Test
	public void testHttp2CoapProxyUri() throws Exception {
		Message<HttpRequest, ContentTypedEntity> request = create("PUT",
				"/proxy/coap://destination:5683/target?para1=1&para2=t", "put");

		Request coapRequest = translator.getCoapRequest(request, "proxy", true);
		assertThat(coapRequest.getCode(), is(CoAP.Code.PUT));
		assertThat(coapRequest.getOptions().getProxyUri(), is("coap://destination:5683/target?para1=1&para2=t"));
		assertThat(coapRequest.getPayloadString(), is("put"));
	}

	@Test
	public void testHttp2CoapProxyMalformedUri() throws Exception {
		exception.expect(TranslationException.class);
		exception.expectMessage(containsString("scheme"));
		Message<HttpRequest, ContentTypedEntity> request = create("PUT",
				"/proxy/coap//destination:5683/target?para1=1&para2=t", "put");

		translator.getCoapRequest(request, "proxy", true);
	}

	@Test
	public void testHttp2CoapHttpProxyUri() throws Exception {
		Message<HttpRequest, ContentTypedEntity> request = create("POST",
				"http://destination:5683/target/coap:?para1=1&para2=t", "post");

		Request coapRequest = translator.getCoapRequest(request, "proxy", true);
		assertThat(coapRequest.getCode(), is(CoAP.Code.POST));
		assertThat(coapRequest.getOptions().getProxyUri(), is("coap://destination:5683/target?para1=1&para2=t"));
		assertThat(coapRequest.getPayloadString(), is("post"));
	}

	@Test
	public void testHttp2CoapHttpProxyMalformedUri() throws Exception {
		exception.expect(TranslationException.class);
		exception.expectMessage(containsString("scheme"));
		Message<HttpRequest, ContentTypedEntity> request = create("POST",
				"http://destination:5683/target?para1=1&para2=t", "post");

		translator.getCoapRequest(request, "proxy", true);
	}

	@Test
	public void testHttp2CoapWithCharsetConversion() throws Exception {
		Message<HttpRequest, ContentTypedEntity> request = create("POST",
				"http://destination:5683/target/coap:?para1=1&para2=t", "pÖstÄ");

		Request coapRequest = translator.getCoapRequest(request, "proxy", true);
		assertThat(coapRequest.getCode(), is(CoAP.Code.POST));
		assertThat(coapRequest.getOptions().getProxyUri(), is("coap://destination:5683/target?para1=1&para2=t"));
		assertThat(coapRequest.getPayload().length, is(7));
		assertThat(coapRequest.getPayloadString(), is("pÖstÄ"));
	}

	@Test
	public void testHttp2CoapWithoutCharsetConversion() throws Exception {
		ContentType contentType = ContentType.create("plain/text", UTF_8);
		Message<HttpRequest, ContentTypedEntity> request = create("POST",
				"http://destination:5683/target/coap:?para1=1&para2=t", "pÖstÄ", contentType);

		Request coapRequest = translator.getCoapRequest(request, "proxy", true);
		assertThat(coapRequest.getCode(), is(CoAP.Code.POST));
		assertThat(coapRequest.getOptions().getProxyUri(), is("coap://destination:5683/target?para1=1&para2=t"));
		assertThat(coapRequest.getPayload().length, is(7));
		assertThat(coapRequest.getPayloadString(), is("pÖstÄ"));
	}

	private void validateCharset(Request request, Charset charset) throws TranslationException {
		ContentTypedEntity httpEntity = crossTranslator.getHttpEntity(request);
		Charset httpEntityCharset = httpEntity.getContentType().getCharset();

		assertThat(httpEntityCharset, equalTo(charset));
	}

	private Message<HttpRequest, ContentTypedEntity> create(String method, String uri) {
		BasicHttpRequest httpRequest = new BasicHttpRequest(method, uri);
		return new Message<HttpRequest, ContentTypedEntity>(httpRequest, null);
	}

	private Message<HttpRequest, ContentTypedEntity> create(String method, String uri, String payload) {
		return create(method, uri, payload, ContentType.TEXT_PLAIN);
	}

	private Message<HttpRequest, ContentTypedEntity> create(String method, String uri, String payload,
			ContentType contentType) {
		BasicHttpRequest httpRequest = new BasicHttpRequest(method, uri);
		Charset charset = contentType.getCharset();
		if (charset == null) {
			charset = ISO_8859_1;
		}
		ContentTypedEntity entity = new ContentTypedEntity(contentType, payload.getBytes(charset));
		return new Message<HttpRequest, ContentTypedEntity>(httpRequest, entity);
	}
}
