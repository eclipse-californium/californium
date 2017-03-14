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
 *    Paul LeMarquand - initial creation
 ******************************************************************************/
package org.eclipse.californium.proxy;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import org.apache.http.HttpEntity;
import org.apache.http.entity.ContentType;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.junit.Test;

public class HttpTranslatorTest {

	@Test
	public void testGetHttpEntity() throws Exception {
		Request req = new Request(Code.GET);
		req.setPayload("payload");
		req.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);

		validateCharset(req, StandardCharsets.ISO_8859_1);
	}

	@Test
	public void testGetHttpEntityWithJSON() throws Exception {
		Request req = new Request(Code.GET);
		req.setPayload("{}");
		req.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_JSON);

		// Charset should be modified to be ISO_8859_1 unless the contentFormat
		// is APPLICATION_JSON, in which case it should stay UTF-8
		validateCharset(req, StandardCharsets.UTF_8);
	}

	private void validateCharset(Message request, Charset charset) throws TranslationException {
		HttpEntity httpEntity = HttpTranslator.getHttpEntity(request);
		Charset httpEntityCharset = ContentType.parse(httpEntity.getContentType().getValue()).getCharset();

		assertThat(httpEntityCharset, equalTo(charset));
	}
}
