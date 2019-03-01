/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
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
 *    Tobias Andersson (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import static org.junit.Assert.*;

import java.net.InetSocketAddress;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.oscore.OptionJuggle;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class OptionJuggleTest {

	private final Integer observe = 42;
	private final int accept = 1;
	private final byte[] oscore = new byte[] { 0x04, 0x02 };
	private final Long maxAge = (long) 33;
	private final Token token = new Token(new byte[] { 0x09, 0x08, 0x07, 0x06 });
	private final int mid = 8;
	private final Type type = Type.CON;
	private final byte[] payload = new byte[] { 0x01, 0x02, 0x09 };
	private final String uri = "coap/";
	private final EndpointContext sourceContext = new AddressEndpointContext(new InetSocketAddress(42));
	private final EndpointContext destinationContext = new AddressEndpointContext(new InetSocketAddress(24));

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testPrepareUOptions() {
		OptionSet uOptions = new OptionSet();
		uOptions.setObserve(observe);
		uOptions.setAccept(accept);

		OptionSet trimmed = OptionJuggle.prepareUoptions(uOptions);

		assertEquals(observe, trimmed.getObserve());
		assertEquals(-1, trimmed.getAccept());
	}

	@Test
	public void testPrepareEOptions() {
		OptionSet eOptions = new OptionSet();
		eOptions.setOscore(oscore);
		eOptions.setAccept(accept);

		OptionSet trimmed = OptionJuggle.prepareEoptions(eOptions);

		assertNull(trimmed.getOscore());
		assertEquals(accept, trimmed.getAccept());
	}

	@Test
	public void testDiscardEOptions() {
		OptionSet options = new OptionSet();
		options.setAccept(accept);
		options.setIfNoneMatch(true);
		options.setMaxAge(maxAge);
		options.setUriHost(uri);

		OptionSet trimmed = OptionJuggle.discardEOptions(options);

		assertNotEquals(accept, trimmed.getAccept());
		assertFalse(trimmed.hasIfNoneMatch());
		assertNotEquals(maxAge, trimmed.getMaxAge());
		assertEquals(uri, trimmed.getUriHost());
	}

	@Test
	public void testFakeCodeRequet() {
		Request request = Request.newGet();

		Request faked = OptionJuggle.setFakeCodeRequest(request);

		assertEquals(CoAP.Code.POST, faked.getCode());
	}

	@Test
	public void testFakeCodeRequestObserve() {
		Request request = Request.newGet();
		request.setObserve();

		Request faked = OptionJuggle.setFakeCodeRequest(request);

		assertEquals(CoAP.Code.FETCH, faked.getCode());
	}

	@Test
	public void testFakeCodeResponse() {
		Response response = new Response(ResponseCode.CONTENT);

		Response faked = OptionJuggle.setFakeCodeResponse(response);

		assertEquals(ResponseCode.CHANGED, faked.getCode());
	}

	@Test
	public void testRealCodeRequest() {
		Request request = new Request(Code.POST);
		request.setToken(token);
		request.setMID(mid);
		request.setType(type);
		request.setPayload(payload);
		request.setSourceContext(sourceContext);
		request.setDestinationContext(destinationContext);
		OptionSet options = new OptionSet();
		options.setAccept(accept);

		request.setOptions(options);
		Code realCode = Code.PUT;

		Request realed = OptionJuggle.setRealCodeRequest(request, realCode);
		OptionSet realOptions = realed.getOptions();

		assertEquals(realCode, realed.getCode());
		assertEquals(token, realed.getToken());
		assertEquals(mid, realed.getMID());
		assertEquals(type, realed.getType());
		assertEquals(payload, realed.getPayload());
		assertEquals(sourceContext, realed.getSourceContext());
		assertEquals(destinationContext, realed.getDestinationContext());
		assertEquals(accept, realOptions.getAccept());
	}

	@Test
	public void testRealCodeResponse() {
		Response response = new Response(ResponseCode.CHANGED);
		response.setToken(token);
		response.setMID(mid);
		response.setType(type);
		response.setPayload(payload);
		response.setSourceContext(sourceContext);
		response.setDestinationContext(destinationContext);
		OptionSet options = new OptionSet();
		options.setAccept(accept);

		response.setOptions(options);
		ResponseCode realCode = ResponseCode.CONTENT;

		Response realed = OptionJuggle.setRealCodeResponse(response, realCode);
		OptionSet realOptions = realed.getOptions();

		assertEquals(realCode, realed.getCode());
		assertEquals(token, realed.getToken());
		assertEquals(mid, realed.getMID());
		assertEquals(type, realed.getType());
		assertEquals(payload, realed.getPayload());
		assertEquals(sourceContext, realed.getSourceContext());
		assertEquals(destinationContext, realed.getDestinationContext());
		assertEquals(accept, realOptions.getAccept());
	}
}
