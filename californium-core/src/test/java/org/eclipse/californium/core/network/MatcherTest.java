/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.network;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class MatcherTest {

	static final String SESSION_ID = "010203";
	static final String OTHER_SESSION_ID = "567322";
	static final String EPOCH = "1";
	static final String OTHER_EPOCH = "2";
	static final String CIPHER = "TLS_PSK";
	static final String OTHER_CIPHER = "TLS_NULL";
	InetSocketAddress dest;
	InetSocketAddress source;

	@Before
	public void setUp() throws Exception {
		source = new InetSocketAddress(InetAddress.getLoopbackAddress(), 12000);
		dest = new InetSocketAddress(InetAddress.getLoopbackAddress(), 5684);
	}

	@Test
	public void testReceiveResponseAcceptsResponseWithArbitraryCorrelationInformation() {
		// GIVEN a request sent without any additional correlation information
		//  using a matcher set to lax matching
		Matcher matcher = newMatcher(false);
		Exchange exchange = sendRequest(matcher);

		// WHEN a response arrives with arbitrary additional correlation information
		Exchange matchedExchange = matcher.receiveResponse(responseFor(exchange.getCurrentRequest()));

		// THEN assert that the response is successfully matched against the request
		assertThat(matchedExchange, is(exchange));
	}

	private Matcher newMatcher(boolean useStrictMatching) {
		NetworkConfig config = NetworkConfig.createStandardWithoutFile();
		return new Matcher(config);
	}

	private Exchange sendRequest(final Matcher matcher) {
		Request request = Request.newGet();
		request.setDestination(dest.getAddress());
		request.setDestinationPort(dest.getPort());
		Exchange exchange = new Exchange(request, Origin.LOCAL);
		matcher.sendRequest(exchange, request);
		return exchange;
	}

	private Response responseFor(Request request) {
		Response response = new Response(ResponseCode.CONTENT);
		response.setMID(request.getMID());
		response.setToken(request.getToken());
		response.setBytes(new byte[]{});
		response.setSource(source.getAddress());
		response.setSourcePort(source.getPort());
		return response;
	}
}
