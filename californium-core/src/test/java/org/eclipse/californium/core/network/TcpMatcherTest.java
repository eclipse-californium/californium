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

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.CorrelationContext;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import static org.junit.Assert.assertSame;

@Category(Small.class)
public class TcpMatcherTest {

	private static final InetSocketAddress dest = new InetSocketAddress(InetAddress.getLoopbackAddress(), 5684);

	@Test
	public void testRequestMatchesResponse() {
		TcpMatcher matcher = newMatcher(false);
		Exchange exchange = sendRequest(matcher, null);

		Exchange matched = matcher.receiveResponse(responseFor(exchange.getCurrentRequest()), null);
		assertSame(exchange, matched);
	}

	private TcpMatcher newMatcher(boolean useStrictMatching) {
		NetworkConfig config = NetworkConfig.createStandardWithoutFile();
		config.setBoolean(NetworkConfig.Keys.USE_STRICT_RESPONSE_MATCHING, useStrictMatching);
		TcpMatcher matcher = new TcpMatcher(config);
		matcher.start();
		return matcher;
	}

	private Exchange sendRequest(final TcpMatcher matcher, final CorrelationContext ctx) {
		Request request = Request.newGet();
		request.setDestination(dest.getAddress());
		request.setDestinationPort(dest.getPort());
		Exchange exchange = new Exchange(request, Origin.LOCAL);
		exchange.setRequest(request);
		matcher.sendRequest(exchange, request);
		exchange.setCorrelationContext(ctx);
		return exchange;
	}

	private Response responseFor(final Request request) {
		Response response = new Response(ResponseCode.CONTENT);
		response.setMID(request.getMID());
		response.setToken(request.getToken());
		response.setBytes(new byte[]{});
		response.setSource(request.getDestination());
		response.setSourcePort(request.getDestinationPort());
		response.setDestination(request.getSource());
		response.setDestinationPort(request.getSourcePort());
		return response;
	}
}
