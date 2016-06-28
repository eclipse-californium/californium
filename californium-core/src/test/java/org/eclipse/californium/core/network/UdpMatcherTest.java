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
import static org.junit.Assert.assertThat;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.CorrelationContext;
import org.eclipse.californium.elements.DtlsCorrelationContext;
import org.eclipse.californium.elements.MapBasedCorrelationContext;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class UdpMatcherTest {

	static final String SESSION_ID = "010203";
	static final String OTHER_SESSION_ID = "567322";
	static final String EPOCH = "1";
	static final String OTHER_EPOCH = "2";
	static final String CIPHER = "TLS_PSK";
	static final String OTHER_CIPHER = "TLS_NULL";
	static final InetSocketAddress dest = new InetSocketAddress(InetAddress.getLoopbackAddress(), 5684);

	@Test
	public void testReceiveResponseAcceptsResponseWithoutCorrelationInformation() {
		// GIVEN a request sent without any additional correlation information
		//  using a matcher set to lax matching
		UdpMatcher matcher = newMatcher(false);
		Exchange exchange = sendRequest(matcher, null);

		// WHEN a response arrives with arbitrary additional correlation information
		Exchange matchedExchange = matcher.receiveResponse(
												responseFor(exchange.getCurrentRequest()),
												new MapBasedCorrelationContext());

		// THEN assert that the response is successfully matched against the request
		assertThat(matchedExchange, is(exchange));
	}

	@Test
	public void testReceiveResponseRejectsResponseWithArbitraryCorrelationInformation() {
		// GIVEN a request sent with some additional correlation information
		//  using a matcher set to lax matching
		UdpMatcher matcher = newMatcher(false);
		MapBasedCorrelationContext ctx = new MapBasedCorrelationContext();
		ctx.put("key", "value");
		Exchange exchange = sendRequest(matcher, ctx);

		// WHEN a response arrives without any correlation information
		Exchange matchedExchange = matcher.receiveResponse(responseFor(exchange.getCurrentRequest()), null);

		// THEN assert that the response is not matched
		assertThat(matchedExchange, is(nullValue()));
	}

	// tests verifying lax response matching based on SESSION ID and CIPHER only

	@Test
	public void testReceiveResponseAcceptsResponseFromDifferentEpochUsingLaxMatching() {
		// GIVEN a request sent via a DTLS transport using a matcher set to lax matching
		UdpMatcher matcher = newMatcher(false);
		Exchange exchange = sendRequest(matcher, new DtlsCorrelationContext(SESSION_ID, EPOCH, CIPHER));

		// WHEN a response arrives with the same message ID within the same DTLS session, using
		// the same cipher but from a different epoch
		Exchange matchedExchange = matcher.receiveResponse(
												responseFor(exchange.getCurrentRequest()),
												new DtlsCorrelationContext(SESSION_ID, OTHER_EPOCH, CIPHER));

		// THEN assert that the response is matched successfully
		assertThat(matchedExchange, is(exchange));
	}

	@Test
	public void testReceiveResponseRejectsResponseFromDifferentSessionUsingLaxMatching() {
		// GIVEN a request sent via a DTLS transport using a matcher set to lax matching
		UdpMatcher matcher = newMatcher(false);
		Exchange exchange = sendRequest(matcher, new DtlsCorrelationContext(SESSION_ID, EPOCH, CIPHER));

		// WHEN a response arrives with the same message ID but a different DTLS session
		Exchange matchedExchange = matcher.receiveResponse(
												responseFor(exchange.getCurrentRequest()),
												new DtlsCorrelationContext(OTHER_SESSION_ID, EPOCH, CIPHER));

		// THEN assert that the response is not matched
		assertThat(matchedExchange, is(nullValue()));
	}

	@Test
	public void testReceiveResponseRejectsResponseUsingDifferentCipherUsingLaxMatching() {
		// GIVEN a request sent via a DTLS transport using a matcher set to lax matching
		UdpMatcher matcher = newMatcher(false);
		Exchange exchange = sendRequest(matcher, new DtlsCorrelationContext(SESSION_ID, EPOCH, CIPHER));

		// WHEN a response arrives with the same message ID within the same DTLS session but using another cipher
		Exchange matchedExchange = matcher.receiveResponse(
												responseFor(exchange.getCurrentRequest()),
												new DtlsCorrelationContext(SESSION_ID, EPOCH, OTHER_CIPHER));

		// THEN assert that the response is not matched
		assertThat(matchedExchange, is(nullValue()));
	}

	// tests verifying strict response matching

	@Test
	public void testReceiveResponseAcceptsResponseFromSameSessionEpochAndCipherUsingStrictMatching() {
		// GIVEN a request sent via a DTLS transport
		UdpMatcher matcher = newMatcher(true);
		Exchange exchange = sendRequest(matcher, new DtlsCorrelationContext(SESSION_ID, EPOCH, CIPHER));

		// WHEN a response arrives with the same message ID, session ID, epoch and cipher
		Exchange matchedExchange = matcher.receiveResponse(
												responseFor(exchange.getCurrentRequest()),
												new DtlsCorrelationContext(SESSION_ID, EPOCH, CIPHER));

		// THEN assert that the response is matched successfully
		assertThat(matchedExchange, is(exchange));
	}

	@Test
	public void testReceiveResponseRejectsResponseFromDifferentEpochUsingStrictMatching() {
		// GIVEN a request sent via a DTLS transport using a matcher set to strict matching
		UdpMatcher matcher = newMatcher(true);
		Exchange exchange = sendRequest(matcher, new DtlsCorrelationContext(SESSION_ID, EPOCH, CIPHER));

		// WHEN a response arrives with the same message ID, session ID and cipher but from a different epoch
		Exchange matchedExchange = matcher.receiveResponse(
												responseFor(exchange.getCurrentRequest()),
												new DtlsCorrelationContext(SESSION_ID, OTHER_EPOCH, CIPHER));

		// THEN assert that the response is not matched
		assertThat(matchedExchange, is(nullValue()));
	}

	@Test
	public void testReceiveResponseRejectsResponseFromDifferentSessionUsingStrictMatching() {
		// GIVEN a request sent via a DTLS transport using a matcher set to strict matching
		UdpMatcher matcher = newMatcher(true);
		Exchange exchange = sendRequest(matcher, new DtlsCorrelationContext(SESSION_ID, EPOCH, CIPHER));

		// WHEN a response arrives with the same message ID, epoch and cipher but a different session ID
		Exchange matchedExchange = matcher.receiveResponse(
												responseFor(exchange.getCurrentRequest()),
												new DtlsCorrelationContext(OTHER_SESSION_ID, EPOCH, CIPHER));

		// THEN assert that the response is not matched
		assertThat(matchedExchange, is(nullValue()));
	}

	@Test
	public void testReceiveResponseRejectsResponseUsingDifferentCipherUsingStrictMatching() {
		// GIVEN a request sent via a DTLS transport using a matcher set to strict matching
		UdpMatcher matcher = newMatcher(true);
		Exchange exchange = sendRequest(matcher, new DtlsCorrelationContext(SESSION_ID, EPOCH, CIPHER));

		// WHEN a response arrives with the same message ID, session ID and epoch but using a different cipher
		Exchange matchedExchange = matcher.receiveResponse(
												responseFor(exchange.getCurrentRequest()),
												new DtlsCorrelationContext(SESSION_ID, EPOCH, OTHER_CIPHER));

		// THEN assert that the response is not matched
		assertThat(matchedExchange, is(nullValue()));
	}

	private UdpMatcher newMatcher(boolean useStrictMatching) {
		NetworkConfig config = NetworkConfig.createStandardWithoutFile();
		config.setBoolean(NetworkConfig.Keys.USE_STRICT_RESPONSE_MATCHING, useStrictMatching);
		UdpMatcher matcher = new UdpMatcher(config);
		matcher.start();
		return matcher;
	}

	private Exchange sendRequest(final UdpMatcher matcher, final CorrelationContext ctx) {
		Request request = Request.newGet();
		request.setDestination(dest.getAddress());
		request.setDestinationPort(dest.getPort());
		Exchange exchange = new Exchange(request, Origin.LOCAL);
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
