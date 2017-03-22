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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add CorrelationContextMatcher
 *                                                    (fix GitHub issue #104)
 ******************************************************************************/
package org.eclipse.californium.core.network;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static org.eclipse.californium.core.network.MatcherTestUtils.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.Exchange.KeyToken;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.observe.InMemoryObservationStore;
import org.eclipse.californium.elements.DtlsCorrelationContext;
import org.eclipse.californium.elements.MapBasedCorrelationContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Verifies behavior of {@code UdpMatcher}.
 *
 */
@Category(Small.class)
public class UdpMatcherTest {

	static final String SESSION_ID = "010203";
	static final String OTHER_SESSION_ID = "567322";
	static final String EPOCH = "1";
	static final String OTHER_EPOCH = "2";
	static final String CIPHER = "TLS_PSK";
	static final String OTHER_CIPHER = "TLS_NULL";
	static final InetSocketAddress dest = new InetSocketAddress(InetAddress.getLoopbackAddress(), 5684);

	private InMemoryObservationStore observationStore;
	private InMemoryRandomTokenProvider tokenProvider; 
	private InMemoryMessageExchangeStore messageExchangeStore;

	@Before
	public void before(){
		NetworkConfig config = NetworkConfig.createStandardWithoutFile();
		tokenProvider = new InMemoryRandomTokenProvider(config);
		messageExchangeStore = new InMemoryMessageExchangeStore(config, tokenProvider);
		observationStore =  new InMemoryObservationStore();
	}

	@Test
	public void testReceiveResponseAcceptsResponseWithoutCorrelationInformation() {
		// GIVEN a request sent without any additional correlation information
		//  using a matcher set to lax matching
		UdpMatcher matcher = newUdpMatcher(false);
		Exchange exchange = sendRequest(dest, matcher, null);

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
		UdpMatcher matcher = newUdpMatcher(false);
		MapBasedCorrelationContext ctx = new MapBasedCorrelationContext();
		ctx.put("key", "value");
		Exchange exchange = sendRequest(dest, matcher, ctx);

		// WHEN a response arrives without any correlation information
		Exchange matchedExchange = matcher.receiveResponse(responseFor(exchange.getCurrentRequest()), null);

		// THEN assert that the response is not matched
		assertThat(matchedExchange, is(nullValue()));
	}

	// tests verifying lax response matching based on SESSION ID and CIPHER only

	@Test
	public void testReceiveResponseAcceptsResponseFromDifferentEpochUsingLaxMatching() {
		// GIVEN a request sent via a DTLS transport using a matcher set to lax matching
		UdpMatcher matcher = newUdpMatcher(false);
		Exchange exchange = sendRequest(dest, matcher, new DtlsCorrelationContext(SESSION_ID, EPOCH, CIPHER));

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
		UdpMatcher matcher = newUdpMatcher(false);
		Exchange exchange = sendRequest(dest, matcher, new DtlsCorrelationContext(SESSION_ID, EPOCH, CIPHER));

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
		UdpMatcher matcher = newUdpMatcher(false);
		Exchange exchange = sendRequest(dest, matcher, new DtlsCorrelationContext(SESSION_ID, EPOCH, CIPHER));

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
		UdpMatcher matcher = newUdpMatcher(true);
		Exchange exchange = sendRequest(dest, matcher, new DtlsCorrelationContext(SESSION_ID, EPOCH, CIPHER));

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
		UdpMatcher matcher = newUdpMatcher(true);
		Exchange exchange = sendRequest(dest, matcher, new DtlsCorrelationContext(SESSION_ID, EPOCH, CIPHER));

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
		UdpMatcher matcher = newUdpMatcher(true);
		Exchange exchange = sendRequest(dest, matcher, new DtlsCorrelationContext(SESSION_ID, EPOCH, CIPHER));

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
		UdpMatcher matcher = newUdpMatcher(true);
		Exchange exchange = sendRequest(dest, matcher, new DtlsCorrelationContext(SESSION_ID, EPOCH, CIPHER));

		// WHEN a response arrives with the same message ID, session ID and epoch but using a different cipher
		Exchange matchedExchange = matcher.receiveResponse(
												responseFor(exchange.getCurrentRequest()),
												new DtlsCorrelationContext(SESSION_ID, EPOCH, OTHER_CIPHER));

		// THEN assert that the response is not matched
		assertThat(matchedExchange, is(nullValue()));
	}
	
	@Test
	public void testReceiveResponseReleasesToken() {
		// GIVEN a request without token sent
		UdpMatcher matcher = newUdpMatcher(false);
		Exchange exchange = sendRequest(dest, matcher, null);
				// WHEN request gets completed
		exchange.completeCurrentRequest();

		// THEN assert that token got released
		KeyToken keyToken = KeyToken.fromOutboundMessage(exchange.getCurrentRequest());
		assertThat(tokenProvider.isTokenInUse(keyToken), is(false));
	}
	
	@Test
	public void testReceiveResponseForObserveDoesNotReleaseToken() {
		// GIVEN a request without token sent
		UdpMatcher matcher = newUdpMatcher(false);
		Exchange exchange = sendObserveRequest(dest, matcher);

		// WHEN observe request gets completed
		exchange.completeCurrentRequest();

		// THEN assert that token got not released
		KeyToken keyToken = KeyToken.fromOutboundMessage(exchange.getCurrentRequest());
		assertThat(tokenProvider.isTokenInUse(keyToken), is(true));
	}

	@Test
	public void testCancelObserveReleasesToken() {

		// GIVEN an exchange for an outbound request
		UdpMatcher matcher = newUdpMatcher(false);
		Exchange exchange = sendObserveRequest(dest, matcher);

		// WHEN canceling any observe relations for the exchange's token
		matcher.cancelObserve(exchange.getCurrentRequest().getToken());

		// THEN the token has been released for re-use
		KeyToken keyToken = KeyToken.fromOutboundMessage(exchange.getCurrentRequest());
		assertThat(tokenProvider.isTokenInUse(keyToken), is(false));
	}

	/**
	 * Verifies that canceling an unsent request (having no MID and no token assigned) does
	 * not fail.
	 */
	@Test
	public void testExchangeCompletionHandlerIsNotRegisteredOnUnsentRequests() {

		// GIVEN a request that has not been sent yet
		Request request = Request.newGet();
		request.setDestination(dest.getAddress());
		request.setDestinationPort(dest.getPort());
		Exchange exchange = new Exchange(request, Origin.LOCAL);
		exchange.setRequest(request);

		MessageExchangeStore exchangeStore = mock(MessageExchangeStore.class);
		when(exchangeStore.registerOutboundRequest(exchange)).thenReturn(false);
		UdpMatcher matcher = MatcherTestUtils.newUdpMatcher(false, exchangeStore, observationStore);

		// WHEN the request is being sent
		matcher.sendRequest(exchange, request);

		// THEN the request has no MID and token assigned and the exchange has not observer registered
		assertThat(request.getToken(), is(nullValue()));
		assertFalse(request.hasMID());
		assertFalse(exchange.hasObserver());
	}

	private UdpMatcher newUdpMatcher(boolean useStrictMatching) {
		return MatcherTestUtils.newUdpMatcher(useStrictMatching, messageExchangeStore, observationStore);
	}
}
