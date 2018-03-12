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
 *    Achim Kraus (Bosch Software Innovations GmbH) - use EndpointContext and
 *                                                    EndpointContextMatcher mocks
 *    Achim Kraus (Bosch Software Innovations GmbH) - adjust to use Token
 ******************************************************************************/
package org.eclipse.californium.core.network;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static org.eclipse.californium.core.network.MatcherTestUtils.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.observe.InMemoryObservationStore;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Verifies behavior of {@code UdpMatcher}.
 *
 */
@Category(Small.class)
public class UdpMatcherTest {

	static final InetSocketAddress dest = new InetSocketAddress(InetAddress.getLoopbackAddress(), 5684);

	private InMemoryObservationStore observationStore;
	private RandomTokenGenerator tokenProvider; 
	private InMemoryMessageExchangeStore messageExchangeStore;
	private EndpointContext exchangeEndpointContext;
	private EndpointContext responseEndpointContext;
	private EndpointContextMatcher endpointContextMatcher;
	
	@Before
	public void before(){
		NetworkConfig config = NetworkConfig.createStandardWithoutFile();
		tokenProvider = new RandomTokenGenerator(config);
		messageExchangeStore = new InMemoryMessageExchangeStore(config, tokenProvider);
		observationStore =  new InMemoryObservationStore(config);
		exchangeEndpointContext = mock(EndpointContext.class);
		responseEndpointContext = mock(EndpointContext.class);
		endpointContextMatcher = mock(EndpointContextMatcher.class);
		when(exchangeEndpointContext.getPeerAddress()).thenReturn(dest);
		when(responseEndpointContext.getPeerAddress()).thenReturn(dest);
	}

	@Test
	public void testReceiveResponseAcceptsWithEndpointContext() {
		// GIVEN a request sent without any additional endpoint information
		when(endpointContextMatcher.isResponseRelatedToRequest(exchangeEndpointContext, responseEndpointContext)).thenReturn(true);

		UdpMatcher matcher = newUdpMatcher();

		Exchange exchange = sendRequest(dest, matcher, exchangeEndpointContext);

		// WHEN a response arrives with arbitrary additional endpoint information
		Response response = receiveResponseFor(exchange.getCurrentRequest(), responseEndpointContext);
		Exchange matchedExchange = matcher.receiveResponse(response);

		verify(endpointContextMatcher, times(1)).isResponseRelatedToRequest(exchangeEndpointContext, responseEndpointContext);
		
		// THEN assert that the response is successfully matched against the request
		assertThat(matchedExchange, is(exchange));
	}

	@Test
	public void testReceiveResponseRejectsWithEndpointContext() {
		// GIVEN a request sent without any additional endpoint information
		when(endpointContextMatcher.isResponseRelatedToRequest(exchangeEndpointContext, responseEndpointContext)).thenReturn(false);

		UdpMatcher matcher = newUdpMatcher();

		Exchange exchange = sendRequest(dest, matcher, exchangeEndpointContext);

		// WHEN a response arrives with arbitrary additional endpoint information
		Response response = receiveResponseFor(exchange.getCurrentRequest(), responseEndpointContext);
		Exchange matchedExchange = matcher.receiveResponse(response);

		verify(endpointContextMatcher, times(1)).isResponseRelatedToRequest(exchangeEndpointContext, responseEndpointContext);
		
		// THEN assert that the response is successfully matched against the request
		assertThat(matchedExchange, is(nullValue()));
	}

	@Test
	public void testReceiveResponseReleasesToken() {
		// GIVEN a request without token sent
		UdpMatcher matcher = newUdpMatcher();
		Exchange exchange = sendRequest(dest, matcher, null);
		// WHEN request gets completed
		exchange.setComplete();

		// THEN assert that token got released in both stores
		Token token = exchange.getCurrentRequest().getToken();
		assertThat(messageExchangeStore.get(token), is(nullValue()));
		assertThat(observationStore.get(token), is(nullValue()));
	}

	@Test
	public void testReceiveResponseForObserveDoesNotReleaseToken() {
		// GIVEN a request without token sent
		UdpMatcher matcher = newUdpMatcher();
		Exchange exchange = sendObserveRequest(dest, matcher, exchangeEndpointContext);

		// WHEN observe request gets completed
		exchange.setComplete();

		// THEN assert that token got released in message exchange store
		// THEN assert that token got not released in observation store
		Token token = exchange.getCurrentRequest().getToken();
		assertThat(messageExchangeStore.get(token), is(nullValue()));
		assertThat(observationStore.get(token), is(notNullValue()));
	}

	@Test
	public void testCancelObserveReleasesToken() {

		// GIVEN an exchange for an outbound request
		UdpMatcher matcher = newUdpMatcher();
		Exchange exchange = sendObserveRequest(dest, matcher, exchangeEndpointContext);

		// WHEN canceling any observe relations for the exchange's token
		matcher.cancelObserve(exchange.getCurrentRequest().getToken());

		// THEN the token has been released for re-use
		Token token = exchange.getCurrentRequest().getToken();
		assertThat(messageExchangeStore.get(token), is(nullValue()));
		assertThat(observationStore.get(token), is(nullValue()));
	}

	/**
	 * Verifies that canceling an unsent request (having no MID and no token assigned) does
	 * not fail.
	 */
	@Test
	public void testExchangeCompletionHandlerIsNotRegisteredOnUnsentRequests() {

		// GIVEN a request that has not been sent yet
		Request request = Request.newGet();
		request.setDestinationContext(new AddressEndpointContext(dest));
		Exchange exchange = new Exchange(request, Origin.LOCAL, MatcherTestUtils.TEST_EXCHANGE_EXECUTOR);

		MessageExchangeStore exchangeStore = mock(MessageExchangeStore.class);
		when(exchangeStore.registerOutboundRequest(exchange)).thenReturn(false);
		verify(endpointContextMatcher, never()).isResponseRelatedToRequest(null, null);
		UdpMatcher matcher = MatcherTestUtils.newUdpMatcher(exchangeStore, observationStore, endpointContextMatcher);

		// WHEN the request is being sent
		matcher.sendRequest(exchange);

		// THEN the request has no MID and token assigned and the exchange has not observer registered
		assertThat(request.getToken(), is(nullValue()));
		assertFalse(request.hasMID());
		assertFalse(exchange.hasRemoveHandler());
	}

	private UdpMatcher newUdpMatcher() {
		return MatcherTestUtils.newUdpMatcher(messageExchangeStore, observationStore, endpointContextMatcher);
	}
}
