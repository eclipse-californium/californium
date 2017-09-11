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
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange.KeyToken;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.observe.InMemoryObservationStore;
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
	private InMemoryRandomTokenProvider tokenProvider; 
	private InMemoryMessageExchangeStore messageExchangeStore;
	private EndpointContext correlationContext1;
	private EndpointContext correlationContext2;
	private EndpointContextMatcher correlationContextMatcher;
	
	@Before
	public void before(){
		NetworkConfig config = NetworkConfig.createStandardWithoutFile();
		tokenProvider = new InMemoryRandomTokenProvider(config);
		messageExchangeStore = new InMemoryMessageExchangeStore(config, tokenProvider);
		observationStore =  new InMemoryObservationStore();
		correlationContext1 = mock(EndpointContext.class);
		correlationContext2 = mock(EndpointContext.class);
		correlationContextMatcher = mock(EndpointContextMatcher.class);
		when(correlationContext1.getPeerAddress()).thenReturn(dest);
		when(correlationContext2.getPeerAddress()).thenReturn(dest);
	}

	@Test
	public void testReceiveResponseAcceptsWithCorrelationContext() {
		// GIVEN a request sent without any additional correlation information
		//  using a matcher set to lax matching
		when(correlationContextMatcher.isResponseRelatedToRequest(correlationContext1, correlationContext2)).thenReturn(true);

		UdpMatcher matcher = newUdpMatcher();

		Exchange exchange = sendRequest(dest, matcher, correlationContext1);

		// WHEN a response arrives with arbitrary additional correlation information
		Response response = receiveResponseFor(exchange.getCurrentRequest());
		response.setSourceContext(correlationContext2);
		Exchange matchedExchange = matcher.receiveResponse(response);

		verify(correlationContextMatcher, times(1)).isResponseRelatedToRequest(correlationContext1, correlationContext2);
		
		// THEN assert that the response is successfully matched against the request
		assertThat(matchedExchange, is(exchange));
	}

	@Test
	public void testReceiveResponseRejectsWithCorrelationContext() {
		// GIVEN a request sent without any additional correlation information
		//  using a matcher set to lax matching
		when(correlationContextMatcher.isResponseRelatedToRequest(correlationContext1, correlationContext2)).thenReturn(false);

		UdpMatcher matcher = newUdpMatcher();

		Exchange exchange = sendRequest(dest, matcher, correlationContext1);

		// WHEN a response arrives with arbitrary additional correlation information
		Response response = receiveResponseFor(exchange.getCurrentRequest());
		response.setSourceContext(correlationContext2);
		Exchange matchedExchange = matcher.receiveResponse(response);

		verify(correlationContextMatcher, times(1)).isResponseRelatedToRequest(correlationContext1, correlationContext2);
		
		// THEN assert that the response is successfully matched against the request
		assertThat(matchedExchange, is(nullValue()));
	}

	@Test
	public void testReceiveResponseAcceptsWithoutCorrelationContext() {
		// GIVEN a request sent without any additional correlation information
		//  using a matcher set to lax matching
		when(correlationContextMatcher.isResponseRelatedToRequest(null, correlationContext2)).thenReturn(true);

		UdpMatcher matcher = newUdpMatcher();

		Exchange exchange = sendRequest(dest, matcher, null);

		// WHEN a response arrives with arbitrary additional correlation information
		Response response = receiveResponseFor(exchange.getCurrentRequest());
		response.setSourceContext(correlationContext2);
		Exchange matchedExchange = matcher.receiveResponse(response);

		verify(correlationContextMatcher, times(1)).isResponseRelatedToRequest(null, correlationContext2);
		
		// THEN assert that the response is successfully matched against the request
		assertThat(matchedExchange, is(exchange));
	}

	@Test
	public void testReceiveResponseRejectsWithoutCorrelationContext() {
		// GIVEN a request sent without any additional correlation information
		//  using a matcher set to lax matching
		when(correlationContextMatcher.isResponseRelatedToRequest(null, correlationContext2)).thenReturn(false);

		UdpMatcher matcher = newUdpMatcher();

		Exchange exchange = sendRequest(dest, matcher, null);

		// WHEN a response arrives with arbitrary additional correlation information
		Response response = receiveResponseFor(exchange.getCurrentRequest());
		response.setSourceContext(correlationContext2);
		Exchange matchedExchange = matcher.receiveResponse(response);

		verify(correlationContextMatcher, times(1)).isResponseRelatedToRequest(null, correlationContext2);
		
		// THEN assert that the response is successfully matched against the request
		assertThat(matchedExchange, is(nullValue()));
	}


	@Test
	public void testReceiveResponseReleasesToken() {
		// GIVEN a request without token sent
		UdpMatcher matcher = newUdpMatcher();
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
		UdpMatcher matcher = newUdpMatcher();
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
		UdpMatcher matcher = newUdpMatcher();
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
		verify(correlationContextMatcher, never()).isResponseRelatedToRequest(null, null);
		UdpMatcher matcher = MatcherTestUtils.newUdpMatcher(exchangeStore, observationStore, correlationContextMatcher);

		// WHEN the request is being sent
		matcher.sendRequest(exchange, request);

		// THEN the request has no MID and token assigned and the exchange has not observer registered
		assertThat(request.getToken(), is(nullValue()));
		assertFalse(request.hasMID());
		assertFalse(exchange.hasObserver());
	}

	private UdpMatcher newUdpMatcher() {
		return MatcherTestUtils.newUdpMatcher(messageExchangeStore, observationStore, correlationContextMatcher);
	}
}
