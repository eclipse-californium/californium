/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add CorrelationContextMatcher
 *                                                    (fix GitHub issue #104)
 *    Achim Kraus (Bosch Software Innovations GmbH) - use EndpointContext and
 *                                                    EndpointContextMatcher mocks
 *    Achim Kraus (Bosch Software Innovations GmbH) - adjust to use Token
 ******************************************************************************/
package org.eclipse.californium.core.network;

import static org.eclipse.californium.core.network.MatcherTestUtils.receiveResponseFor;
import static org.eclipse.californium.core.network.MatcherTestUtils.sendObserveRequest;
import static org.eclipse.californium.core.network.MatcherTestUtils.sendRequest;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.notNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.Exchange.EndpointContextOperator;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.MatcherTestUtils.TestEndpointReceiver;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.observe.InMemoryObservationStore;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.UdpEndpointContextMatcher;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Verifies behavior of {@code UdpMatcher}.
 *
 */
@Category(Small.class)
public class UdpMatcherTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	static final InetSocketAddress dest = new InetSocketAddress(InetAddress.getLoopbackAddress(), 5684);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	private ScheduledExecutorService scheduler;
	private InMemoryObservationStore observationStore;
	private RandomTokenGenerator tokenProvider; 
	private InMemoryMessageExchangeStore messageExchangeStore;
	private EndpointContext exchangeEndpointContext;
	private EndpointContext responseEndpointContext;
	private EndpointContext preEndpointContext;
	private EndpointContextMatcher endpointContextMatcher;
	private EndpointContextOperator endpointContextOperator;
	
	@Before
	public void before(){
		NetworkConfig config = NetworkConfig.createStandardWithoutFile();
		scheduler = MatcherTestUtils.newScheduler();
		cleanup.add(scheduler);
		tokenProvider = new RandomTokenGenerator(config);
		messageExchangeStore = new InMemoryMessageExchangeStore(config, tokenProvider, new UdpEndpointContextMatcher());
		observationStore =  new InMemoryObservationStore(config);
		exchangeEndpointContext = mock(EndpointContext.class);
		responseEndpointContext = mock(EndpointContext.class);
		preEndpointContext = mock(EndpointContext.class);
		endpointContextMatcher = mock(EndpointContextMatcher.class);
		endpointContextOperator = mock(EndpointContextOperator.class);
		when(exchangeEndpointContext.getPeerAddress()).thenReturn(dest);
		when(responseEndpointContext.getPeerAddress()).thenReturn(dest);
		when(endpointContextMatcher.getEndpointIdentity((EndpointContext)notNull())).thenReturn(dest);
		when(endpointContextOperator.apply(preEndpointContext)).thenReturn(exchangeEndpointContext);
	}

	@Test
	public void testReceiveResponseAcceptsWithEndpointContext() {
		// GIVEN a request sent without any additional endpoint information
		when(endpointContextMatcher.isResponseRelatedToRequest(exchangeEndpointContext, responseEndpointContext))
				.thenReturn(true);

		UdpMatcher matcher = newUdpMatcher();

		Exchange exchange = sendRequest(dest, matcher, exchangeEndpointContext);
		TestEndpointReceiver receiver = new TestEndpointReceiver();

		// WHEN a response arrives with arbitrary additional endpoint information
		Response response = receiveResponseFor(exchange.getCurrentRequest(), responseEndpointContext);
		matcher.receiveResponse(response, receiver);
		Exchange matched = receiver.waitForExchange(1000);
		assertThat(matched, is(exchange));

		verify(endpointContextMatcher, times(1)).isResponseRelatedToRequest(exchangeEndpointContext,
				responseEndpointContext);
	}

	@Test
	public void testReceiveResponseRejectsWithEndpointContext() {
		// GIVEN a request sent without any additional endpoint information
		when(endpointContextMatcher.isResponseRelatedToRequest(exchangeEndpointContext, responseEndpointContext))
				.thenReturn(false);

		UdpMatcher matcher = newUdpMatcher();

		Exchange exchange = sendRequest(dest, matcher, exchangeEndpointContext);
		TestEndpointReceiver receiver = new TestEndpointReceiver();

		// WHEN a response arrives with arbitrary additional endpoint information
		Response response = receiveResponseFor(exchange.getCurrentRequest(), responseEndpointContext);
		matcher.receiveResponse(response, receiver);
		Exchange matched = receiver.waitForExchange(1000);
		assertThat(matched, is(nullValue()));

		verify(endpointContextMatcher, times(1)).isResponseRelatedToRequest(exchangeEndpointContext,
				responseEndpointContext);
	}

	@Test
	public void testReceiveResponseReleasesToken() {
		// GIVEN a request without token sent
		UdpMatcher matcher = newUdpMatcher();
		Exchange exchange = sendRequest(dest, matcher, null);
		// WHEN request gets completed
		exchange.setComplete();

		// THEN assert that token got released in both stores
		Request request = exchange.getCurrentRequest();
		Token token = request.getToken();
		KeyToken keyToken = tokenProvider.getKeyToken(token,  request.getDestinationContext().getPeerAddress());
		assertThat(messageExchangeStore.get(keyToken), is(nullValue()));
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
		Request request = exchange.getCurrentRequest();
		Token token = request.getToken();
		KeyToken keyToken = tokenProvider.getKeyToken(token,  request.getDestinationContext().getPeerAddress());
		assertThat(messageExchangeStore.get(keyToken), is(nullValue()));
		assertThat(observationStore.get(token), is(notNullValue()));
	}

	@Test
	public void testCancelObserveReleasesToken() {

		// GIVEN an exchange for an outbound request
		UdpMatcher matcher = newUdpMatcher();
		Exchange exchange = sendObserveRequest(dest, matcher, exchangeEndpointContext);

		// WHEN canceling any observe relations for the exchange's token
		matcher.cancelObserve(exchange.getRequest().getToken());

		// THEN the token has been released for re-use
		Request request = exchange.getCurrentRequest();
		Token token = request.getToken();
		KeyToken keyToken = tokenProvider.getKeyToken(token,  request.getDestinationContext().getPeerAddress());
		assertThat(messageExchangeStore.get(keyToken), is(nullValue()));
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
		UdpMatcher matcher = newUdpMatcher(exchangeStore);

		// WHEN the request is being sent
		matcher.sendRequest(exchange);

		// THEN the request has no MID and token assigned and the exchange has not observer registered
		assertThat(request.getToken(), is(nullValue()));
		assertFalse(request.hasMID());
		assertFalse(exchange.hasRemoveHandler());
	}

	@Test
	public void testRequestGetEndpointConextAfterPreOperator() {
		// GIVEN a request sent without any additional endpoint information
		when(endpointContextMatcher.isResponseRelatedToRequest(exchangeEndpointContext, responseEndpointContext))
				.thenReturn(true);

		UdpMatcher matcher = newUdpMatcher();

		Exchange exchange = sendRequest(dest, matcher, endpointContextOperator, preEndpointContext);
		TestEndpointReceiver receiver = new TestEndpointReceiver();

		// WHEN a response arrives with arbitrary additional endpoint information
		Response response = receiveResponseFor(exchange.getCurrentRequest(), responseEndpointContext);
		matcher.receiveResponse(response, receiver);
		Exchange matched = receiver.waitForExchange(1000);
		assertThat(matched, is(exchange));

		verify(endpointContextMatcher, times(1)).isResponseRelatedToRequest(exchangeEndpointContext,
				responseEndpointContext);
		verify(endpointContextOperator, times(1)).apply(preEndpointContext);
	}

	private UdpMatcher newUdpMatcher() {
		return newUdpMatcher(messageExchangeStore);
	}

	private UdpMatcher newUdpMatcher(MessageExchangeStore exchangeStore) {
		return MatcherTestUtils.newUdpMatcher(network.getStandardTestConfig(), exchangeStore, observationStore,
				endpointContextMatcher, scheduler);
	}
}
