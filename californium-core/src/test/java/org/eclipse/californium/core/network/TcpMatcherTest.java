/*******************************************************************************
 * Copyright (c) 2016, 2017 Bosch Software Innovations GmbH and others.
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
 ******************************************************************************/
package org.eclipse.californium.core.network;

import static org.eclipse.californium.core.network.MatcherTestUtils.newTcpMatcher;
import static org.eclipse.californium.core.network.MatcherTestUtils.receiveResponseFor;
import static org.eclipse.californium.core.network.MatcherTestUtils.sendRequest;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.network.MatcherTestUtils.TestEndpointReceiver;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Verifies behavior of {@link TcpMatcher}.
 *
 */
@Category(Small.class)
public class TcpMatcherTest {

	private static final InetSocketAddress dest = new InetSocketAddress(InetAddress.getLoopbackAddress(), 5684);
	private EndpointContext exchangeEndpointContext;
	private EndpointContext responseEndpointContext;
	private EndpointContextMatcher endpointContextMatcher;

	@Before
	public void before() {
		exchangeEndpointContext = mock(EndpointContext.class);
		responseEndpointContext = mock(EndpointContext.class);
		endpointContextMatcher = mock(EndpointContextMatcher.class);
		when(exchangeEndpointContext.getPeerAddress()).thenReturn(dest);
		when(responseEndpointContext.getPeerAddress()).thenReturn(dest);
	}

	@Test
	public void testRequestMatchesResponse() {
		when(endpointContextMatcher.isResponseRelatedToRequest(exchangeEndpointContext, responseEndpointContext))
				.thenReturn(true);

		TcpMatcher matcher = newTcpMatcher(endpointContextMatcher);
		Exchange exchange = sendRequest(dest, matcher, exchangeEndpointContext);
		TestEndpointReceiver receiver = new TestEndpointReceiver();

		matcher.receiveResponse(receiveResponseFor(exchange.getCurrentRequest(), responseEndpointContext), receiver);
		Exchange matched = receiver.waitForExchange(1000);
		assertSame(exchange, matched);

		verify(endpointContextMatcher, times(1)).isResponseRelatedToRequest(exchangeEndpointContext,
				responseEndpointContext);
	}

	@Test
	public void testRequestDoesntMatchesResponse() {
		when(endpointContextMatcher.isResponseRelatedToRequest(exchangeEndpointContext, responseEndpointContext))
				.thenReturn(false);

		TcpMatcher matcher = newTcpMatcher(endpointContextMatcher);
		Exchange exchange = sendRequest(dest, matcher, exchangeEndpointContext);
		TestEndpointReceiver receiver = new TestEndpointReceiver();

		matcher.receiveResponse(receiveResponseFor(exchange.getCurrentRequest(), responseEndpointContext), receiver);
		Exchange matched = receiver.waitForExchange(1000);
		assertThat(matched, is(nullValue()));

		verify(endpointContextMatcher, times(1)).isResponseRelatedToRequest(exchangeEndpointContext,
				responseEndpointContext);
	}

}
