/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.network;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.*;
import static org.eclipse.californium.core.network.MatcherTestUtils.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.MatcherTestUtils.TestEndpointReceiver;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.observe.InMemoryObservationStore;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * This test verifies the behaviour of {@code UdpMatcher} in context of
 * multicast requests.
 */
@Category(Small.class)
public class UdpMatcherMulticastTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	private static final InetSocketAddress dest = new InetSocketAddress(InetAddress.getLoopbackAddress(), 5687);
	private static final InetSocketAddress multicast_dest = new InetSocketAddress(CoAP.MULTICAST_IPV4, 5687);

	private InMemoryObservationStore observationStore;
	private RandomTokenGenerator tokenProvider;
	private InMemoryMessageExchangeStore messageExchangeStore;
	private EndpointContext exchangeEndpointContext;
	private EndpointContext responseEndpointContext;
	private EndpointContextMatcher endpointContextMatcher;

	@Before
	public void before() throws UnknownHostException {
		NetworkConfig config = network.createStandardTestConfig();
		config.setInt(NetworkConfig.Keys.MULTICAST_BASE_MID, 20000);
		tokenProvider = new RandomTokenGenerator(config);
		messageExchangeStore = new InMemoryMessageExchangeStore(config, tokenProvider);
		observationStore = new InMemoryObservationStore(config);
		exchangeEndpointContext = mock(EndpointContext.class);
		responseEndpointContext = mock(EndpointContext.class);
		endpointContextMatcher = mock(EndpointContextMatcher.class);
		when(endpointContextMatcher.isResponseRelatedToRequest(exchangeEndpointContext, responseEndpointContext)).thenReturn(true);
		when(responseEndpointContext.getPeerAddress()).thenReturn(dest);
		when(exchangeEndpointContext.getPeerAddress()).thenReturn(multicast_dest);
	}

	@Test
	public void testReceivedResponseExchangeWithMulticastRequestExchange() {

		UdpMatcher matcher = newUdpMatcher(messageExchangeStore, observationStore, endpointContextMatcher);

		// multicast request
		Request request = Request.newGet();
		request.setType(Type.NON);
		request.setDestinationContext(new AddressEndpointContext(multicast_dest));
		Exchange exchange = new Exchange(request, Origin.LOCAL, MatcherTestUtils.TEST_EXCHANGE_EXECUTOR);
		exchange.setRequest(request);
		matcher.sendRequest(exchange);
		exchange.setEndpointContext(exchangeEndpointContext);

		// 1. Response for the request //
		Response response = new Response(ResponseCode.CONTENT);
		response.setType(Type.NON);
		response.setMID((request.getMID() + 1) & 0xffff);
		response.setToken(request.getToken());
		response.setBytes("first".getBytes());
		response.setSourceContext(responseEndpointContext);

		TestEndpointReceiver receiver = new TestEndpointReceiver();

		// verify the exchange
		matcher.receiveResponse(response, receiver);
		Exchange matched = receiver.waitForExchange(1000);
		assertThat(matched, is(exchange));

		// 2. Response for the request //
		response = new Response(ResponseCode.CONTENT);
		response.setType(Type.NON);
		response.setToken(request.getToken());
		response.setMID((request.getMID() + 2) & 0xffff);
		response.setBytes("second".getBytes());
		response.setSourceContext(responseEndpointContext);
		
		receiver = new TestEndpointReceiver();

		// verify the exchange
		matcher.receiveResponse(response, receiver);
		matched = receiver.waitForExchange(1000);
		assertThat(matched, is(exchange));

		verify(endpointContextMatcher, times(2)).isResponseRelatedToRequest(exchangeEndpointContext,
				responseEndpointContext);
	}
}
