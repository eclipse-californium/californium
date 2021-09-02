/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.network;

import static org.eclipse.californium.core.network.MatcherTestUtils.newUdpMatcher;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.MatcherTestUtils.TestEndpointReceiver;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.TestSynchroneExecutor;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
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

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	private ScheduledExecutorService scheduler;
	private EndpointContext exchangeEndpointContext;
	private EndpointContext responseEndpointContext;
	private EndpointContextMatcher endpointContextMatcher;

	@Before
	public void before() throws UnknownHostException {
		Configuration config = network.createStandardTestConfig();
		config.set(CoapConfig.MULTICAST_BASE_MID, 20000);
		scheduler = MatcherTestUtils.newScheduler();
		cleanup.add(scheduler);
		exchangeEndpointContext = mock(EndpointContext.class);
		responseEndpointContext = mock(EndpointContext.class);
		endpointContextMatcher = mock(EndpointContextMatcher.class);
		when(endpointContextMatcher.isResponseRelatedToRequest(exchangeEndpointContext, responseEndpointContext)).thenReturn(true);
		when(responseEndpointContext.getPeerAddress()).thenReturn(dest);
		when(endpointContextMatcher.getEndpointIdentity(responseEndpointContext)).thenReturn(dest);
		when(exchangeEndpointContext.getPeerAddress()).thenReturn(multicast_dest);
	}

	@Test
	public void testReceivedResponseExchangeWithMulticastRequestExchange() {

		final UdpMatcher matcher = newUdpMatcher(network.getStandardTestConfig(), endpointContextMatcher, scheduler);

		// multicast request
		Request request = Request.newGet();
		request.setType(Type.NON);
		request.setDestinationContext(new AddressEndpointContext(multicast_dest));
		final Exchange exchange = new Exchange(request, multicast_dest, Origin.LOCAL,
				TestSynchroneExecutor.TEST_EXECUTOR);
		exchange.execute(new Runnable() {

			@Override
			public void run() {
				matcher.sendRequest(exchange);
				exchange.setEndpointContext(exchangeEndpointContext);
			}
		});

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

		matcher.stop();
	}
}
