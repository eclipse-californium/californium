/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - make exchangeStore in 
 *                                                    BaseMatcher final
 *    Achim Kraus (Bosch Software Innovations GmbH) - use provided EndpointContextMatcher
 *                                                    instead of factory
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.net.InetSocketAddress;
import java.util.concurrent.Executor;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.observe.InMemoryObservationStore;
import org.eclipse.californium.core.observe.NotificationListener;
import org.eclipse.californium.core.observe.ObservationStore;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextMatcher;

/**
 * Helper methods for testing {@code Matcher}s.
 *
 */
public final class MatcherTestUtils {

	private MatcherTestUtils() {
	}

	private static final NotificationListener notificationListener = new NotificationListener() {

		@Override
		public void onNotification(Request request, Response response) {
		}
		
	};

	public static final Executor TEST_EXCHANGE_EXECUTOR = null;
	
	static TcpMatcher newTcpMatcher(EndpointContextMatcher correlationContextMatcher) {
		NetworkConfig config = NetworkConfig.createStandardWithoutFile();
		TcpMatcher matcher = new TcpMatcher(config, notificationListener, new RandomTokenGenerator(config),
				new InMemoryObservationStore(config), new InMemoryMessageExchangeStore(config), TEST_EXCHANGE_EXECUTOR, correlationContextMatcher);
		matcher.start();
		return matcher;
	}

	static UdpMatcher newUdpMatcher(MessageExchangeStore exchangeStore, ObservationStore observationStore,
			EndpointContextMatcher correlationContextMatcher) {
		NetworkConfig config = NetworkConfig.createStandardWithoutFile();
		UdpMatcher matcher = new UdpMatcher(config, notificationListener, new RandomTokenGenerator(config),
				observationStore, exchangeStore, TEST_EXCHANGE_EXECUTOR, correlationContextMatcher);

		matcher.start();
		return matcher;
	}

	static Exchange sendRequest(InetSocketAddress dest, Matcher matcher, EndpointContext exchangeContext) {
		Request request = Request.newGet();
		request.setDestinationContext(new AddressEndpointContext(dest));
		Exchange exchange = new Exchange(request, Origin.LOCAL, TEST_EXCHANGE_EXECUTOR);
		matcher.sendRequest(exchange);
		exchange.setEndpointContext(exchangeContext);
		return exchange;
	}

	static Exchange sendObserveRequest(InetSocketAddress dest, Matcher matcher, EndpointContext exchangeContext) {
		Request request = Request.newGet();
		request.setDestinationContext(new AddressEndpointContext(dest));
		request.setObserve();
		Exchange exchange = new Exchange(request, Origin.LOCAL, TEST_EXCHANGE_EXECUTOR);
		matcher.sendRequest(exchange);
		exchange.setEndpointContext(exchangeContext);
		return exchange;
	}

	public static Response receiveResponseFor(final Request request) {
		return receiveResponseFor(request, request.getDestinationContext());
	}

	public static Response receiveResponseFor(final Request request, final EndpointContext sourceContext) {
		Response response = new Response(ResponseCode.CONTENT);
		response.setMID(request.getMID());
		response.setToken(request.getToken());
		response.setBytes(new byte[]{});
		response.setSourceContext(sourceContext);
		return response;
	}
}
