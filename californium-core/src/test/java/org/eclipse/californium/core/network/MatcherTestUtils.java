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
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.net.InetSocketAddress;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.observe.InMemoryObservationStore;
import org.eclipse.californium.core.observe.NotificationListener;
import org.eclipse.californium.core.observe.ObservationStore;
import org.eclipse.californium.elements.CorrelationContext;

/**
 * Helper methods for testing {@code Matcher}s.
 *
 */
public final class MatcherTestUtils {

	private MatcherTestUtils() {
	}

	static TcpMatcher newTcpMatcher(boolean useStrictMatching) {
		NetworkConfig config = NetworkConfig.createStandardWithoutFile();
		config.setBoolean(NetworkConfig.Keys.USE_STRICT_RESPONSE_MATCHING, useStrictMatching);
		NotificationListener notificationListener = new NotificationListener() {

			@Override
			public void onNotification(Request request, Response response) {
			}
			
		};
		TcpMatcher matcher = new TcpMatcher(config, notificationListener, new InMemoryObservationStore(), new InMemoryMessageExchangeStore(config), CorrelationContextMatcherFactory.create(null, config));
		matcher.start();
		return matcher;
	}

	static UdpMatcher newUdpMatcher(boolean useStrictMatching, MessageExchangeStore exchangeStore, ObservationStore observationStore) {
		NetworkConfig config = NetworkConfig.createStandardWithoutFile();
		config.setBoolean(NetworkConfig.Keys.USE_STRICT_RESPONSE_MATCHING, useStrictMatching);
		NotificationListener notificationListener = new NotificationListener() {

			@Override
			public void onNotification(Request request, Response response) {
			}
			
		};
		UdpMatcher matcher = new UdpMatcher(config, notificationListener, observationStore, exchangeStore, CorrelationContextMatcherFactory.create(null, config));

		matcher.start();
		return matcher;
	}

	static Exchange sendRequest(InetSocketAddress dest, Matcher matcher, CorrelationContext ctx) {
		Request request = Request.newGet();
		request.setDestination(dest.getAddress());
		request.setDestinationPort(dest.getPort());
		Exchange exchange = new Exchange(request, Origin.LOCAL);
		exchange.setRequest(request);
		matcher.sendRequest(exchange, request);
		exchange.setCorrelationContext(ctx);
		return exchange;
	}

	static Exchange sendObserveRequest(InetSocketAddress dest, Matcher matcher) {
		Request request = Request.newGet();
		request.setDestination(dest.getAddress());
		request.setDestinationPort(dest.getPort());
		request.setObserve();
		Exchange exchange = new Exchange(request, Origin.LOCAL);
		exchange.setRequest(request);
		matcher.sendRequest(exchange, request);
		return exchange;
	}

	static Response responseFor(final Request request) {
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
