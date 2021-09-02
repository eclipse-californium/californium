/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - make exchangeStore in 
 *                                                    BaseMatcher final
 *    Achim Kraus (Bosch Software Innovations GmbH) - use provided EndpointContextMatcher
 *                                                    instead of factory
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.net.InetSocketAddress;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.observe.InMemoryObservationStore;
import org.eclipse.californium.core.observe.NotificationListener;
import org.eclipse.californium.core.observe.ObservationStore;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.TestSynchroneExecutor;
import org.eclipse.californium.elements.util.TestThreadFactory;

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

	static ScheduledExecutorService newScheduler() {
		return ExecutorsUtil.newSingleThreadScheduledExecutor(new TestThreadFactory("MatcherTest-"));
	}

	static TcpMatcher newTcpMatcher(Configuration config, EndpointContextMatcher correlationContextMatcher, ScheduledExecutorService scheduler) {
		InMemoryMessageExchangeStore exchangeStore = new InMemoryMessageExchangeStore(config);
		TcpMatcher matcher = new TcpMatcher(config, notificationListener, new RandomTokenGenerator(config),
				new InMemoryObservationStore(config), exchangeStore, correlationContextMatcher, TestSynchroneExecutor.TEST_EXECUTOR);
		exchangeStore.setExecutor(scheduler);
		matcher.start();
		return matcher;
	}

	static UdpMatcher newUdpMatcher(Configuration config, EndpointContextMatcher correlationContextMatcher, ScheduledExecutorService scheduler) {
		return newUdpMatcher(config, new InMemoryMessageExchangeStore(config), new InMemoryObservationStore(config), correlationContextMatcher, scheduler);
	}

	static UdpMatcher newUdpMatcher(Configuration config, MessageExchangeStore exchangeStore,
			ObservationStore observationStore, EndpointContextMatcher correlationContextMatcher,
			ScheduledExecutorService scheduler) {
		UdpMatcher matcher = new UdpMatcher(config, notificationListener, new RandomTokenGenerator(config),
				observationStore, exchangeStore, TestSynchroneExecutor.TEST_EXECUTOR,
				correlationContextMatcher);
		exchangeStore.setExecutor(scheduler);
		matcher.start();
		return matcher;
	}

	static Exchange sendRequest(InetSocketAddress dest, Matcher matcher, EndpointContext exchangeContext) {
		return sendRequest(dest, false, matcher, null, exchangeContext);
	}

	static Exchange sendObserveRequest(InetSocketAddress dest, Matcher matcher, EndpointContext exchangeContext) {
		return sendRequest(dest, true, matcher, null, exchangeContext);
	}

	static Exchange sendRequest(InetSocketAddress dest, boolean observe, final Matcher matcher, Exchange.EndpointContextOperator preoperator, EndpointContext exchangeContext) {
		Request request = Request.newGet();
		if (observe) {
			request.setObserve();
		}
		request.setDestinationContext(new AddressEndpointContext(dest));
		final Exchange exchange = new Exchange(request, dest, Origin.LOCAL, TestSynchroneExecutor.TEST_EXECUTOR);
		exchange.setEndpointContextPreOperator(preoperator);
		exchange.execute(new Runnable() {
			
			@Override
			public void run() {
				matcher.sendRequest(exchange);
			}
		});
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
		response.setBytes(Bytes.EMPTY);
		response.setSourceContext(sourceContext);
		return response;
	}

	public static class TestEndpointReceiver implements EndpointReceiver {

		private Exchange exchange;
		private Message message;
		private Message rejected;

		@Override
		public synchronized void receiveRequest(Exchange exchange, Request request) {
			this.exchange = exchange;
			this.message = request;
			notifyAll();
		}

		@Override
		public synchronized void receiveResponse(Exchange exchange, Response response) {
			this.exchange = exchange;
			this.message = response;
			notifyAll();
		}

		@Override
		public synchronized void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
			this.exchange = exchange;
			this.message = message;
			notifyAll();
		}

		@Override
		public synchronized void reject(final Message message) {
			this.rejected = message;
			notifyAll();
		}

		public synchronized Exchange waitForExchange(long timeoutMillis) {
			if (exchange == null) {
				try {
					wait(timeoutMillis);
				} catch (InterruptedException e) {
				}
			}
			return exchange;
		}

		public synchronized Message waitForMessage(long timeoutMillis) {
			if (message == null) {
				try {
					wait(timeoutMillis);
				} catch (InterruptedException e) {
				}
			}
			return message;
		}

		public synchronized Message waitForReject(long timeoutMillis) {
			if (rejected == null) {
				try {
					wait(timeoutMillis);
				} catch (InterruptedException e) {
				}
			}
			return rejected;
		}
	}
}
