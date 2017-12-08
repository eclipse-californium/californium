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
 *    Achim Kraus (Bosch Software Innovations GmbH) - reduce external dependency
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.junit.Assert.assertTrue;

import java.net.InetSocketAddress;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.CheckCondition;
import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.InMemoryMessageExchangeStore;
import org.eclipse.californium.core.network.MessageExchangeStore;
import org.eclipse.californium.core.network.Outbox;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.stack.BlockwiseLayer;
import org.eclipse.californium.core.network.stack.CoapStack;
import org.eclipse.californium.core.network.stack.CoapUdpStack;
import org.eclipse.californium.core.network.stack.Layer;
import org.eclipse.californium.core.observe.InMemoryObservationStore;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.UdpEndpointContextMatcher;

/**
 * Test tools for MessageExchangeStore.
 * 
 * Dumps exchanges, if MessageExchangeStore is not finally empty.
 */
public class MessageExchangeStoreTool {

	/**
	 * Assert, that all exchanges in both stores are empty.
	 * 
	 * dump exchanges, if not empty.
	 * 
	 * @param config used network configuration.
	 * @param clientExchangeStore client message exchange store.
	 * @param serverExchangeStore server message exchange store.
	 */
	public static void assertAllExchangesAreCompleted(NetworkConfig config,
			final MessageExchangeStore clientExchangeStore, final MessageExchangeStore serverExchangeStore) {
		int exchangeLifetime = (int) config.getLong(NetworkConfig.Keys.EXCHANGE_LIFETIME);
		int sweepInterval = config.getInt(NetworkConfig.Keys.MARK_AND_SWEEP_INTERVAL);
		waitUntilDeduplicatorShouldBeEmpty(exchangeLifetime, sweepInterval, new CheckCondition() {

			@Override
			public boolean isFulFilled() throws IllegalStateException {
				return clientExchangeStore.isEmpty() && serverExchangeStore.isEmpty();
			}
		});
		assertTrue("Client side message exchange store still contains exchanges", clientExchangeStore.isEmpty());
		assertTrue("Server side message exchange store still contains exchanges", serverExchangeStore.isEmpty());
	}

	/**
	 * Assert, that all exchanges in store are empty.
	 * 
	 * dump exchanges, if not empty.
	 * 
	 * @param config used network configuration.
	 * @param exchangeStore message exchange store.
	 */
	public static void assertAllExchangesAreCompleted(NetworkConfig config, final MessageExchangeStore exchangeStore) {
		int exchangeLifetime = (int) config.getLong(NetworkConfig.Keys.EXCHANGE_LIFETIME);
		int sweepInterval = config.getInt(NetworkConfig.Keys.MARK_AND_SWEEP_INTERVAL);
		waitUntilDeduplicatorShouldBeEmpty(exchangeLifetime, sweepInterval, new CheckCondition() {

			@Override
			public boolean isFulFilled() throws IllegalStateException {
				return exchangeStore.isEmpty();
			}
		});
		assertTrue("message exchange store still contains exchanges", exchangeStore.isEmpty());
	}

	/**
	 * Assert, that exchanges store and block-wise layer are empty.
	 */
	public static void assertAllExchangesAreCompleted(final CoapTestEndpoint endpoint) {
		NetworkConfig config = endpoint.getConfig();
		int exchangeLifetime = (int) config.getLong(NetworkConfig.Keys.EXCHANGE_LIFETIME);
		int sweepInterval = config.getInt(NetworkConfig.Keys.MARK_AND_SWEEP_INTERVAL);

		waitUntilDeduplicatorShouldBeEmpty(exchangeLifetime, sweepInterval, new CheckCondition() {

			@Override
			public boolean isFulFilled() throws IllegalStateException {
				return endpoint.isEmpty() && endpoint.getRequestChecker().allRequestsTerminated();
			}
		});
		assertTrue("endpoint still contains states", endpoint.isEmpty());
		assertTrue(endpoint.getRequestChecker().getUnterminatedRequests()+ " not terminated with an event",
				endpoint.getRequestChecker().allRequestsTerminated());
		
	}

	public static void waitUntilDeduplicatorShouldBeEmpty(final int exchangeLifetime, final int sweepInterval, CheckCondition check) {
		try {
			int timeToWait = exchangeLifetime + sweepInterval + 300; // milliseconds
			System.out.println("Wait until deduplicator should be empty (" + timeToWait/1000f + " seconds)");
			TestTools.waitForCondition(timeToWait, timeToWait / 10, TimeUnit.MILLISECONDS, check);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	public static class CoapUdpTestStack extends CoapUdpStack {

		private BlockwiseLayer blockwiseLayer;

		public CoapUdpTestStack(NetworkConfig config, Outbox outbox) {
			super(config, outbox);
		}

		@Override
		protected Layer createBlockwiseLayer(NetworkConfig config) {
			blockwiseLayer = (BlockwiseLayer) super.createBlockwiseLayer(config);
			return blockwiseLayer;
		}

		public BlockwiseLayer getBlockwiseLayer() {
			return blockwiseLayer;
		}

		public boolean isEmpty() {
			return blockwiseLayer == null || blockwiseLayer.isEmpty();
		}
	}

	public static class CoapTestEndpoint extends CoapEndpoint {

		private final MessageExchangeStore exchangeStore;
		private final InMemoryObservationStore observationStore;
		private CoapUdpTestStack stack;
		private RequestEventChecker requestChecker;

		private CoapTestEndpoint(InetSocketAddress bind, NetworkConfig config,
				InMemoryObservationStore observationStore, MessageExchangeStore exchangeStore) {
			super(new UDPConnector(bind), true, config, observationStore, exchangeStore, new UdpEndpointContextMatcher());
			this.exchangeStore = exchangeStore;
			this.observationStore = observationStore;
			this.requestChecker = new RequestEventChecker();
		}

		public CoapTestEndpoint(InetSocketAddress bind, NetworkConfig config) {
			this(bind, config, new InMemoryObservationStore(), new InMemoryMessageExchangeStore(config));
		}

		@Override
		protected CoapStack createUdpStack(NetworkConfig config, Outbox outbox) {
			stack = new CoapUdpTestStack(config, outbox);
			return stack;
		}

		public MessageExchangeStore getExchangeStore() {
			return exchangeStore;
		}

		public InMemoryObservationStore getObservationStore() {
			return observationStore;
		}

		public CoapUdpTestStack getStack() {
			return stack;
		}

		public boolean isEmpty() {
			return exchangeStore.isEmpty() && (stack == null || stack.isEmpty());
		}

		@Override
		public void sendRequest(Request request) {
			requestChecker.registerRequest(request);
			super.sendRequest(request);
		}

		public RequestEventChecker getRequestChecker() {
			return requestChecker;
		}
	}

	public static class RequestEventChecker {

		private Collection<Request> requests = Collections.synchronizedSet(new HashSet<Request>());

		public void registerRequest(final Request request) {
			requests.add(request);

			request.addMessageObserver(new MessageObserverAdapter() {

				@Override
				public void onCancel() {
					requests.remove(request);
				}

				@Override
				public void onReject() {
					requests.remove(request);
				}

				@Override
				public void onResponse(Response response) {
					requests.remove(request);
				}

				@Override
				public void onSendError(Throwable error) {
					requests.remove(request);
				}

				@Override
				public void onTimeout() {
					requests.remove(request);
				}
			});
		}

		public boolean allRequestsTerminated() {
			return requests.isEmpty();
		}
		
		public Collection<Request> getUnterminatedRequests(){
			return requests;
		}
	}
}
