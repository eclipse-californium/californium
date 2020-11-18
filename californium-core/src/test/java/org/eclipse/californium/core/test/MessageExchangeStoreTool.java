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
 *    Achim Kraus (Bosch Software Innovations GmbH) - reduce external dependency
 *    Achim Kraus (Bosch Software Innovations GmbH) - add parameter for address check
 *                                                    in UdpEndpointContextMatcher
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.junit.Assert.assertTrue;

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.CoapStackFactory;
import org.eclipse.californium.core.network.InMemoryMessageExchangeStore;
import org.eclipse.californium.core.network.Outbox;
import org.eclipse.californium.core.network.RandomTokenGenerator;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.stack.BlockwiseLayer;
import org.eclipse.californium.core.network.stack.CoapStack;
import org.eclipse.californium.core.network.stack.CoapUdpStack;
import org.eclipse.californium.core.network.stack.Layer;
import org.eclipse.californium.core.observe.InMemoryObservationStore;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.UdpEndpointContextMatcher;
import org.eclipse.californium.elements.rule.TestTimeRule;
import org.eclipse.californium.elements.util.IntendedTestException;
import org.eclipse.californium.elements.util.TestCondition;
import org.eclipse.californium.elements.util.TestConditionTools;

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
			final InMemoryMessageExchangeStore clientExchangeStore,
			final InMemoryMessageExchangeStore serverExchangeStore, TestTimeRule time) {
		int exchangeLifetime = (int) config.getLong(NetworkConfig.Keys.EXCHANGE_LIFETIME);
		int sweepInterval = config.getInt(NetworkConfig.Keys.MARK_AND_SWEEP_INTERVAL);
		if (time != null) {
			time.setTestTimeShift(exchangeLifetime + 1000, TimeUnit.MILLISECONDS);
		}
		waitUntilDeduplicatorShouldBeEmpty(exchangeLifetime, sweepInterval, new TestCondition() {

			@Override
			public boolean isFulFilled() throws IllegalStateException {
				return clientExchangeStore.isEmpty() && serverExchangeStore.isEmpty();
			}
		});
		assertTrue("Client side message exchange store still contains exchanges", isEmptyWithDump(clientExchangeStore));
		assertTrue("Server side message exchange store still contains exchanges", isEmptyWithDump(serverExchangeStore));
	}

	/**
	 * Assert, that all exchanges in store are empty.
	 * 
	 * dump exchanges, if not empty.
	 * 
	 * @param config used network configuration.
	 * @param exchangeStore message exchange store.
	 */
	public static void assertAllExchangesAreCompleted(NetworkConfig config,
			final InMemoryMessageExchangeStore exchangeStore, TestTimeRule time) {
		int exchangeLifetime = (int) config.getLong(NetworkConfig.Keys.EXCHANGE_LIFETIME);
		int sweepInterval = config.getInt(NetworkConfig.Keys.MARK_AND_SWEEP_INTERVAL);
		if (time != null) {
			time.setTestTimeShift(exchangeLifetime + 1000, TimeUnit.MILLISECONDS);
		}
		waitUntilDeduplicatorShouldBeEmpty(exchangeLifetime, sweepInterval, new TestCondition() {

			@Override
			public boolean isFulFilled() throws IllegalStateException {
				return exchangeStore.isEmpty();
			}
		});
		assertTrue("message exchange store still contains exchanges", isEmptyWithDump(exchangeStore));
	}

	/**
	 * Assert, that exchanges store and block-wise layer are empty.
	 */
	public static void assertAllExchangesAreCompleted(final CoapTestEndpoint endpoint, TestTimeRule time) {
		NetworkConfig config = endpoint.getConfig();
		int exchangeLifetime = (int) config.getLong(NetworkConfig.Keys.EXCHANGE_LIFETIME);
		int sweepInterval = config.getInt(NetworkConfig.Keys.MARK_AND_SWEEP_INTERVAL);
		if (time != null) {
			time.setTestTimeShift(exchangeLifetime + 1000, TimeUnit.MILLISECONDS);
		}
		waitUntilDeduplicatorShouldBeEmpty(exchangeLifetime, sweepInterval, new TestCondition() {

			@Override
			public boolean isFulFilled() throws IllegalStateException {
				return endpoint.isEmpty() && endpoint.getRequestChecker().allRequestsTerminated();
			}
		});
		assertTrue("endpoint still contains states", isEmptyWithDump(endpoint));
		assertTrue(endpoint.getRequestChecker().getUnterminatedRequests() + " not terminated with an event",
				endpoint.getRequestChecker().allRequestsTerminated());
	}

	public static void waitUntilDeduplicatorShouldBeEmpty(final int exchangeLifetime, final int sweepInterval,
			TestCondition check) {
		try {
			int timeToWait = exchangeLifetime + sweepInterval + 300; // milliseconds
			System.out.println("Wait until deduplicator should be empty (" + timeToWait / 1000f + " seconds)");
			TestConditionTools.waitForCondition(timeToWait, timeToWait / 10, TimeUnit.MILLISECONDS, check);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	private static boolean isEmptyWithDump(CoapTestEndpoint endpoint) {
		boolean empty = endpoint.isEmpty();
		if (!empty) {
			endpoint.getExchangeStore().dump(5);
		}
		return empty;
	}

	private static boolean isEmptyWithDump(InMemoryMessageExchangeStore exchangeStore) {
		boolean empty = exchangeStore.isEmpty();
		if (!empty) {
			exchangeStore.dump(5);
		}
		return empty;
	}

	private static final CoapStackFactory COAP_STACK_TEST_FACTORY = new CoapStackFactory() {

		public CoapStack createCoapStack(String protocol, NetworkConfig config, Outbox outbox, Object customStackArgument) {
			if (CoAP.isTcpProtocol(protocol)) {
				throw new IllegalArgumentException("protocol \"" + protocol + "\" is not supported!");
			}
			return new CoapUdpTestStack(config, outbox);
		}
	};

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

		private final InMemoryMessageExchangeStore exchangeStore;
		private final InMemoryObservationStore observationStore;
		private final UDPTestConnector testConnector;
		private RequestEventChecker requestChecker;

		private CoapTestEndpoint(Connector connector, boolean applyConfiguration, NetworkConfig config,
				InMemoryObservationStore observationStore, InMemoryMessageExchangeStore exchangeStore,
				EndpointContextMatcher matcher) {
			super(connector, applyConfiguration, config, new RandomTokenGenerator(config), observationStore,
					exchangeStore, matcher, null, null, null, COAP_STACK_TEST_FACTORY, null);
			this.exchangeStore = exchangeStore;
			this.observationStore = observationStore;
			this.requestChecker = new RequestEventChecker();
			this.testConnector = connector instanceof UDPTestConnector ? (UDPTestConnector) connector : null;
		}

		public CoapTestEndpoint(UDPTestConnector connector, NetworkConfig config, boolean checkAddress) {
			this(connector, true, config, new InMemoryObservationStore(config),
					new InMemoryMessageExchangeStore(config), new UdpEndpointContextMatcher(checkAddress));
		}

		public CoapTestEndpoint(InetSocketAddress bind, NetworkConfig config, boolean checkAddress) {
			this(new UDPTestConnector(bind), true, config, new InMemoryObservationStore(config),
					new InMemoryMessageExchangeStore(config), new UdpEndpointContextMatcher(checkAddress));
		}

		public CoapTestEndpoint(InetSocketAddress bind, NetworkConfig config) {
			this(bind, config, true);
		}

		public CoapTestEndpoint(Connector connector, NetworkConfig config, EndpointContextMatcher matcher) {
			this(connector, false, config, new InMemoryObservationStore(config),
					new InMemoryMessageExchangeStore(config), matcher);
		}

		public InMemoryMessageExchangeStore getExchangeStore() {
			return exchangeStore;
		}

		public InMemoryObservationStore getObservationStore() {
			return observationStore;
		}

		public CoapUdpTestStack getStack() {
			return (CoapUdpTestStack) coapstack;
		}

		public boolean isEmpty() {
			return exchangeStore.isEmpty() && getStack().isEmpty();
		}

		@Override
		public void sendRequest(Request request) {
			requestChecker.registerRequest(request);
			super.sendRequest(request);
		}

		public RequestEventChecker getRequestChecker() {
			return requestChecker;
		}

		/**
		 * Set message to be dropped.
		 * 
		 * @param drops indexes of messages to be dropped.
		 * @throws IllegalStateException if the used {@link Connector} is no
		 *             {@link UDPTestConnector}.
		 */
		public void setDrops(int... drops) {
			if (testConnector == null) {
				throw new IllegalStateException("no test connector available!");
			}
			testConnector.setDrops(drops);
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

		public Collection<Request> getUnterminatedRequests() {
			return requests;
		}
	}

	public static class UDPTestConnector extends UDPConnector {

		private int counter;
		private int[] drops;

		public UDPTestConnector(InetSocketAddress address) {
			super(address);
		}

		@Override
		public void send(RawData msg) {
			synchronized (this) {
				if (drops != null && Arrays.binarySearch(drops, counter++) >= 0) {
					msg.onError(new IntendedTestException("Intended test error on send!"));
					return;
				}
			}
			super.send(msg);
		}

		/**
		 * Set message to be dropped.
		 * 
		 * @param drops indexes of messages to be dropped.
		 */
		public synchronized void setDrops(int... drops) {
			this.drops = drops;
			this.counter = 0;
		}
	}
}
