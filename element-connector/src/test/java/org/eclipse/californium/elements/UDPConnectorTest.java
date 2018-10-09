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
 *    Bosch Software Innovations - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add test for
 *                                                    CorrelationContextMatcher
 *    Achim Kraus (Bosch Software Innovations GmbH) - add tests for MessageCallback
 *                                                    add tests for start/stop
 *    Achim Kraus (Bosch Software Innovations GmbH) - use Logger and NetworkRule
 ******************************************************************************/
package org.eclipse.californium.elements;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.elements.rule.NetworkRule;
import org.eclipse.californium.elements.util.SimpleMessageCallback;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UDPConnectorTest {
	public static final Logger LOGGER = LoggerFactory.getLogger(UDPConnectorTest.class.getName());

	@ClassRule
	public static NetworkRule network = new NetworkRule(NetworkRule.Mode.DIRECT, NetworkRule.Mode.NATIVE);

	UDPConnector connector;
	UDPConnector destination;
	TestEndpointContextMatcher matcher;

	@Before
	public void setup() throws IOException {
		matcher = new TestEndpointContextMatcher(1, 1);
		connector = new UDPConnector(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
		connector.setEndpointContextMatcher(matcher);
		connector.start();
		destination = new UDPConnector(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
		destination.setRawDataReceiver(new RawDataChannel() {

			@Override
			public void receiveData(RawData raw) {
			}
		});
		destination.start();
	}

	@After
	public void stop() {
		connector.destroy();
		destination.destroy();
	}

	@Test
	public void testSendMessageWithEndpointContext() throws InterruptedException {
		byte[] data = { 0, 1, 2 };
		InetSocketAddress dest = destination.getAddress();
		EndpointContext context = new UdpEndpointContext(dest);

		RawData message = RawData.outbound(data, context, null, false);
		connector.send(message);

		matcher.await();

		assertThat(matcher.getMessageEndpointContext(), is(sameInstance(context)));
	}

	@Test
	public void testMessageCallbackOnContextEstablished() throws InterruptedException {
		byte[] data = { 0, 1, 2 };
		InetSocketAddress dest = destination.getAddress();
		EndpointContext context = new UdpEndpointContext(dest);

		SimpleMessageCallback callback = new SimpleMessageCallback(1, true);
		RawData message = RawData.outbound(data, context, callback, false);
		connector.send(message);

		callback.await(100);
		assertThat(callback.toString(), callback.getEndpointContext(), is(notNullValue()));
	}

	@Test
	public void testMessageCallbackOnSent() throws InterruptedException {
		byte[] data = { 0, 1, 2 };
		InetSocketAddress dest = destination.getAddress();
		EndpointContext context = new UdpEndpointContext(dest);

		SimpleMessageCallback callback = new SimpleMessageCallback(1, false);
		RawData message = RawData.outbound(data, context, callback, false);
		connector.send(message);

		callback.await(100);
		assertThat(callback.toString(), callback.isSent(), is(true));
	}

	@Test
	public void testMessageCallbackOnError() throws InterruptedException {
		byte[] data = { 0, 1, 2 };
		InetSocketAddress dest = destination.getAddress();
		EndpointContext context = new UdpEndpointContext(dest);

		matcher = new TestEndpointContextMatcher(1, 0);
		connector.setEndpointContextMatcher(matcher);

		SimpleMessageCallback callback = new SimpleMessageCallback(1, false);
		RawData message = RawData.outbound(data, context, callback, false);
		connector.send(message);

		callback.await(100);
		assertThat(callback.toString(), callback.getError(), is(notNullValue()));
	}

	@Test
	public void testStopCallsMessageCallbackOnError() throws InterruptedException {
		testStopCallsMessageCallbackOnError(100, 20);
	}

	@Test
	public void testStopCallsMessageCallbackOnErrorCirtical() throws InterruptedException {
		testStopCallsMessageCallbackOnError(1, 20);
	}

	private void testStopCallsMessageCallbackOnError(final int pending, final int loops) throws InterruptedException {
		byte[] data = { 0, 1, 2 };
		InetSocketAddress dest = destination.getAddress();
		EndpointContext context = new UdpEndpointContext(dest);

		for (int loop = 0; loop < loops; ++loop) {
			LOGGER.info("start/stop: {}/{} loops, {} msgs", loop, loops, pending);
			TestEndpointContextMatcher matcher = new TestEndpointContextMatcher(pending, pending);
			connector.setEndpointContextMatcher(matcher);

			SimpleMessageCallback callback = new SimpleMessageCallback(pending, false);
			for (int i = 0; i < pending; ++i) {
				RawData message = RawData.outbound(data, context, callback, false);
				connector.send(message);
			}
			connector.stop();
			assertThat(loop + ": " + callback.toString(), callback.await(100), is(true));
			try {
				connector.start();
				Thread.sleep(20);
			} catch (IOException e) {
			}
		}
	}

	private static class TestEndpointContextMatcher implements EndpointContextMatcher {

		private final CountDownLatch latchSendMatcher;
		private final AtomicInteger matches;
		private EndpointContext messageContext;

		public TestEndpointContextMatcher(int count, int matches) {
			this.latchSendMatcher = new CountDownLatch(count);
			this.matches = new AtomicInteger(matches);
		}

		public synchronized EndpointContext getMessageEndpointContext() {
			return messageContext;
		}

		@Override
		public String getName() {
			return "test-only";
		}

		@Override
		public boolean isResponseRelatedToRequest(EndpointContext requestContext, EndpointContext responseContext) {
			return false;
		}

		@Override
		public boolean isToBeSent(EndpointContext messageContext, EndpointContext connectorContext) {
			synchronized (this) {
				this.messageContext = messageContext;
			}
			latchSendMatcher.countDown();
			return 0 < matches.getAndDecrement();
		}

		public void await() throws InterruptedException {
			latchSendMatcher.await();
		}

	}
}
