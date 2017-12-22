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
 ******************************************************************************/
package org.eclipse.californium.elements;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.CountDownLatch;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class UDPConnectorTest {

	UDPConnector connector;
	TestEndpointContextMatcher matcher;

	@Before
	public void setup() throws IOException {
		matcher = new TestEndpointContextMatcher(1);
		connector = new UDPConnector(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
		connector.setEndpointContextMatcher(matcher);
		connector.start();
	}

	@After
	public void stop() {
		connector.destroy();
	}

	@Test
	public void testSendMessageWithEndpointContext() throws InterruptedException {
		byte[] data = { 0, 1, 2 };
		InetSocketAddress dest = new InetSocketAddress(0);
		EndpointContext context = new DtlsEndpointContext(dest, null, "session", "1", "CIPHER");
		
		RawData message = RawData.outbound(data, context, null, false);
		connector.setEndpointContextMatcher(matcher);
		connector.send(message);
		
		matcher.await();
		
		assertThat(matcher.getMessageEndpointContext(), is(sameInstance(context)));
	}

	private static class TestEndpointContextMatcher implements EndpointContextMatcher {

		private final CountDownLatch latchSendMatcher;
		private EndpointContext messageContext;

		public TestEndpointContextMatcher(int count) {
			this.latchSendMatcher = new CountDownLatch(count);
		}

		public synchronized EndpointContext getMessageEndpointContext() {
			return messageContext;
		}

		@Override
		public byte[] getEndpointIdentifier(EndpointContext endpointContext) {
			return null;
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
			return 0 < latchSendMatcher.getCount();
		}
		
		public void await() throws InterruptedException {
			latchSendMatcher.await();
		}

	};

}
