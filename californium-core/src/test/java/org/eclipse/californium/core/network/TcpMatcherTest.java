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
 ******************************************************************************/
package org.eclipse.californium.core.network;

import static org.eclipse.californium.core.network.MatcherTestUtils.newTcpMatcher;
import static org.eclipse.californium.core.network.MatcherTestUtils.receiveResponseFor;
import static org.eclipse.californium.core.network.MatcherTestUtils.sendRequest;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertEquals;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.elements.TestEndpointContextMatcher;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Verifies behavior of {@link TcpMatcher}.
 *
 */
@Category(Small.class)
public class TcpMatcherTest {

	private static final InetSocketAddress dest = new InetSocketAddress(InetAddress.getLoopbackAddress(), 5684);

	@Test
	public void testRequestMatchesResponse() {
		TestEndpointContextMatcher correlationMatcher = new TestEndpointContextMatcher(1, 0);
		TcpMatcher matcher = newTcpMatcher(correlationMatcher);
		Exchange exchange = sendRequest(dest, matcher, null);

		Exchange matched = matcher.receiveResponse(receiveResponseFor(exchange.getCurrentRequest()));
		assertSame(exchange, matched);
		assertEquals(1,  correlationMatcher.callsIsResponseRelatedToRequest.get());
	}

	@Test
	public void testRequestDoesntMatchesResponse() {
		TestEndpointContextMatcher correlationMatcher = new TestEndpointContextMatcher(0, 0);
		TcpMatcher matcher = newTcpMatcher(correlationMatcher);
		Exchange exchange = sendRequest(dest, matcher, null);

		Exchange matched = matcher.receiveResponse(receiveResponseFor(exchange.getCurrentRequest()));
		assertNull(matched);
		assertEquals(1,  correlationMatcher.callsIsResponseRelatedToRequest.get());
	}

}
