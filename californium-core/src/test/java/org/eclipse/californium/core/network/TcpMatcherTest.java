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
import static org.eclipse.californium.core.network.MatcherTestUtils.responseFor;
import static org.eclipse.californium.core.network.MatcherTestUtils.sendRequest;
import static org.junit.Assert.assertSame;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.category.Small;
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
		TcpMatcher matcher = newTcpMatcher(false);
		Exchange exchange = sendRequest(dest, matcher, null);

		Exchange matched = matcher.receiveResponse(responseFor(exchange.getCurrentRequest()), null);
		assertSame(exchange, matched);
	}

}
