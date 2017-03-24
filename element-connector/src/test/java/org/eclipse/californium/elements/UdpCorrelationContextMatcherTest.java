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
 ******************************************************************************/
package org.eclipse.californium.elements;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

import java.net.InetAddress;

import org.junit.Before;
import org.junit.Test;


/**
 * Verifies behavior of {@link UdpCorrelationContext}.
 *
 */
public class UdpCorrelationContextMatcherTest {

	private UdpCorrelationContext messageContext;
	private UdpCorrelationContext connectorContext;
	private UdpCorrelationContext differentMessageContext;
	private UdpCorrelationContextMatcher matcher;

	@Before
	public void setup() {
		connectorContext = new UdpCorrelationContext(InetAddress.getLoopbackAddress(), 10000);
		messageContext = new UdpCorrelationContext(InetAddress.getLoopbackAddress(), 10000);
		differentMessageContext = new UdpCorrelationContext(InetAddress.getLoopbackAddress(), 12000);
		matcher = new UdpCorrelationContextMatcher();
	}

	@Test
	public void testWithConnectorCorrelationContext() {
		assertTrue(matcher.isToBeSent(null, connectorContext));
		assertTrue(matcher.isToBeSent(messageContext, connectorContext));
		assertFalse(matcher.isToBeSent(differentMessageContext, connectorContext));
	}

	@Test
	public void testWithoutConnectorCorrelationContext() {
		assertTrue(matcher.isToBeSent(null, null));
		assertFalse(matcher.isToBeSent(messageContext, null));
		assertFalse(matcher.isToBeSent(differentMessageContext, null));
	}
}
