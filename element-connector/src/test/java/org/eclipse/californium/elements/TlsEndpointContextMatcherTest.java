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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.net.InetSocketAddress;

import org.junit.Before;
import org.junit.Test;

public class TlsEndpointContextMatcherTest {

	private static final InetSocketAddress ADDRESS = new InetSocketAddress(0);

	private EndpointContext connectorContext;
	private EndpointContext messageContext;
	private EndpointContext differentMessageContext;
	private EndpointContextMatcher matcher;

	@Before
	public void setup() {
		long time = System.currentTimeMillis();
		connectorContext = new TlsEndpointContext(ADDRESS, null, "ID1", "S1", "C1", time);
		messageContext = new TlsEndpointContext(ADDRESS, null, "ID1", "S1", "C1", time);
		differentMessageContext = new TlsEndpointContext(ADDRESS, null, "ID2", "S2", "C1", System.currentTimeMillis());
		matcher = new TlsEndpointContextMatcher();
	}

	@Test
	public void testWithConnectorEndpointContext() {
		assertThat(matcher.isToBeSent(messageContext, connectorContext), is(true));
		assertThat(matcher.isToBeSent(differentMessageContext, connectorContext), is(false));
	}

	@Test
	public void testWithoutConnectorEndpointContext() {
		assertThat(matcher.isToBeSent(messageContext, null), is(false));
		assertThat(matcher.isToBeSent(differentMessageContext, null), is(false));
	}

}
