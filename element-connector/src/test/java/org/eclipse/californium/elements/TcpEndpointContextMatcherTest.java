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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.net.InetSocketAddress;

import static org.eclipse.californium.elements.EndpointContextBuilder.createTcpEndpointContext;

import org.junit.Before;
import org.junit.Test;

public class TcpEndpointContextMatcherTest {

	private EndpointContext addressContext;
	private EndpointContext connectorContext;
	private EndpointContext messageContext;
	private EndpointContext differentMessageContext;
	private EndpointContextMatcher matcher;

	@Before
	public void setup() {
		addressContext = new AddressEndpointContext(new InetSocketAddress(0));
		connectorContext = createTcpEndpointContext("ID1");
		messageContext = createTcpEndpointContext("ID1");
		differentMessageContext = createTcpEndpointContext("ID2");
		matcher = new TcpEndpointContextMatcher();
	}

	@Test
	public void testWithConnectionEndpointContext() {
		assertThat(matcher.isToBeSent(addressContext, connectorContext), is(true));
		assertThat(matcher.isToBeSent(messageContext, connectorContext), is(true));
		assertThat(matcher.isToBeSent(differentMessageContext, connectorContext), is(false));
	}

	@Test
	public void testWithoutConnectionEndpointContext() {
		assertThat(matcher.isToBeSent(addressContext, null), is(true));
		assertThat(matcher.isToBeSent(messageContext, null), is(false));
		assertThat(matcher.isToBeSent(differentMessageContext, null), is(false));
	}

}
