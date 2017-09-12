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

import org.junit.Before;
import org.junit.Test;

public class TcpEndpointContextMatcherTest {

	private EndpointContext connectorContext;
	private EndpointContext messageContext;
	private EndpointContext differentMessageContext;
	private EndpointContextMatcher matcher;

	@Before
	public void setup() {
		connectorContext = new TcpEndpointContext("ID1");
		messageContext = new TcpEndpointContext("ID1");
		differentMessageContext = new TcpEndpointContext("ID2");
		matcher = new TcpEndpointContextMatcher();
	}

	@Test
	public void testWithConnectorEndpointContext() {
		assertThat(matcher.isToBeSent(null, connectorContext), is(true));
		assertThat(matcher.isToBeSent(messageContext, connectorContext), is(true));
		assertThat(matcher.isToBeSent(differentMessageContext, connectorContext), is(false));
	}

	@Test
	public void testWithoutConnectorEndpointContext() {
		assertThat(matcher.isToBeSent(null, null), is(true));
		assertThat(matcher.isToBeSent(messageContext, null), is(false));
		assertThat(matcher.isToBeSent(differentMessageContext, null), is(false));
	}

}
