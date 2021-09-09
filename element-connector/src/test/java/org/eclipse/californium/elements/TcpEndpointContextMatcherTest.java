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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.net.InetSocketAddress;

import org.eclipse.californium.elements.rule.LoggingRule;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

public class TcpEndpointContextMatcherTest {

	private static final InetSocketAddress ADDRESS = new InetSocketAddress(0);

	@Rule 
	public LoggingRule logging = new LoggingRule();

	private EndpointContext connectorContext;
	private EndpointContext messageContext;
	private EndpointContext differentMessageContext;
	private EndpointContextMatcher matcher;

	@Before
	public void setup() {
		long time = System.currentTimeMillis();
		connectorContext = new TcpEndpointContext(ADDRESS, "ID1", time);
		messageContext = new TcpEndpointContext(ADDRESS, "ID1", time);
		differentMessageContext = new TcpEndpointContext(ADDRESS, "ID2", System.currentTimeMillis());
		matcher = new TcpEndpointContextMatcher();
	}

	@Test
	public void testWithConnectorEndpointContext() {
		logging.setLoggingLevel("ERROR", EndpointContextUtil.class);
		assertThat(matcher.isToBeSent(messageContext, connectorContext), is(true));
		assertThat(matcher.isToBeSent(differentMessageContext, connectorContext), is(false));
	}

	@Test
	public void testWithoutConnectorEndpointContext() {
		logging.setLoggingLevel("ERROR", EndpointContextUtil.class);
		assertThat(matcher.isToBeSent(messageContext, null), is(false));
		assertThat(matcher.isToBeSent(differentMessageContext, null), is(false));
	}

}
