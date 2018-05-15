/*******************************************************************************
 * Copyright (c) 2017, 2018 Bosch Software Innovations GmbH and others.
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

import org.junit.Before;
import org.junit.Test;

/**
 * Verifies behavior of the {@link StrictDtlsEndpointContextMatcher} and
 * {@link RelaxedDtlsEndpointContextMatcher}.
 *
 */
public class DtlsEndpointContextMatcherTest {

	private static final InetSocketAddress ADDRESS = new InetSocketAddress(0);

	private EndpointContext connectorContext;
	private EndpointContext scopedConnectorContext;
	private EndpointContext relaxedMessageContext;
	private EndpointContext scopedRelaxedMessageContext;
	private EndpointContext strictMessageContext;
	private EndpointContext scopedStrictMessageContext;
	private EndpointContext differentMessageContext;
	private EndpointContext scopedDifferentMessageContext;
	private EndpointContext unsecureMessageContext;
	private EndpointContextMatcher relaxedMatcher;
	private EndpointContextMatcher strictMatcher;

	@Before
	public void setup() {

		relaxedMatcher = new RelaxedDtlsEndpointContextMatcher();
		strictMatcher = new StrictDtlsEndpointContextMatcher();

		connectorContext = new DtlsEndpointContext(ADDRESS, null, "session", "1", "CIPHER");
		scopedConnectorContext = new DtlsEndpointContext(ADDRESS, "iot.eclipse.org", null, "session", "1", "CIPHER");

		relaxedMessageContext = new DtlsEndpointContext(ADDRESS, null, "session", "2", "CIPHER");
		scopedRelaxedMessageContext = new DtlsEndpointContext(ADDRESS, "iot.eclipse.org", null, "session", "2", "CIPHER");

		strictMessageContext = new DtlsEndpointContext(ADDRESS, null, "session", "1", "CIPHER");
		scopedStrictMessageContext = new DtlsEndpointContext(ADDRESS, "iot.eclipse.org", null, "session", "1", "CIPHER");

		differentMessageContext = new DtlsEndpointContext(ADDRESS, null,"new session", "1", "CIPHER");
		scopedDifferentMessageContext = new DtlsEndpointContext(ADDRESS, "iot.eclipse.org", null,"new session", "1", "CIPHER");

		unsecureMessageContext = new UdpEndpointContext(ADDRESS);
	}

	@Test
	public void testRelaxedWithConnectionEndpointContext() {

		assertThat(relaxedMatcher.isToBeSent(relaxedMessageContext, connectorContext), is(true));
		assertThat(relaxedMatcher.isToBeSent(scopedRelaxedMessageContext, connectorContext), is(false));
		assertThat(relaxedMatcher.isToBeSent(differentMessageContext, connectorContext), is(false));
		assertThat(relaxedMatcher.isToBeSent(scopedDifferentMessageContext, connectorContext), is(false));
		assertThat(relaxedMatcher.isToBeSent(unsecureMessageContext, connectorContext), is(false));
	}

	@Test
	public void testRelaxedWithScopedConnectionEndpointContext() {

		assertThat(relaxedMatcher.isToBeSent(relaxedMessageContext, scopedConnectorContext), is(false));
		assertThat(relaxedMatcher.isToBeSent(scopedRelaxedMessageContext, scopedConnectorContext), is(true));
		assertThat(relaxedMatcher.isToBeSent(strictMessageContext, scopedConnectorContext), is(false));
		assertThat(relaxedMatcher.isToBeSent(scopedStrictMessageContext, scopedConnectorContext), is(true));
		assertThat(relaxedMatcher.isToBeSent(differentMessageContext, scopedConnectorContext), is(false));
		assertThat(relaxedMatcher.isToBeSent(scopedDifferentMessageContext, scopedConnectorContext), is(false));
		assertThat(relaxedMatcher.isToBeSent(unsecureMessageContext, scopedConnectorContext), is(false));
	}

	@Test
	public void testStrictWithConnectionEndpointContext() {
		assertThat(strictMatcher.isToBeSent(strictMessageContext, connectorContext), is(true));
		assertThat(strictMatcher.isToBeSent(scopedStrictMessageContext, connectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(relaxedMessageContext, connectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(scopedRelaxedMessageContext, connectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(unsecureMessageContext, connectorContext), is(false));
	}

	@Test
	public void testStrictWithScopedConnectionEndpointContext() {

		assertThat(strictMatcher.isToBeSent(strictMessageContext, scopedConnectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(scopedStrictMessageContext, scopedConnectorContext), is(true));
		assertThat(strictMatcher.isToBeSent(relaxedMessageContext, scopedConnectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(scopedRelaxedMessageContext, scopedConnectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(differentMessageContext, scopedConnectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(scopedDifferentMessageContext, scopedConnectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(unsecureMessageContext, scopedConnectorContext), is(false));
	}

	@Test
	public void testRelaxedWithoutConnectionEndpointContext() {

		assertThat(relaxedMatcher.isToBeSent(relaxedMessageContext, null), is(false));
		assertThat(relaxedMatcher.isToBeSent(scopedRelaxedMessageContext, null), is(false));
		assertThat(relaxedMatcher.isToBeSent(differentMessageContext, null), is(false));
		assertThat(relaxedMatcher.isToBeSent(scopedDifferentMessageContext, null), is(false));
		assertThat(relaxedMatcher.isToBeSent(unsecureMessageContext, null), is(false));
	}

	@Test
	public void testStrictWithoutConnectionEndpointContext() {

		assertThat(strictMatcher.isToBeSent(strictMessageContext, null), is(false));
		assertThat(strictMatcher.isToBeSent(scopedStrictMessageContext, null), is(false));
		assertThat(strictMatcher.isToBeSent(relaxedMessageContext, null), is(false));
		assertThat(strictMatcher.isToBeSent(scopedRelaxedMessageContext, null), is(false));
		assertThat(strictMatcher.isToBeSent(unsecureMessageContext, null), is(false));
	}

}
