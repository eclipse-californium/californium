/*******************************************************************************
 * Copyright (c) 2017, 2018 Bosch Software Innovations GmbH and others.
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
import static org.eclipse.californium.elements.DtlsEndpointContext.*;

import java.net.InetSocketAddress;

import org.eclipse.californium.elements.MapBasedEndpointContext.Attributes;
import org.eclipse.californium.elements.rule.LoggingRule;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.ExpectedExceptionWrapper;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * Verifies behavior of the {@link StrictDtlsEndpointContextMatcher} and
 * {@link RelaxedDtlsEndpointContextMatcher}.
 *
 */
public class DtlsEndpointContextMatcherTest {

	private static final InetSocketAddress ADDRESS = new InetSocketAddress(0);
	private static final String SCOPE = "californium.eclipseprojects.io";

	@Rule
	public ExpectedException exception = ExpectedExceptionWrapper.none();

	@Rule 
	public LoggingRule logging = new LoggingRule();

	private EndpointContext connectorContext;
	private EndpointContext scopedConnectorContext;
	private EndpointContext relaxedMessageContext;
	private EndpointContext scopedRelaxedMessageContext;
	private EndpointContext strictMessageContext;
	private EndpointContext scopedStrictMessageContext;
	private EndpointContext noneCriticalMessageContext;
	private EndpointContext scopedNoneCriticalMessageContext;
	private EndpointContext strictNoneCriticalMessageContext;
	private EndpointContext scopedStrictNoneCriticalMessageContext;
	private EndpointContext differentMessageContext;
	private EndpointContext scopedDifferentMessageContext;
	private EndpointContext unsecureMessageContext;
	private EndpointContextMatcher relaxedMatcher;
	private EndpointContextMatcher strictMatcher;

	@Before
	public void setup() {
		Bytes session = new Bytes("session".getBytes());
		Bytes newSession = new Bytes("new-session".getBytes());

		relaxedMatcher = new RelaxedDtlsEndpointContextMatcher();
		strictMatcher = new StrictDtlsEndpointContextMatcher();

		connectorContext = new DtlsEndpointContext(ADDRESS, null, null, session, 1, "CIPHER", 100);
		scopedConnectorContext = new DtlsEndpointContext(ADDRESS, SCOPE, null, session, 1, "CIPHER", 100);

		relaxedMessageContext = new DtlsEndpointContext(ADDRESS, null, null, session, 2, "CIPHER", 200);
		scopedRelaxedMessageContext = new DtlsEndpointContext(ADDRESS, SCOPE, null, session, 2, "CIPHER", 200);

		strictMessageContext = new DtlsEndpointContext(ADDRESS, null, null, session, 1, "CIPHER", 100);
		scopedStrictMessageContext = new DtlsEndpointContext(ADDRESS, SCOPE, null, session, 1, "CIPHER", 100);

		differentMessageContext = new DtlsEndpointContext(ADDRESS, null, null, newSession, 1, "CIPHER", 100);
		scopedDifferentMessageContext = new DtlsEndpointContext(ADDRESS, SCOPE, null, newSession, 1, "CIPHER", 100);

		unsecureMessageContext = new UdpEndpointContext(ADDRESS);

		noneCriticalMessageContext = new MapBasedEndpointContext(ADDRESS, null,
				new Attributes().add(KEY_AUTO_HANDSHAKE_TIMEOUT, 30000));
		scopedNoneCriticalMessageContext = new MapBasedEndpointContext(ADDRESS, SCOPE, null,
				new Attributes().add(KEY_AUTO_HANDSHAKE_TIMEOUT, 30000));

		strictNoneCriticalMessageContext = new MapBasedEndpointContext(ADDRESS, null,
				new Attributes().add(KEY_SESSION_ID, session).add(KEY_EPOCH, 1).add(KEY_CIPHER, "CIPHER")
						.add(KEY_AUTO_HANDSHAKE_TIMEOUT, 30000));
		scopedStrictNoneCriticalMessageContext = new MapBasedEndpointContext(ADDRESS, SCOPE, null,
				new Attributes().add(KEY_SESSION_ID, session).add(KEY_EPOCH, 1).add(KEY_CIPHER, "CIPHER")
						.add(KEY_AUTO_HANDSHAKE_TIMEOUT, 30000));
	}

	@Test
	public void testRelaxedWithConnectionEndpointContext() {
		logging.setLoggingLevel("ERROR", EndpointContextUtil.class);

		assertThat(relaxedMatcher.isToBeSent(relaxedMessageContext, connectorContext), is(true));
		assertThat(relaxedMatcher.isToBeSent(scopedRelaxedMessageContext, connectorContext), is(false));
		assertThat(relaxedMatcher.isToBeSent(differentMessageContext, connectorContext), is(false));
		assertThat(relaxedMatcher.isToBeSent(scopedDifferentMessageContext, connectorContext), is(false));
		assertThat(relaxedMatcher.isToBeSent(unsecureMessageContext, connectorContext), is(false));
		assertThat(relaxedMatcher.isToBeSent(noneCriticalMessageContext, connectorContext), is(true));
		assertThat(relaxedMatcher.isToBeSent(scopedNoneCriticalMessageContext, connectorContext), is(false));
		assertThat(relaxedMatcher.isToBeSent(strictNoneCriticalMessageContext, connectorContext), is(true));
		assertThat(relaxedMatcher.isToBeSent(scopedStrictNoneCriticalMessageContext, connectorContext), is(false));
	}

	@Test
	public void testRelaxedWithScopedConnectionEndpointContext() {
		logging.setLoggingLevel("ERROR", EndpointContextUtil.class);

		assertThat(relaxedMatcher.isToBeSent(relaxedMessageContext, scopedConnectorContext), is(false));
		assertThat(relaxedMatcher.isToBeSent(scopedRelaxedMessageContext, scopedConnectorContext), is(true));
		assertThat(relaxedMatcher.isToBeSent(strictMessageContext, scopedConnectorContext), is(false));
		assertThat(relaxedMatcher.isToBeSent(scopedStrictMessageContext, scopedConnectorContext), is(true));
		assertThat(relaxedMatcher.isToBeSent(differentMessageContext, scopedConnectorContext), is(false));
		assertThat(relaxedMatcher.isToBeSent(scopedDifferentMessageContext, scopedConnectorContext), is(false));
		assertThat(relaxedMatcher.isToBeSent(unsecureMessageContext, scopedConnectorContext), is(false));
		assertThat(relaxedMatcher.isToBeSent(noneCriticalMessageContext, scopedConnectorContext), is(false));
		assertThat(relaxedMatcher.isToBeSent(scopedNoneCriticalMessageContext, scopedConnectorContext), is(true));
		assertThat(relaxedMatcher.isToBeSent(strictNoneCriticalMessageContext, scopedConnectorContext), is(false));
		assertThat(relaxedMatcher.isToBeSent(scopedStrictNoneCriticalMessageContext, scopedConnectorContext), is(true));
	}

	@Test
	public void testStrictWithConnectionEndpointContext() {
		logging.setLoggingLevel("ERROR", EndpointContextUtil.class);
		assertThat(strictMatcher.isToBeSent(strictMessageContext, connectorContext), is(true));
		assertThat(strictMatcher.isToBeSent(scopedStrictMessageContext, connectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(relaxedMessageContext, connectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(scopedRelaxedMessageContext, connectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(unsecureMessageContext, connectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(noneCriticalMessageContext, connectorContext), is(true));
		assertThat(strictMatcher.isToBeSent(scopedNoneCriticalMessageContext, connectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(strictNoneCriticalMessageContext, connectorContext), is(true));
		assertThat(strictMatcher.isToBeSent(scopedStrictNoneCriticalMessageContext, connectorContext), is(false));
	}

	@Test
	public void testStrictWithScopedConnectionEndpointContext() {
		logging.setLoggingLevel("ERROR", EndpointContextUtil.class);

		assertThat(strictMatcher.isToBeSent(strictMessageContext, scopedConnectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(scopedStrictMessageContext, scopedConnectorContext), is(true));
		assertThat(strictMatcher.isToBeSent(relaxedMessageContext, scopedConnectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(scopedRelaxedMessageContext, scopedConnectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(differentMessageContext, scopedConnectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(scopedDifferentMessageContext, scopedConnectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(unsecureMessageContext, scopedConnectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(noneCriticalMessageContext, scopedConnectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(scopedNoneCriticalMessageContext, scopedConnectorContext), is(true));
		assertThat(strictMatcher.isToBeSent(strictNoneCriticalMessageContext, scopedConnectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(scopedStrictNoneCriticalMessageContext, scopedConnectorContext), is(true));
	}

	@Test
	public void testRelaxedWithoutConnectionEndpointContext() {

		assertThat(relaxedMatcher.isToBeSent(relaxedMessageContext, null), is(false));
		assertThat(relaxedMatcher.isToBeSent(scopedRelaxedMessageContext, null), is(false));
		assertThat(relaxedMatcher.isToBeSent(differentMessageContext, null), is(false));
		assertThat(relaxedMatcher.isToBeSent(scopedDifferentMessageContext, null), is(false));
		assertThat(relaxedMatcher.isToBeSent(unsecureMessageContext, null), is(false));
		assertThat(relaxedMatcher.isToBeSent(noneCriticalMessageContext, null), is(true));
		assertThat(relaxedMatcher.isToBeSent(scopedNoneCriticalMessageContext, null), is(true));
		assertThat(relaxedMatcher.isToBeSent(strictNoneCriticalMessageContext, null), is(false));
		assertThat(relaxedMatcher.isToBeSent(scopedStrictNoneCriticalMessageContext, null), is(false));
	}

	@Test
	public void testStrictWithoutConnectionEndpointContext() {

		assertThat(strictMatcher.isToBeSent(strictMessageContext, null), is(false));
		assertThat(strictMatcher.isToBeSent(scopedStrictMessageContext, null), is(false));
		assertThat(strictMatcher.isToBeSent(relaxedMessageContext, null), is(false));
		assertThat(strictMatcher.isToBeSent(scopedRelaxedMessageContext, null), is(false));
		assertThat(strictMatcher.isToBeSent(unsecureMessageContext, null), is(false));
		assertThat(strictMatcher.isToBeSent(noneCriticalMessageContext, null), is(true));
		assertThat(strictMatcher.isToBeSent(scopedNoneCriticalMessageContext, null), is(true));
		assertThat(strictMatcher.isToBeSent(strictNoneCriticalMessageContext, null), is(false));
		assertThat(strictMatcher.isToBeSent(scopedStrictNoneCriticalMessageContext, null), is(false));
	}

	@Test
	public void testAddNewEntries() {
		EndpointContext context = MapBasedEndpointContext.addEntries(strictMessageContext,
				new Attributes().add(KEY_AUTO_HANDSHAKE_TIMEOUT, 30000));
		assertThat(context.getPeerAddress(), is(strictMessageContext.getPeerAddress()));
		assertThat(context.getVirtualHost(), is(strictMessageContext.getVirtualHost()));
		assertThat(context.getPeerIdentity(), is(strictMessageContext.getPeerIdentity()));
		assertThat(context.get(KEY_AUTO_HANDSHAKE_TIMEOUT).intValue(), is(30000));

		context = MapBasedEndpointContext.addEntries(scopedStrictMessageContext,
				new Attributes().add(KEY_AUTO_HANDSHAKE_TIMEOUT, 30000));
		assertThat(context.getPeerAddress(), is(scopedStrictMessageContext.getPeerAddress()));
		assertThat(context.getVirtualHost(), is(scopedStrictMessageContext.getVirtualHost()));
		assertThat(context.getPeerIdentity(), is(scopedStrictMessageContext.getPeerIdentity()));
		assertThat(context.get(KEY_AUTO_HANDSHAKE_TIMEOUT).intValue(), is(30000));
	}

	@Test
	public void testAddContainedEntries() {
		EndpointContext context = MapBasedEndpointContext.addEntries(noneCriticalMessageContext,
				new Attributes().add(KEY_AUTO_HANDSHAKE_TIMEOUT, 60000));
		assertThat(context.getPeerAddress(), is(noneCriticalMessageContext.getPeerAddress()));
		assertThat(context.getVirtualHost(), is(noneCriticalMessageContext.getVirtualHost()));
		assertThat(context.getPeerIdentity(), is(noneCriticalMessageContext.getPeerIdentity()));
		assertThat(context.get(KEY_AUTO_HANDSHAKE_TIMEOUT).intValue(), is(60000));
	}

	@Test
	public void testAddWithUnsupportedType() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("is not supported");
		Definition<Float> FAIL = new Definition<>("F", Float.class);
		Attributes attributes = new Attributes();
		attributes.add(FAIL, 1.0F);
	}
}
