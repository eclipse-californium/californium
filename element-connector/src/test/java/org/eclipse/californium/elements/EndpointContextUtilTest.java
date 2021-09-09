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
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.net.InetSocketAddress;

import org.eclipse.californium.elements.MapBasedEndpointContext.Attributes;
import org.eclipse.californium.elements.rule.LoggingRule;
import org.eclipse.californium.elements.util.Bytes;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

public class EndpointContextUtilTest {

	private static final InetSocketAddress ADDRESS = new InetSocketAddress(0);
	public static final Definition<String> ID = new Definition<>("ID", String.class, MapBasedEndpointContext.ATTRIBUTE_DEFINITIONS);
	public static final Definition<String> UNKNOWN = new Definition<>("UNKNOWN", String.class, MapBasedEndpointContext.ATTRIBUTE_DEFINITIONS);

	@Rule 
	public LoggingRule logging = new LoggingRule();

	private EndpointContext connectorContext;
	private EndpointContext relaxedMessageContext;
	private EndpointContext strictMessageContext;
	private EndpointContext differentMessageContext;
	private EndpointContext unsecureMessageContext;
	private EndpointContext unsecureMessageContext2;

	@Before
	public void setup() {
		Bytes session = new Bytes("session".getBytes());
		Bytes newSession = new Bytes("new-session".getBytes());
		connectorContext = new DtlsEndpointContext(ADDRESS, null, null, session, 1, "CIPHER", 100);
		relaxedMessageContext = new DtlsEndpointContext(ADDRESS, null, null, session, 2, "CIPHER", 200);
		strictMessageContext = new DtlsEndpointContext(ADDRESS, null, null, session, 1, "CIPHER", 100);
		differentMessageContext = new DtlsEndpointContext(ADDRESS, null, null, newSession, 1, "CIPHER", 100);
		MapBasedEndpointContext mapBasedContext = new MapBasedEndpointContext(ADDRESS, null,
				new Attributes().add(ID, "session").add(UNKNOWN, "secret"));
		unsecureMessageContext = mapBasedContext;
		mapBasedContext = new MapBasedEndpointContext(ADDRESS, null,
				new Attributes().add(ID, "session").add(UNKNOWN, "topsecret"));
		unsecureMessageContext2 = mapBasedContext;
	}

	@Test
	public void testEndpointContextUtil() {
		logging.setLoggingLevel("ERROR", EndpointContextUtil.class);

		Definitions<Definition<?>> keys = new Definitions<>("test")
				.add(DtlsEndpointContext.KEY_SESSION_ID)
				.add(DtlsEndpointContext.KEY_CIPHER);
		assertThat(EndpointContextUtil.match("test-1", keys, strictMessageContext, connectorContext), is(true));
		assertThat(EndpointContextUtil.match("test-2", keys, relaxedMessageContext, connectorContext), is(true));
		assertThat(EndpointContextUtil.match("test-3", keys, differentMessageContext, connectorContext), is(false));
		assertThat(EndpointContextUtil.match("test-4", keys, differentMessageContext, unsecureMessageContext),
				is(false));
		assertThat(EndpointContextUtil.match("test-5", keys, unsecureMessageContext, unsecureMessageContext2),
				is(true));
	}

	@Test
	public void testEndpointContextUtilWithAdditionalKey() {
		logging.setLoggingLevel("ERROR", EndpointContextUtil.class);
		Definitions<Definition<?>> keys = new Definitions<>("test")
				.add(DtlsEndpointContext.KEY_SESSION_ID)
				.add(DtlsEndpointContext.KEY_CIPHER)
				.add(UNKNOWN);
		assertThat(EndpointContextUtil.match("test-1", keys, strictMessageContext, connectorContext), is(true));
		assertThat(EndpointContextUtil.match("test-2", keys, relaxedMessageContext, connectorContext), is(true));
		assertThat(EndpointContextUtil.match("test-3", keys, differentMessageContext, connectorContext), is(false));
		assertThat(EndpointContextUtil.match("test-4", keys, differentMessageContext, unsecureMessageContext),
				is(false));
		assertThat(EndpointContextUtil.match("test-5", keys, unsecureMessageContext, unsecureMessageContext2),
				is(false));
	}

	@Test
	public void testFollowUpEndpointContextStartHandshake() {
		EndpointContext messageContext = new AddressEndpointContext(ADDRESS);
		messageContext = MapBasedEndpointContext.addEntries(messageContext,
				new Attributes().add(DtlsEndpointContext.KEY_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_FORCE));
		EndpointContext connectionContext = new AddressEndpointContext(ADDRESS, "myserver", null);
		EndpointContext followUp = EndpointContextUtil.getFollowUpEndpointContext(messageContext, connectionContext);
		assertThat(followUp.get(DtlsEndpointContext.KEY_HANDSHAKE_MODE), is(nullValue()));
	}

	@Test
	public void testFollowUpEndpointContextNoneHandshake() {
		EndpointContext messageContext = new AddressEndpointContext(ADDRESS);
		messageContext = MapBasedEndpointContext.addEntries(messageContext, DtlsEndpointContext.ATTRIBUTE_HANDSHAKE_MODE_NONE);
		EndpointContext connectionContext = new AddressEndpointContext(ADDRESS, "myserver", null);
		EndpointContext followUp = EndpointContextUtil.getFollowUpEndpointContext(messageContext, connectionContext);
		assertThat(followUp.getString(DtlsEndpointContext.KEY_HANDSHAKE_MODE),
				is(DtlsEndpointContext.HANDSHAKE_MODE_NONE));
	}

}
