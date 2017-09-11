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
import static org.eclipse.californium.elements.EndpointContextBuilder.createDtlsEndpointContext;
import static org.eclipse.californium.elements.EndpointContextBuilder.createMapBasedEndpointContext;

import java.util.Set;

import org.junit.Before;
import org.junit.Test;

public class EndpointContextUtilTest {

	private EndpointContext connectorContext;
	private EndpointContext relaxedMessageContext;
	private EndpointContext strictMessageContext;
	private EndpointContext differentMessageContext;
	private EndpointContext unsecureMessageContext;
	private EndpointContext unsecureMessageContext2;

	@Before
	public void setup() {
		connectorContext = createDtlsEndpointContext("session", "1", "CIPHER");
		relaxedMessageContext = createDtlsEndpointContext("session", "2", "CIPHER");
		strictMessageContext = createDtlsEndpointContext("session", "1", "CIPHER");
		differentMessageContext = createDtlsEndpointContext("new session", "1", "CIPHER");
		MapBasedEndpointContext mapBasedContext = createMapBasedEndpointContext();
		mapBasedContext.put("ID", "session");
		mapBasedContext.put("UNKNOWN", "secret");
		unsecureMessageContext = mapBasedContext;
		mapBasedContext = createMapBasedEndpointContext();
		mapBasedContext.put("ID", "session");
		mapBasedContext.put("UNKNOWN", "topsecret");
		unsecureMessageContext2 = mapBasedContext;
	}

	@Test
	public void testEndpointContextUtil() {
		Set<String> keys = KeySetEndpointContextMatcher.createKeySet(DtlsEndpointContext.KEY_SESSION_ID,
				DtlsEndpointContext.KEY_CIPHER);
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
		Set<String> keys = KeySetEndpointContextMatcher.createKeySet(DtlsEndpointContext.KEY_SESSION_ID,
				DtlsEndpointContext.KEY_CIPHER, "UNKNOWN");
		assertThat(EndpointContextUtil.match("test-1", keys, strictMessageContext, connectorContext), is(true));
		assertThat(EndpointContextUtil.match("test-2", keys, relaxedMessageContext, connectorContext), is(true));
		assertThat(EndpointContextUtil.match("test-3", keys, differentMessageContext, connectorContext), is(false));
		assertThat(EndpointContextUtil.match("test-4", keys, differentMessageContext, unsecureMessageContext),
				is(false));
		assertThat(EndpointContextUtil.match("test-5", keys, unsecureMessageContext, unsecureMessageContext2),
				is(false));
	}

}
