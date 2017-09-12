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

public class DtlsEndpointContextMatcherTest {

	private EndpointContext connectorContext;
	private EndpointContext relaxedMessageContext;
	private EndpointContext strictMessageContext;
	private EndpointContext differentMessageContext;
	private EndpointContext unsecureMessageContext;
	private EndpointContextMatcher relaxedMatcher;
	private EndpointContextMatcher strictMatcher;

	@Before
	public void setup() {
		connectorContext = new DtlsEndpointContext("session", "1", "CIPHER");
		relaxedMessageContext = new DtlsEndpointContext("session", "2", "CIPHER");
		strictMessageContext = new DtlsEndpointContext("session", "1", "CIPHER");
		differentMessageContext = new DtlsEndpointContext("new session", "1", "CIPHER");
		MapBasedEndpointContext mapBasedContext = new MapBasedEndpointContext();
		mapBasedContext.put("ID", "session");
		unsecureMessageContext = mapBasedContext;
		relaxedMatcher = new RelaxedDtlsEndpointContextMatcher();
		strictMatcher = new StrictDtlsEndpointContextMatcher();
	}

	@Test
	public void testRelaxedWithConnectorEndpointContext() {
		assertThat(relaxedMatcher.isToBeSent(null, connectorContext), is(true));
		assertThat(relaxedMatcher.isToBeSent(relaxedMessageContext, connectorContext), is(true));
		assertThat(relaxedMatcher.isToBeSent(differentMessageContext, connectorContext), is(false));
		assertThat(relaxedMatcher.isToBeSent(unsecureMessageContext, connectorContext), is(false));
	}

	@Test
	public void testStrictWithConnectorEndpointContext() {
		assertThat(strictMatcher.isToBeSent(null, connectorContext), is(true));
		assertThat(strictMatcher.isToBeSent(strictMessageContext, connectorContext), is(true));
		assertThat(strictMatcher.isToBeSent(relaxedMessageContext, connectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(unsecureMessageContext, connectorContext), is(false));
	}

	@Test
	public void testRelaxedWithoutConnectorEndpointContext() {
		assertThat(relaxedMatcher.isToBeSent(null, null), is(true));
		assertThat(relaxedMatcher.isToBeSent(relaxedMessageContext, null), is(false));
		assertThat(relaxedMatcher.isToBeSent(differentMessageContext, null), is(false));
		assertThat(relaxedMatcher.isToBeSent(unsecureMessageContext, null), is(false));
	}

	@Test
	public void testStrictWithoutConnectorEndpointContext() {
		assertThat(strictMatcher.isToBeSent(null, null), is(true));
		assertThat(strictMatcher.isToBeSent(strictMessageContext, null), is(false));
		assertThat(strictMatcher.isToBeSent(relaxedMessageContext, null), is(false));
		assertThat(strictMatcher.isToBeSent(unsecureMessageContext, null), is(false));
	}

}
