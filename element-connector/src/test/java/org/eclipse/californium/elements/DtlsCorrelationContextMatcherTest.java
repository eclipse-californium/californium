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

public class DtlsCorrelationContextMatcherTest {

	private CorrelationContext connectorContext;
	private CorrelationContext relaxedMessageContext;
	private CorrelationContext strictMessageContext;
	private CorrelationContext differentMessageContext;
	private CorrelationContext unsecureMessageContext;
	private CorrelationContextMatcher relaxedMatcher;
	private CorrelationContextMatcher strictMatcher;

	@Before
	public void setup() {
		connectorContext = new DtlsCorrelationContext("session", "1", "CIPHER");
		relaxedMessageContext = new DtlsCorrelationContext("session", "2", "CIPHER");
		strictMessageContext = new DtlsCorrelationContext("session", "1", "CIPHER");
		differentMessageContext = new DtlsCorrelationContext("new session", "1", "CIPHER");
		MapBasedCorrelationContext mapBasedContext = new MapBasedCorrelationContext();
		mapBasedContext.put("ID", "session");
		unsecureMessageContext = mapBasedContext;
		relaxedMatcher = new RelaxedDtlsCorrelationContextMatcher();
		strictMatcher = new StrictDtlsCorrelationContextMatcher();
	}

	@Test
	public void testRelaxedWithConnectorCorrelationContext() {
		assertThat(relaxedMatcher.isToBeSent(null, connectorContext), is(true));
		assertThat(relaxedMatcher.isToBeSent(relaxedMessageContext, connectorContext), is(true));
		assertThat(relaxedMatcher.isToBeSent(differentMessageContext, connectorContext), is(false));
		assertThat(relaxedMatcher.isToBeSent(unsecureMessageContext, connectorContext), is(false));
	}

	@Test
	public void testStrictWithConnectorCorrelationContext() {
		assertThat(strictMatcher.isToBeSent(null, connectorContext), is(true));
		assertThat(strictMatcher.isToBeSent(strictMessageContext, connectorContext), is(true));
		assertThat(strictMatcher.isToBeSent(relaxedMessageContext, connectorContext), is(false));
		assertThat(strictMatcher.isToBeSent(unsecureMessageContext, connectorContext), is(false));
	}

	@Test
	public void testRelaxedWithoutConnectorCorrelationContext() {
		assertThat(relaxedMatcher.isToBeSent(null, null), is(true));
		assertThat(relaxedMatcher.isToBeSent(relaxedMessageContext, null), is(false));
		assertThat(relaxedMatcher.isToBeSent(differentMessageContext, null), is(false));
		assertThat(relaxedMatcher.isToBeSent(unsecureMessageContext, null), is(false));
	}

	@Test
	public void testStrictWithoutConnectorCorrelationContext() {
		assertThat(strictMatcher.isToBeSent(null, null), is(true));
		assertThat(strictMatcher.isToBeSent(strictMessageContext, null), is(false));
		assertThat(strictMatcher.isToBeSent(relaxedMessageContext, null), is(false));
		assertThat(strictMatcher.isToBeSent(unsecureMessageContext, null), is(false));
	}

}
