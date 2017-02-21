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

import java.util.Set;

import org.junit.Before;
import org.junit.Test;

public class CorrelationContextUtilTest {

	private CorrelationContext connectorContext;
	private CorrelationContext relaxedMessageContext;
	private CorrelationContext strictMessageContext;
	private CorrelationContext differentMessageContext;
	private CorrelationContext unsecureMessageContext;
	private CorrelationContext unsecureMessageContext2;

	@Before
	public void setup() {
		connectorContext = new DtlsCorrelationContext("session", "1", "CIPHER");
		relaxedMessageContext = new DtlsCorrelationContext("session", "2", "CIPHER");
		strictMessageContext = new DtlsCorrelationContext("session", "1", "CIPHER");
		differentMessageContext = new DtlsCorrelationContext("new session", "1", "CIPHER");
		MapBasedCorrelationContext mapBasedContext = new MapBasedCorrelationContext();
		mapBasedContext.put("ID", "session");
		mapBasedContext.put("UNKNOWN", "secret");
		unsecureMessageContext = mapBasedContext;
		mapBasedContext = new MapBasedCorrelationContext();
		mapBasedContext.put("ID", "session");
		mapBasedContext.put("UNKNOWN", "topsecret");
		unsecureMessageContext2 = mapBasedContext;
	}

	@Test
	public void testCorrelationContextUtil() {
		Set<String> keys = KeySetCorrelationContextMatcher.createKeySet(DtlsCorrelationContext.KEY_SESSION_ID,
				DtlsCorrelationContext.KEY_CIPHER);
		assertThat(CorrelationContextUtil.match("test-1", keys, strictMessageContext, connectorContext), is(true));
		assertThat(CorrelationContextUtil.match("test-2", keys, relaxedMessageContext, connectorContext), is(true));
		assertThat(CorrelationContextUtil.match("test-3", keys, differentMessageContext, connectorContext), is(false));
		assertThat(CorrelationContextUtil.match("test-4", keys, differentMessageContext, unsecureMessageContext),
				is(false));
		assertThat(CorrelationContextUtil.match("test-5", keys, unsecureMessageContext, unsecureMessageContext2),
				is(true));
	}

	@Test
	public void testCorrelationContextUtilWithAdditionalKey() {
		Set<String> keys = KeySetCorrelationContextMatcher.createKeySet(DtlsCorrelationContext.KEY_SESSION_ID,
				DtlsCorrelationContext.KEY_CIPHER, "UNKNOWN");
		assertThat(CorrelationContextUtil.match("test-1", keys, strictMessageContext, connectorContext), is(true));
		assertThat(CorrelationContextUtil.match("test-2", keys, relaxedMessageContext, connectorContext), is(true));
		assertThat(CorrelationContextUtil.match("test-3", keys, differentMessageContext, connectorContext), is(false));
		assertThat(CorrelationContextUtil.match("test-4", keys, differentMessageContext, unsecureMessageContext),
				is(false));
		assertThat(CorrelationContextUtil.match("test-5", keys, unsecureMessageContext, unsecureMessageContext2),
				is(false));
	}

}
