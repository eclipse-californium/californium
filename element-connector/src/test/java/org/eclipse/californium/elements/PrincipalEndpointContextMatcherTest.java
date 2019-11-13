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
import static org.junit.Assert.assertThat;

import java.net.InetSocketAddress;
import java.security.Principal;

import org.junit.Before;
import org.junit.Test;

public class PrincipalEndpointContextMatcherTest {

	private static final InetSocketAddress ADDRESS = new InetSocketAddress(0);
	
	private Principal principal1;
	private Principal principal2;
	private Principal principal3;
	private EndpointContext connectionContext;
	private EndpointContext messageContext;
	private EndpointContext differentMessageContext;
	private EndpointContext unsecureMessageContext;
	private EndpointContextMatcher matcher;

	@Before
	public void setup() {
		principal1 = new TestPrincipal("P1");
		principal2 = new TestPrincipal("P1"); // intended to have the same name as principal1
		principal3 = new TestPrincipal("P3");
		
		connectionContext = new DtlsEndpointContext(ADDRESS, principal1, "session", "1", "CIPHER", "100");
		messageContext = new AddressEndpointContext(ADDRESS, principal2);
		differentMessageContext = new AddressEndpointContext(ADDRESS, principal3);
		unsecureMessageContext = new AddressEndpointContext(ADDRESS, null);
		matcher = new PrincipalEndpointContextMatcher();
	}

	@Test
	public void testWithConnectionEndpointContext() {
		assertThat(matcher.isToBeSent(messageContext, connectionContext), is(true));
		assertThat(matcher.isToBeSent(differentMessageContext, connectionContext), is(false));
		assertThat(matcher.isToBeSent(unsecureMessageContext, connectionContext), is(true));
	}

	@Test
	public void testWithoutConnectionEndpointContext() {
		assertThat(matcher.isToBeSent(messageContext, null), is(true));
		assertThat(matcher.isToBeSent(differentMessageContext, null), is(true));
		assertThat(matcher.isToBeSent(unsecureMessageContext, null), is(true));
	}

	private static class TestPrincipal implements Principal {
		private final String name;
		public TestPrincipal(String name) {
			this.name = name;
		}
		@Override
		public String getName() {
			return name;
		}
		
		@Override
		public int hashCode() {
			return name.hashCode();
		}
		
		@Override
		public boolean equals(Object other) {
			if (this == other) {
				return true;
			} else if (other == null || !(other instanceof Principal)) {
				return false;
			}
			return name.equals(((Principal)other).getName());
		}
		
	}

}
