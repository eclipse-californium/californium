/********************************************************************************
 * Copyright (c) 2025 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.elements;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.net.InetSocketAddress;
import java.security.Principal;

import org.eclipse.californium.elements.auth.ApplicationPrincipal;
import org.eclipse.californium.elements.util.Bytes;
import org.junit.Before;
import org.junit.Test;

public class PrincipalAndAnonymousEndpointContextMatcherTest {

	private static final InetSocketAddress ADDRESS = new InetSocketAddress(0);
	
	private Principal principal1;
	private Principal principal2;
	private Principal principal3;
	private Principal anonymous = ApplicationPrincipal.ANONYMOUS;
	private EndpointContext connectionContext;
	private EndpointContext messageContext;
	private EndpointContext differentMessageContext;
	private EndpointContext unsecureMessageContext;
	private EndpointContext anonymousMessageContext;
	private EndpointContext anonymousMessageContext2;
	private EndpointContext anonymousConnectionContext;
	private EndpointContextMatcher matcher;

	@Before
	public void setup() {
		Bytes session = new Bytes("session".getBytes());
		Bytes session2 = new Bytes("session2".getBytes());
		principal1 = new TestPrincipal("P1");
		principal2 = new TestPrincipal("P1"); // intended to have the same name as principal1
		principal3 = new TestPrincipal("P3");

		connectionContext = new DtlsEndpointContext(ADDRESS, null, principal1, session, 1, "CIPHER", 100);
		anonymousConnectionContext = new DtlsEndpointContext(ADDRESS, null, anonymous, session2, 1, "CIPHER", 100);
		messageContext = new AddressEndpointContext(ADDRESS, principal2);
		differentMessageContext = new AddressEndpointContext(ADDRESS, principal3);
		unsecureMessageContext = new AddressEndpointContext(ADDRESS, null);
		anonymousMessageContext = new DtlsEndpointContext(ADDRESS, null, anonymous, session2, 1, "CIPHER", 100);
		anonymousMessageContext2 = new DtlsEndpointContext(ADDRESS, null, null, session2, 1, "CIPHER", 100);
		matcher = new PrincipalAndAnonymousEndpointContextMatcher();
	}

	@Test
	public void testWithConnectionEndpointContext() {
		assertThat(matcher.isToBeSent(messageContext, connectionContext), is(true));
		assertThat(matcher.isToBeSent(differentMessageContext, connectionContext), is(false));
		assertThat(matcher.isToBeSent(unsecureMessageContext, connectionContext), is(true));
		assertThat(matcher.isToBeSent(anonymousMessageContext, connectionContext), is(false));
		assertThat(matcher.isToBeSent(anonymousMessageContext2, connectionContext), is(false));
	}

	@Test
	public void testWithAnonymousConnectionEndpointContext() {
		assertThat(matcher.isToBeSent(messageContext, anonymousConnectionContext), is(false));
		assertThat(matcher.isToBeSent(differentMessageContext, anonymousConnectionContext), is(false));
		assertThat(matcher.isToBeSent(unsecureMessageContext, anonymousConnectionContext), is(true));
		assertThat(matcher.isToBeSent(anonymousMessageContext, anonymousConnectionContext), is(true));
		assertThat(matcher.isToBeSent(anonymousMessageContext2, anonymousConnectionContext), is(true));
	}

	@Test
	public void testWithoutConnectionEndpointContext() {
		assertThat(matcher.isToBeSent(messageContext, null), is(true));
		assertThat(matcher.isToBeSent(differentMessageContext, null), is(true));
		assertThat(matcher.isToBeSent(unsecureMessageContext, null), is(true));
		assertThat(matcher.isToBeSent(anonymousMessageContext, null), is(true));
		assertThat(matcher.isToBeSent(anonymousMessageContext2, null), is(true));
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
