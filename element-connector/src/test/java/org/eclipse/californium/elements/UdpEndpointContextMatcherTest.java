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

import org.eclipse.californium.elements.util.Bytes;
import org.junit.Before;
import org.junit.Test;

public class UdpEndpointContextMatcherTest {

	private static final InetSocketAddress ADDRESS = new InetSocketAddress(5683);
	private static final InetSocketAddress CHANGED_ADDRESS = new InetSocketAddress(5684);
	private static final InetSocketAddress MULTICAST_ADDRESS = new InetSocketAddress("224.0.1.187", 5683);

	private EndpointContext connectorContext;
	private EndpointContext addressContext;
	private EndpointContext messageContext;
	private EndpointContext multicastContext;
	private EndpointContext changedAddressContext;
	private EndpointContext secureMessageContext;
	private EndpointContextMatcher matcher;

	@Before
	public void setup() {
		Bytes session = new Bytes("session".getBytes());
		connectorContext = new UdpEndpointContext(ADDRESS);
		addressContext = new AddressEndpointContext(ADDRESS);
		messageContext = new UdpEndpointContext(ADDRESS);
		multicastContext = new UdpEndpointContext(MULTICAST_ADDRESS);
		changedAddressContext = new UdpEndpointContext(CHANGED_ADDRESS);
		secureMessageContext = new DtlsEndpointContext(ADDRESS, null, null, session, 1, "CIPHER", 100);
		matcher = new UdpEndpointContextMatcher(true);
	}

	@Test
	public void testSending() {
		assertThat(matcher.isToBeSent(addressContext, connectorContext), is(true));
		assertThat(matcher.isToBeSent(messageContext, connectorContext), is(true));
		assertThat(matcher.isToBeSent(secureMessageContext, connectorContext), is(false));
		assertThat(matcher.isToBeSent(multicastContext, connectorContext), is(true));
	}

	@Test
	public void testResponse() {
		assertThat(matcher.isResponseRelatedToRequest(messageContext, messageContext), is(true));
		assertThat(matcher.isResponseRelatedToRequest(messageContext, secureMessageContext), is(false));
		assertThat(matcher.isResponseRelatedToRequest(secureMessageContext, messageContext), is(false));
		assertThat(matcher.isResponseRelatedToRequest(addressContext, messageContext), is(true));
		assertThat(matcher.isResponseRelatedToRequest(messageContext, addressContext), is(false));
		assertThat(matcher.isResponseRelatedToRequest(messageContext, changedAddressContext), is(false));
		assertThat(matcher.isResponseRelatedToRequest(changedAddressContext, messageContext), is(false));
		assertThat(matcher.isResponseRelatedToRequest(multicastContext, messageContext), is(true));
		assertThat(matcher.isResponseRelatedToRequest(multicastContext, changedAddressContext), is(true));
	}
}
