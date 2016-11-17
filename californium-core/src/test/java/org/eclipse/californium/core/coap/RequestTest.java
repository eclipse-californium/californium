/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;
import static org.junit.Assume.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.UnknownHostException;

import org.eclipse.californium.category.Small;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * Unit test cases validating behavior of the {@link Request} class.
 *
 */
@Category(Small.class)
public class RequestTest {

	@Test(expected = IllegalArgumentException.class)
	public void testSetURIRejectsUnsupportedScheme() {
		Request.newGet().setURI("unknown://127.0.0.1");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testSetURIRejectsUnresolvableHost() {
		Request.newGet().setURI("coap://non-existing.host");
	}

	@Test
	public void testSetURIDoesNotSetUriHostOptionForIp4Address() {
		Request req = Request.newGet().setURI("coap://192.168.0.1");
		assertNull(req.getOptions().getUriHost());
	}

	@Test
	public void testSetURIDoesNotSetUriHostOptionForIp6Address() {
		// use www.google.com's IPv6 address
		Request req = Request.newGet().setURI("coap://[2a00:1450:4001:817::2003]");
		assertNull(req.getOptions().getUriHost());
	}

	@Test
	public void testSetURISetsDestination() {
		InetSocketAddress dest = InetSocketAddress.createUnresolved("192.168.0.1", 12000);
		Request req = Request.newGet().setURI("coap://192.168.0.1:12000");
		assertThat(req.getDestination().getHostAddress(), is(dest.getHostString()));
		assertThat(req.getDestinationPort(), is(dest.getPort()));
	}

	@Test
	public void testSetURISetsUriHostOptionToHostName() {

		assumeTrue(dnsIsWorking());
		Request req = Request.newGet().setURI("coaps://localhost");
		assertNotNull(req.getDestination());
		assertThat(req.getDestinationPort(), is(CoAP.DEFAULT_COAP_SECURE_PORT));
		assertThat(req.getOptions().getUriHost(), is("localhost"));
	}

	@Test
	public void testSetURISetsDestinationPortBasedOnUriScheme() {
		Request req = Request.newGet().setURI("coap://127.0.0.1");
		assertThat(req.getDestinationPort(), is(CoAP.DEFAULT_COAP_PORT));

		req = Request.newGet().setURI("coaps://127.0.0.1");
		assertThat(req.getDestinationPort(), is(CoAP.DEFAULT_COAP_SECURE_PORT));
	}

	@Test(expected = IllegalStateException.class)
	public void testSetOptionsFailsIfDestinationIsNotSet() {
		Request.newGet().setOptions(URI.create("coap://iot.eclipse.org"));
	}

	@Test
	public void testSetOptionsSetsUriHostOption() {

		Request req = Request.newGet();
		req.setDestination(InetAddress.getLoopbackAddress());
		req.setOptions(URI.create("coap://iot.eclipse.org"));
		assertThat(req.getDestinationPort(), is(CoAP.DEFAULT_COAP_PORT));
		assertThat(req.getOptions().getUriHost(), is("iot.eclipse.org"));
	}

	private static boolean dnsIsWorking() {
		try {
			InetAddress.getByName("localhost");
			return true;
		} catch (UnknownHostException e) {
			return false;
		}
	}
}
