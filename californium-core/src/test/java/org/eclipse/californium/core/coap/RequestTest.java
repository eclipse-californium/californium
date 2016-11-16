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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;

import java.net.InetAddress;
import java.net.InetSocketAddress;
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
		Request.newGet().setURI("unknown://localhost");
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
	public void testSetURISetsDestination() throws UnknownHostException {
		InetSocketAddress dest = InetSocketAddress.createUnresolved("192.168.0.1", 12000);
		Request req = Request.newGet().setURI("coap://192.168.0.1:12000");
		assertThat(req.getDestination().getHostAddress(), is(dest.getHostString()));
		assertThat(req.getDestinationPort(), is(dest.getPort()));
	}

	@Test
	public void testSetURISetsUriHostOption() throws UnknownHostException {
		String host = "iot.eclipse.org";
		
		try {
			/* check, id DNS is working */
			InetAddress.getByName(host);
			/* DNS OK! */
		}
		catch(UnknownHostException ex) {
			/* DNS failed, so use own host name */
			host = InetAddress.getLocalHost().getHostName();
		}

		Request req = Request.newGet().setURI("coap://" + host);
		assertThat(req.getOptions().getUriHost(), is(host));

	}

	@Test
	public void testSetURISetsDestinationPortBasedOnUriScheme() throws UnknownHostException {
		Request req = Request.newGet().setURI("coap://127.0.0.1");
		assertThat(req.getDestinationPort(), is(CoAP.DEFAULT_COAP_PORT));

		req = Request.newGet().setURI("coaps://127.0.0.1");
		assertThat(req.getDestinationPort(), is(CoAP.DEFAULT_COAP_SECURE_PORT));

		req = Request.newGet().setURI("coap+tcp://127.0.0.1");
		assertThat(req.getDestinationPort(), is(CoAP.DEFAULT_COAP_PORT));

		req = Request.newGet().setURI("coaps+tcp://127.0.0.1");
		assertThat(req.getDestinationPort(), is(CoAP.DEFAULT_COAP_SECURE_PORT));
	}

}
