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
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.List;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * Unit test cases validating behavior of the {@link Request} class.
 *
 */
@Category(Small.class)
public class RequestTest {

	/**
	 * Verifies that a Request that is instantiated with a {@code null} CoAP.Code
	 * (used for a CoAP ping) has a code value of 0.
	 */
	@Test
	public void testGetRawCodeReturnsZeroForNullCode() {
		Request ping = new Request(null, Type.CON);
		assertThat(ping.getRawCode(), is(0));
	}

	/**
	 * Verifies that the URI examples from <a href="https://tools.ietf.org/html/rfc7252#section-6.3">
	 * RFC 7252, Section 6.3</a> result in the same option values.
	 * @throws URISyntaxException 
	 */
	@Test
	public void testSetOptionsCompliesWithRfcExample() throws URISyntaxException {

		String[] exampleUris = new String[]{
				"coap://example.com:5683/~sensors/temp.xml",
				"coap://EXAMPLE.com/%7Esensors/temp.xml",
				"coap://EXAMPLE.com:/%7esensors/temp.xml"
		};

		for (String uriString : exampleUris) {
			URI uri = new URI(uriString);
			Request req = Request.newGet();
			// explicitly set destination address so that we do not rely on working DNS
			req.setDestination(InetAddress.getLoopbackAddress());
			req.setOptions(uri);
			assertThat(req.getOptions().getUriHost(), is("example.com"));
			assertThat(req.getDestinationPort(), is(5683));
			assertThat(req.getOptions().getUriPort(), is(nullValue()));
			assertThat(req.getOptions().getUriPathString(), is("~sensors/temp.xml"));
		}
	}

	/**
	 * Verifies that non-ASCII characters in the URI components are
	 * not escaped when being put to Uri options.
	 */
	@Test
	public void testSetUriStringDoesNotEscapeNonUsAsciiChars() {
		String nonUsAsciiPath = "äöüß"; // german "Umlaute
		String nonUsAsciiQuery = "ä=öß";
		Request req = Request.newGet().setURI(String.format("coap://127.0.0.1/%s?%s", nonUsAsciiPath, nonUsAsciiQuery));

		List<String> path = req.getOptions().getUriPath();
		assertThat(path, is(notNullValue()));
		assertThat(path.get(0), is(nonUsAsciiPath));

		List<String> query = req.getOptions().getUriQuery();
		assertThat(query, is(notNullValue()));
		assertThat(query.get(0), is(nonUsAsciiQuery));
	}

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

		req = Request.newGet().setURI("coap+tcp://127.0.0.1");
		assertThat(req.getDestinationPort(), is(CoAP.DEFAULT_COAP_PORT));

		req = Request.newGet().setURI("coaps+tcp://127.0.0.1");
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
