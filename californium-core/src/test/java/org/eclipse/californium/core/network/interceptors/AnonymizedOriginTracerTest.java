/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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

package org.eclipse.californium.core.network.interceptors;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * This test tests the AnonymizedOriginTracer.
 */
@Category(Medium.class)
public class AnonymizedOriginTracerTest {

	private static final long FILTER_TIMEOUT_IN_SECONDS = 2;

	private AnonymizedOriginTracer tracer;
	private byte[] rawAddress;
	private InetAddress address1;
	private InetAddress address2;
	private InetAddress address3;
	private InetAddress address1_2;
	private InetAddress address4;
	private InetAddress address5;

	@Before
	public void init() throws UnknownHostException {
		tracer = new AnonymizedOriginTracer("test", FILTER_TIMEOUT_IN_SECONDS);
		address1 = InetAddress.getByName("127.0.0.1");
		rawAddress = address1.getAddress();
		address2 = InetAddress.getByName("192.168.0.1");
		address3 = InetAddress.getByName("192.168.0.10");
		address1_2 = InetAddress.getByName("127.0.0.1");
		address4 = InetAddress.getByName("[fd00::f5cd:cdd:d48f:eeb0]");
		address5 = InetAddress.getByName("[fd00::f5cd:cdd:d48f:eec0]");
	}

	/**
	 * Validates, that the same address results in the same hash.
	 */
	@Test
	public void testAnonymizedAddressIdentity() {
		String hash1 = AnonymizedOriginTracer.getAnonymizedOrigin(address1);
		String hash2 = AnonymizedOriginTracer.getAnonymizedOrigin(address2);
		String hash3 = AnonymizedOriginTracer.getAnonymizedOrigin(address3);
		String hash4 = AnonymizedOriginTracer.getAnonymizedOrigin(address4);
		String hash5 = AnonymizedOriginTracer.getAnonymizedOrigin(address5);
		String hash1_2 = AnonymizedOriginTracer.getAnonymizedOrigin(address1_2);
		String hash2_2 = AnonymizedOriginTracer.getAnonymizedOrigin(address2);
		String hash3_2 = AnonymizedOriginTracer.getAnonymizedOrigin(address3);
		String hash4_2 = AnonymizedOriginTracer.getAnonymizedOrigin(address4);
		String hash5_2 = AnonymizedOriginTracer.getAnonymizedOrigin(address5);

		// anonymize twice results in same hash
		assertThat(hash1, is(hash1_2));
		assertThat(hash2, is(hash2_2));
		assertThat(hash3, is(hash3_2));
		assertThat(hash4, is(hash4_2));
		assertThat(hash5, is(hash5_2));
	}

	/**
	 * Validates, that the different address results mainly in different hashes.
	 * The test ensures, that more than 95 of 100 addresses results in a
	 * different hash.
	 */
	@Test
	public void testAnonymizedAddressDiffers() throws UnknownHostException {
		int differsCounter = 0;
		String hash1 = AnonymizedOriginTracer.getAnonymizedOrigin(address1);

		for (int tries = 0; tries < 100; ++tries) {
			++rawAddress[0];
			InetAddress differentAddress = InetAddress.getByAddress(rawAddress);
			String hash2 = AnonymizedOriginTracer.getAnonymizedOrigin(differentAddress);
			if (!hash1.equals(hash2)) {
				++differsCounter;
			}
		}
		// anonymized different addresses "mostly" results in different hash's
		assertThat(differsCounter, is(greaterThan(95)));
	}

	@Test
	public void testFilterLogging() throws InterruptedException {
		assertTrue(log(address1));
		assertTrue(log(address2));
		// logging again within timeout is suppressed.
		assertFalse(log(address1_2));
		assertTrue(log(address3));
		Thread.sleep(TimeUnit.SECONDS.toMillis(FILTER_TIMEOUT_IN_SECONDS) + 500);
		// logging again after timeout
		assertTrue(log(address1));
	}

	private boolean log(InetAddress address) {
		Request message = Request.newGet();
		AddressEndpointContext context = new AddressEndpointContext(address, 0);
		message.setSourceContext(context);
		return tracer.log(message);
	}
}
