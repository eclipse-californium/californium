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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements;

import static org.junit.Assert.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.junit.Before;
import org.junit.Test;

public class RawDataTest {

	private static final InetSocketAddress SOURCE = new InetSocketAddress(InetAddress.getLoopbackAddress(), 10000);

	@Before
	public void setUp() throws Exception {
	}

	/**
	 * Verifies that isSecure() detects that the data has been received via a secure channel
	 * based on the endpoint context.
	 */
	@Test
	public void testIsSecure() {

		RawData rawData = RawData.inbound(new byte[]{0x01, 0x02}, SOURCE, null, getSecureEndpointContext(), false);
		assertTrue(rawData.isSecure());

		rawData = RawData.inbound(new byte[]{0x01, 0x02}, SOURCE, null, getNonSecureEndpointContext(), false);
		assertFalse(rawData.isSecure());

		rawData = RawData.inbound(new byte[]{0x01, 0x02}, SOURCE, null, null, false);
		assertFalse(rawData.isSecure());
	}

	private EndpointContext getSecureEndpointContext() {
		return new DtlsEndpointContext("12345", "2", "PSK");
	}

	private EndpointContext getNonSecureEndpointContext() {
		MapBasedEndpointContext ctx = new MapBasedEndpointContext();
		ctx.put("someKey", "someValue");
		return ctx;
	}
}
