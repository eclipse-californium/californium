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
	 * based on the correlation context.
	 */
	@Test
	public void testIsSecure() {

		RawData rawData = RawData.inbound(new byte[]{0x01, 0x02}, SOURCE, null, getSecureCorrelationContext(), false);
		assertTrue(rawData.isSecure());

		rawData = RawData.inbound(new byte[]{0x01, 0x02}, SOURCE, null, getNonSecureCorrelationContext(), false);
		assertFalse(rawData.isSecure());

		rawData = RawData.inbound(new byte[]{0x01, 0x02}, SOURCE, null, null, false);
		assertFalse(rawData.isSecure());
	}

	private CorrelationContext getSecureCorrelationContext() {
		return new DtlsCorrelationContext("12345", "2", "PSK");
	}

	private CorrelationContext getNonSecureCorrelationContext() {
		MapBasedCorrelationContext ctx = new MapBasedCorrelationContext();
		ctx.put("someKey", "someValue");
		return ctx;
	}
}
