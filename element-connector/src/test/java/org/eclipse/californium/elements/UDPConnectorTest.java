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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add test for
 *                                                    CorrelationContextMatcher
 ******************************************************************************/
package org.eclipse.californium.elements;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class UDPConnectorTest {

	UDPConnector connector;
	TestEndpointContextMatcher matcher;

	@Before
	public void setup() throws IOException {
		matcher = new TestEndpointContextMatcher(0, 1);
		connector = new UDPConnector(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
		connector.setEndpointContextMatcher(matcher);
		connector.start();
	}

	@After
	public void stop() {
		connector.destroy();
	}

	@Test
	public void testGetUriContainsCorrectSchemeAndAddress() {
		assertThat(connector.getUri().getScheme(), is("coap"));
		assertThat(connector.getUri().getHost(), is(connector.getAddress().getHostString()));
		assertThat(connector.getUri().getPort(), is(connector.getAddress().getPort()));
	}

	@Test
	public void testSendMessageWithEndpointContext() throws InterruptedException {
		byte[] data = { 0, 1, 2 };
		InetSocketAddress dest = new InetSocketAddress(0);
		EndpointContext context = new DtlsEndpointContext(dest, null, "session", "1", "CIPHER");
		
		RawData message = RawData.outbound(data, context, null, false);
		connector.setEndpointContextMatcher(matcher);
		connector.send(message);
		
		matcher.await(2000, TimeUnit.MILLISECONDS);
		
		assertThat(matcher.getMessageEndpointContext(0), is(sameInstance(context)));
	}
}
