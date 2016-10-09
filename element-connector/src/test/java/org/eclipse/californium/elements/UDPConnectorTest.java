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
package org.eclipse.californium.elements;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;


public class UDPConnectorTest {

	UDPConnector connector;

	@Before
	public void setup() throws IOException {
		connector = new UDPConnector(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
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

}
