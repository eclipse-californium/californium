/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

import java.security.SecureRandom;

import org.junit.Before;
import org.junit.Test;

public class ClientHelloTest {

	ClientHello clientHello;
	
	@Before
	public void setUp() throws Exception {
	}

	@Test
	public void testGetMessageLengthEqualsSerializedMessageLength() {
		givenAClientHelloWithEmptyExtensions();
		assertThat("ServerHello's anticipated message length does not match its real length",
				clientHello.getMessageLength(), is(clientHello.fragmentToByteArray().length));
	}
	
	private void givenAClientHelloWithEmptyExtensions() {
		clientHello = new ClientHello(new ProtocolVersion(), new SecureRandom(), false);
	}
}
