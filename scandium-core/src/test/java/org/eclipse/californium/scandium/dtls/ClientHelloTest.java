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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - adapt to ClientHello changes 
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.Collections;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.CertificateTypeExtension.CertificateType;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class ClientHelloTest {

	ClientHello clientHello;
	InetSocketAddress peerAddress;
	
	@Before
	public void setUp() throws Exception {
		peerAddress = new InetSocketAddress("localhost", 5684);
	}

	@Test
	public void testGetMessageLengthEqualsSerializedMessageLength() {
		givenAClientHelloWithEmptyExtensions();
		assertThat("ServerHello's anticipated message length does not match its real length",
				clientHello.getMessageLength(), is(clientHello.fragmentToByteArray().length));
	}
	
	private void givenAClientHelloWithEmptyExtensions() {
		clientHello = new ClientHello(new ProtocolVersion(), new SecureRandom(), Collections.<CertificateType> emptyList(), Collections.<CertificateType> emptyList(), peerAddress);
	}
}
