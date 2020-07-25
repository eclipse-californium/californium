/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - adapt to ServerHello changes
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.net.InetSocketAddress;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class ServerHelloTest {

	ServerHello serverHello;
	InetSocketAddress peerAddress;
	
	@Before
	public void setUp() throws Exception {
		peerAddress = new InetSocketAddress("localhost", 5684);
	}

	@Test
	public void testGetClientCertificateType() {
		givenAServerHelloWith(null, CertificateType.RAW_PUBLIC_KEY);
		assertThat(serverHello.getClientCertificateType(), is(CertificateType.RAW_PUBLIC_KEY));
	}

	@Test
	public void testGetServerCertificateType() {
		givenAServerHelloWith(CertificateType.RAW_PUBLIC_KEY, null);
		assertThat(serverHello.getServerCertificateType(), is(CertificateType.RAW_PUBLIC_KEY));
	}

	@Test
	public void testGetMessageLengthEqualsSerializedMessageLength() {
		givenAServerHelloWithEmptyExtensions();
		assertThat("ServerHello's anticipated message length does not match its real length",
				serverHello.getMessageLength(), is(serverHello.fragmentToByteArray().length));
		
		givenAServerHelloWith(CertificateType.RAW_PUBLIC_KEY, CertificateType.RAW_PUBLIC_KEY);
		assertThat("ServerHello's anticipated message length does not match its real length",
				serverHello.getMessageLength(), is(serverHello.fragmentToByteArray().length));
	}
	

	private void givenAServerHelloWith(CertificateType serverType, CertificateType clientType) {
		HelloExtensions ext = new HelloExtensions();
		if (serverType != null) {
			ext.addExtension(new ServerCertificateTypeExtension(serverType));
		}
		if (clientType != null) {
			ext.addExtension(new ClientCertificateTypeExtension(clientType));
		}
		serverHello = new ServerHello(ProtocolVersion.VERSION_DTLS_1_2, new Random(), new SessionId(),
				CipherSuite.TLS_PSK_WITH_AES_128_CCM_8, CompressionMethod.NULL, ext, peerAddress);
	}
	
	private void givenAServerHelloWithEmptyExtensions() {
		serverHello = new ServerHello(ProtocolVersion.VERSION_DTLS_1_2, new Random(), new SessionId(),
				CipherSuite.TLS_PSK_WITH_AES_128_CCM_8, CompressionMethod.NULL, new HelloExtensions(), peerAddress);
	}
}
