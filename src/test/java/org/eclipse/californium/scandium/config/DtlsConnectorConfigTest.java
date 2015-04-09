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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - Initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.config;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.cert.Certificate;

import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.junit.Before;
import org.junit.Test;

public class DtlsConnectorConfigTest {

	DtlsConnectorConfig.Builder builder;
	InetSocketAddress endpoint;
	
	@Before
	public void setUp() throws Exception {
		endpoint =  new InetSocketAddress(InetAddress.getLocalHost(), 10000);
		builder = new DtlsConnectorConfig.Builder(endpoint);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testSetSupportedCiphersRejectsNullCipher() {
		builder.setSupportedCipherSuites(new CipherSuite[]{CipherSuite.TLS_NULL_WITH_NULL_NULL});
	}

	@Test(expected = IllegalStateException.class)
	public void testBuilderDetectsMissingCertificateChain() {
		builder.setSupportedCipherSuites(new CipherSuite[]{CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
		builder.build();
	}

	@Test(expected = IllegalStateException.class)
	public void testBuilderDetectsMissingPskStore() {
		builder.build();
	}
	
	@Test(expected = NullPointerException.class)
	public void testSetIdentityRequiresPrivateKey() {
		builder.setIdentity(null, new Certificate[0], false);
	}
	

}
