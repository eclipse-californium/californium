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

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import junit.framework.Assert;

import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
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

	@Test(expected = IllegalArgumentException.class)
	public void testSetSupportedCiphersRejectsEmptyArray() {
		builder.setSupportedCipherSuites(new CipherSuite[]{});
	}

	@Test(expected = IllegalStateException.class)
	public void testBuilderDetectsMissingPskStore() {
		builder.build();
	}
	
	@Test(expected = IllegalStateException.class)
	public void testBuilderDetectsMissingIdentity() {
		builder.setPskStore(new StaticPskStore("ID", "KEY".getBytes())).build();
	}
	
	@Test(expected = NullPointerException.class)
	public void testSetIdentityRequiresPrivateKey() {
		builder.setIdentity(null, new Certificate[0], false);
	}
	
	@Test
	public void testSetIdentityRequiresPrivateAndPublicKey() throws IOException, GeneralSecurityException {
		PrivateKey privateKey = DtlsTestTools.getPrivateKey();
		PublicKey publicKey = DtlsTestTools.getPublicKey();
		try {
			builder.setIdentity(privateKey, null);
			Assert.fail("Should have rejected null as public key");
		} catch (NullPointerException e) {
			// all is well
		}
		try {
			builder.setIdentity(null, publicKey);
			Assert.fail("Should have rejected null as private key");
		} catch (NullPointerException e) {
			// all is well
		}
	}
}
