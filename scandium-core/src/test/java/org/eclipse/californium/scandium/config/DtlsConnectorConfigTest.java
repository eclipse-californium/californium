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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add support for anonymous client-only
 *                                                    configuration
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 483559
 *    Achim Kraus (Bosch Software Innovations GmbH) - Replace getLocalHost() by
 *                                                    getLoopbackAddress()
 ******************************************************************************/
package org.eclipse.californium.scandium.config;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class DtlsConnectorConfigTest {

	DtlsConnectorConfig.Builder builder;
	InetSocketAddress endpoint;

	@Before
	public void setUp() throws Exception {
		endpoint =  new InetSocketAddress(InetAddress.getLoopbackAddress(), 10000);
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
	public void testBuilderFailsWithDefaultConfiguration() {
		builder.build();
	}

	@Test
	public void testBuilderSetsPskCipherSuitesWhenPskStoreIsSet() {
		DtlsConnectorConfig config = builder.setPskStore(new StaticPskStore("ID", "KEY".getBytes())).build();
		assertTrue(config.getSupportedCipherSuites().length > 0);
		for (CipherSuite suite : config.getSupportedCipherSuites()) {
			assertThat(suite.getKeyExchange(), is(KeyExchangeAlgorithm.PSK));
		}
	}

	@Test
	public void testBuilderSetsEcdhCipherSuiteWhenKeysAreSet() throws Exception {
		DtlsConnectorConfig config = builder.setIdentity(
				DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey()).build();
		assertTrue(config.getSupportedCipherSuites().length > 0);
		for (CipherSuite suite : config.getSupportedCipherSuites()) {
			assertThat(suite.getKeyExchange(), is(KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN));
		}
	}

	@Test
	public void testBuilderSetsAllCipherSuitesWhenKeysAndPskStoreAreSet() throws Exception {
		DtlsConnectorConfig config = builder
				.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setPskStore(new StaticPskStore("ID", "KEY".getBytes()))
				.build();
		int ecDhSuitesCount = 0;
		int pskSuitesCount = 0;
		for (CipherSuite suite : config.getSupportedCipherSuites()) {
			if (KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN.equals(suite.getKeyExchange())) {
				ecDhSuitesCount++;
			} else if (KeyExchangeAlgorithm.PSK.equals(suite.getKeyExchange())) {
				pskSuitesCount++;
			}
		}
		assertTrue(ecDhSuitesCount > 0);
		assertTrue(pskSuitesCount > 0);
	}

	@Test(expected = IllegalStateException.class)
	public void testBuilderDetectsMissingIdentity() {
		builder.setSupportedCipherSuites(new CipherSuite[]{CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8}).build();
	}

	@Test(expected = IllegalStateException.class)
	public void testBuilderDetectsMissingPskStore() {
		builder.setSupportedCipherSuites(new CipherSuite[]{CipherSuite.TLS_PSK_WITH_AES_128_CCM_8}).build();
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
			fail("Should have rejected null as public key");
		} catch (NullPointerException e) {
			// all is well
		}
		try {
			builder.setIdentity(null, publicKey);
			fail("Should have rejected null as private key");
		} catch (NullPointerException e) {
			// all is well
		}
	}

	@Test
	public void testBuildAllowsForAnonymousClient() {
		builder.setClientOnly()
			.setSupportedCipherSuites(new CipherSuite[]{CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8})
			.build();
	}

	@Test(expected = IllegalStateException.class)
	public void testBuildAllowsForAnonymousClientUsingEcDsaCiphersOnly() {
		builder.setClientOnly()
			.setSupportedCipherSuites(new CipherSuite[]{CipherSuite.TLS_PSK_WITH_AES_128_CCM_8})
			.build();
	}

	@Test
	public void testGetCertificateChainReturnsNullForRpkOnlyConfiguration() throws Exception {
		// GIVEN a configuration supporting RawPublicKey only
		DtlsConnectorConfig config = builder
				.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.build();

		// WHEN retrieving the certificate chain
		Certificate[] chain = config.getCertificateChain();

		// THEN
		assertThat("Certificate chain should be null for RawPublicKey only configuration", chain, is(nullValue()));
	}
}
