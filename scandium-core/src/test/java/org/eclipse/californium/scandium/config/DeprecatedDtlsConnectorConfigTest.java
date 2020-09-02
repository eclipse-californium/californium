/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.config;

import static org.hamcrest.CoreMatchers.either;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm.HashAlgorithm;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm.SignatureAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.ExpectedException;

@Category(Small.class)
@SuppressWarnings("deprecation")
public class DeprecatedDtlsConnectorConfigTest {

	@Rule
	public ExpectedException exception = ExpectedException.none();

	DtlsConnectorConfig.Builder builder;
	InetSocketAddress endpoint;

	@Before
	public void setUp() throws Exception {
		endpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 10000);
		builder = new DtlsConnectorConfig.Builder().setAddress(endpoint);
	}

	@Test
	public void testBuilderSetsPskCipherSuitesWhenPskStoreIsSet() {
		DtlsConnectorConfig config = builder.setPskStore(new StaticPskStore("ID", "KEY".getBytes())).build();
		assertFalse(config.getSupportedCipherSuites().isEmpty());
		for (CipherSuite suite : config.getSupportedCipherSuites()) {
			assertThat(suite.getKeyExchange(),
					either(is(KeyExchangeAlgorithm.PSK)).or(is(KeyExchangeAlgorithm.ECDHE_PSK)));
		}
	}

	@Test
	public void testBuilderSetsAtLeastAllMandatoryCipherSuitesWhenKeysAndPskStoreAreSet() throws Exception {
		DtlsConnectorConfig config = builder.setClientAuthenticationRequired(false).setRecommendedCipherSuitesOnly(false)
				.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setPskStore(new StaticPskStore("ID", "KEY".getBytes())).build();
		List<CipherSuite> cipherSuites = config.getSupportedCipherSuites();
		assertThat(cipherSuites,
				hasItems(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256,
						CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256));
	}

	@Test
	public void testBuilderSetsNoNotRecommendedCipherSuitesWhenKeysAndPskStoreAreSet() throws Exception {
		DtlsConnectorConfig config = builder.setClientAuthenticationRequired(false)
				.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setPskStore(new StaticPskStore("ID", "KEY".getBytes())).build();
		List<CipherSuite> cipherSuites = config.getSupportedCipherSuites();
		for (CipherSuite cipherSuite :cipherSuites) {
			assertThat(cipherSuite.isRecommended(), is(true)); 
		}
	}

	@Test(expected = IllegalStateException.class)
	public void testBuilderDetectsNoCurveForCertificate() throws Exception {
		builder.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
				.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setSupportedGroups("secp384r1")
				.setRpkTrustAll().build();
	}

	@Test(expected = IllegalStateException.class)
	public void testBuilderDetectsMissingIdentity() {
		builder.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8).setRpkTrustAll().build();
	}
	@Test
	public void testBuildAllowsForAnonymousClientWithRpkTrust() {
		builder.setClientOnly().setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
				.setRpkTrustAll().build();
	}

	@Test
	public void testBuildAllowsForAnonymousClientWithTrustStore() {
		builder.setClientOnly().setTrustStore(new Certificate[0]).build();
	}

	@Test
	public void testSetNoSignatureAndHashAlgorithms() throws IOException, GeneralSecurityException {
		DtlsConnectorConfig config = builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setRpkTrustAll()
				.build();
		assertNotNull(config.getSupportedSignatureAlgorithms());
		assertThat(config.getSupportedSignatureAlgorithms(), is(SignatureAndHashAlgorithm.DEFAULT));
	}

	@Test
	public void testSetNoneSignatureAndHashAlgorithms() throws IOException, GeneralSecurityException {
		DtlsConnectorConfig config = builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setRpkTrustAll()
				.setSupportedSignatureAlgorithms((String[]) null)
				.build();
		assertNotNull(config.getSupportedSignatureAlgorithms());
		assertThat(config.getSupportedSignatureAlgorithms(), is(SignatureAndHashAlgorithm.DEFAULT));
	}

	@Test
	public void testSetNullSignatureAndHashAlgorithms() throws IOException, GeneralSecurityException {
		DtlsConnectorConfig config = builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setRpkTrustAll()
				.setSupportedSignatureAlgorithms(Collections.<SignatureAndHashAlgorithm>emptyList())
				.build();
		assertNotNull(config.getSupportedSignatureAlgorithms());
		assertThat(config.getSupportedSignatureAlgorithms(), is(SignatureAndHashAlgorithm.DEFAULT));
	}

	@Test
	public void testBuildForSignatureAndHashAlgorithmsRpk() throws IOException, GeneralSecurityException {
		builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setRpkTrustAll()
				.setSupportedSignatureAlgorithms(SignatureAndHashAlgorithm.SHA1_WITH_ECDSA)
				.build();
	}

	@Test
	public void testBuildSignatureAndHashAlgorithmsX509() throws IOException, GeneralSecurityException {
		builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getServerCertificateChain())
				.setTrustStore(new Certificate[0])
				.setSupportedSignatureAlgorithms(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
				.build();
	}

	@Test
	public void testBuildDetectsErrorForSignatureAndHashAlgorithmsRpk() throws IOException, GeneralSecurityException {
		SignatureAndHashAlgorithm algo = new SignatureAndHashAlgorithm(HashAlgorithm.SHA256, SignatureAlgorithm.DSA);
		exception.expect(IllegalStateException.class);
		exception.expectMessage("supported signature and hash algorithms doesn't match the public key!");
		builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setRpkTrustAll()
				.setSupportedSignatureAlgorithms(algo)
				.build();
	}

	@Test
	public void testBuildDetectsErrorForSignatureAndHashAlgorithmsX509() throws IOException, GeneralSecurityException {
		exception.expect(IllegalStateException.class);
		exception.expectMessage("supported signature and hash algorithms doesn't match the certificate chain!");
		builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getServerCertificateChain())
				.setTrustStore(new Certificate[0])
				.setSupportedSignatureAlgorithms(SignatureAndHashAlgorithm.SHA1_WITH_ECDSA)
				.build();
	}

	@Test
	public void testSupportedGroupForMixedCertificateChain() throws IOException, GeneralSecurityException {
		DtlsConnectorConfig config = builder
				.setIdentity(DtlsTestTools.getServerRsPrivateKey(), DtlsTestTools.getServerRsaCertificateChain())
				.setTrustStore(new Certificate[0])
				.build();
		assertNotNull(config.getSupportedGroups());
		assertFalse(config.getSupportedGroups().isEmpty());
	}

	@Test
	public void testGetCertificateChainReturnsNullForRpkOnlyConfiguration() throws Exception {
		// GIVEN a configuration supporting RawPublicKey only
		DtlsConnectorConfig config = builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setRpkTrustAll().build();

		// WHEN retrieving the certificate chain
		List<X509Certificate> chain = config.getCertificateChain();

		// THEN
		assertThat("Certificate chain should be null for RawPublicKey only configuration", chain, is(nullValue()));
	}

	@Test
	public void testWantedAuthentication() throws Exception {
		// GIVEN a configuration supporting RawPublicKey only and wanted client authentication
		builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setRpkTrustAll();
		builder.setClientAuthenticationWanted(true);
		// WHEN configuration is build
		DtlsConnectorConfig config = builder.build();

		// THEN
		assertThat(config.isClientAuthenticationWanted(), is(true));
		assertThat(config.isClientAuthenticationRequired(), is(false));
	}

	@Test(expected = IllegalStateException.class)
	public void testClientOnlyWantedAuthentication() throws Exception {
		// GIVEN a configuration supporting RawPublicKey only and wanted client authentication
		builder.setClientOnly();
		builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setRpkTrustAll();
		// WHEN client authentication is wanted
		builder.setClientAuthenticationWanted(true);
		// THEN fails
	}

	@Test(expected = IllegalStateException.class)
	public void testClientOnlyRequiredAuthentication() throws Exception {
		// GIVEN a configuration supporting RawPublicKey only and wanted client authentication
		builder.setClientOnly();
		builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setRpkTrustAll();
		// WHEN client authentication is required
		builder.setClientAuthenticationRequired(true);
		// THEN fails
	}

	@Test(expected = IllegalStateException.class)
	public void testServerOnlyWithDisabledRequiredAuthenticationFailsOnTrust() throws Exception {
		// GIVEN a configuration supporting RawPublicKey only and wanted client authentication
		builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setRpkTrustAll();
		builder.setServerOnly(true);
		builder.setClientAuthenticationRequired(false);
		// WHEN configuration is build
		builder.build();
		// THEN fails
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAntiReplayFilterAndWindowFilter() throws Exception {
		builder.setUseAntiReplayFilter(true);
		builder.setUseWindowFilter(true);
	}

	@Test
	public void testAntiReplayFilterDefault() throws Exception {
		builder.setPskStore(new StaticPskStore("ID", "KEY".getBytes()));
		
		builder.build();
		// WHEN configuration is build
		DtlsConnectorConfig config = builder.build();

		// THEN
		assertThat(config.useAntiReplayFilter(), is(true));
		assertThat(config.useWindowFilter(), is(false));
	}

	@Test
	public void testAntiReplayFilterDefaultWithWindowFilter() throws Exception {
		builder.setPskStore(new StaticPskStore("ID", "KEY".getBytes()));
		builder.setUseWindowFilter(true);
		builder.build();
		// WHEN configuration is build
		DtlsConnectorConfig config = builder.build();

		// THEN
		assertThat(config.useAntiReplayFilter(), is(false));
		assertThat(config.useWindowFilter(), is(true));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testTrustStoreDoNotContainDuplicateSubject() {
		X509Certificate[] trustedCertificates = new X509Certificate[2];
		trustedCertificates[0] = DtlsTestTools.getTrustedRootCA();
		trustedCertificates[1] = DtlsTestTools.getTrustedRootCA();
		builder.setTrustStore(trustedCertificates);
	}
}
