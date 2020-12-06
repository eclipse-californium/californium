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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - Initial creation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add support for anonymous client-only
 *                                                    configuration
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 483559
 *    Achim Kraus (Bosch Software Innovations GmbH) - Replace getLocalHost() by
 *                                                    getLoopbackAddress()
 *    Vikram (University of Rostock) - add test to check ECDHE_PSK CipherSuite 
 ******************************************************************************/
package org.eclipse.californium.scandium.config;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.either;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.ExpectedExceptionWrapper;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm.HashAlgorithm;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm.SignatureAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedSinglePskStore;
import org.eclipse.californium.scandium.dtls.x509.NewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.StaticNewAdvancedCertificateVerifier;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.ExpectedException;

@Category(Small.class)
public class DtlsConnectorConfigTest {

	@Rule
	public ExpectedException exception = ExpectedExceptionWrapper.none();

	DtlsConnectorConfig.Builder builder;
	InetSocketAddress endpoint;

	@Before
	public void setUp() throws Exception {
		endpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 10000);
		builder = DtlsConnectorConfig.builder().setAddress(endpoint);
	}

	@Test
	public void testSetSupportedCiphersRejectsNullCipher() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage(containsString("NULL Cipher Suite is not supported"));
		builder.setSupportedCipherSuites(CipherSuite.TLS_NULL_WITH_NULL_NULL);
	}

	@Test
	public void testSetSupportedCiphersRejectsEmptyArray() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage(containsString("must support at least one cipher suite"));
		builder.setSupportedCipherSuites(new CipherSuite[] {});
	}

	@Test
	public void testSetSupportedCiphersRejectsNull() {
		exception.expect(NullPointerException.class);
		exception.expectMessage(containsString("must support at least one cipher suite"));
		builder.setSupportedCipherSuites((CipherSuite[]) null);
	}

	@Test
	public void testSetSupportedCiphersListRejectsNullCipher() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage(containsString("NULL Cipher Suite is not supported"));
		builder.setSupportedCipherSuites(Arrays.asList(CipherSuite.TLS_NULL_WITH_NULL_NULL));
	}

	@Test
	public void testSetSupportedCiphersListRejectsEmptyArray() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage(containsString("must support at least one cipher suite"));
		builder.setSupportedCipherSuites(new ArrayList<CipherSuite>(0));
	}

	@Test
	public void testSetSupportedCiphersListRejectsNull() {
		exception.expect(NullPointerException.class);
		exception.expectMessage(containsString("must support at least one cipher suite"));
		builder.setSupportedCipherSuites((List<CipherSuite>) null);
	}

	@Test
	public void testBuilderFailsWithDefaultConfiguration() {
		exception.expect(IllegalStateException.class);
		exception.expectMessage("Supported cipher suites must be set either explicitly or implicitly by means of setting the identity or PSK store");
		builder.build();
	}

	@Test
	public void testBuilderSetsPskCipherSuitesWhenPskStoreIsSet() {
		DtlsConnectorConfig config = builder.setAdvancedPskStore(new AdvancedSinglePskStore("ID", "KEY".getBytes())).build();
		assertFalse(config.getSupportedCipherSuites().isEmpty());
		for (CipherSuite suite : config.getSupportedCipherSuites()) {
			assertThat(suite.getKeyExchange(),
					either(is(KeyExchangeAlgorithm.PSK)).or(is(KeyExchangeAlgorithm.ECDHE_PSK)));
		}
	}

	@Test
	public void testBuilderSetsEcdheCipherSuiteWhenKeysAreSet() throws Exception {
		DtlsConnectorConfig config = builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setClientAuthenticationRequired(false).build();
		assertFalse(config.getSupportedCipherSuites().isEmpty());
		for (CipherSuite suite : config.getSupportedCipherSuites()) {
			assertThat(suite.getKeyExchange(), is(KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN));
		}
	}

	@Test
	public void testBuilderSetsAtLeastAllMandatoryCipherSuitesWhenKeysAndPskStoreAreSet() throws Exception {
		DtlsConnectorConfig config = builder.setClientAuthenticationRequired(false).setRecommendedCipherSuitesOnly(false)
				.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setAdvancedPskStore(new AdvancedSinglePskStore("ID", "KEY".getBytes())).build();
		List<CipherSuite> cipherSuites = config.getSupportedCipherSuites();
		assertThat(cipherSuites,
				hasItems(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256,
						CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256));
	}

	@Test
	public void testBuilderSetsPreselectedCipherSuitesWhenKeysAndPskStoreAreSet() throws Exception {
		DtlsConnectorConfig config = builder.setClientAuthenticationRequired(false)
				.setRecommendedCipherSuitesOnly(false)
				.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setAdvancedPskStore(new AdvancedSinglePskStore("ID", "KEY".getBytes()))
				.setPreselectedCipherSuites(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256)
				.build();
		List<CipherSuite> cipherSuites = config.getSupportedCipherSuites();
		assertThat(cipherSuites,
				hasItems(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256));
		assertThat(cipherSuites, not(hasItems(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256)));
		assertThat(cipherSuites, not(hasItems(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)));
	}

	@Test
	public void testBuilderSetsNoNotRecommendedCipherSuitesWhenKeysAndPskStoreAreSet() throws Exception {
		DtlsConnectorConfig config = builder.setClientAuthenticationRequired(false)
				.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setAdvancedPskStore(new AdvancedSinglePskStore("ID", "KEY".getBytes())).build();
		List<CipherSuite> cipherSuites = config.getSupportedCipherSuites();
		for (CipherSuite cipherSuite :cipherSuites) {
			assertThat(cipherSuite.isRecommended(), is(true)); 
		}
	}

	@Test
	public void testBuilderDetectsNotRecommendedCiperSuite() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage(containsString("Not recommended cipher suites"));
		builder.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
	}

	@Test
	public void testBuilderDetectsNoCurveForCertificate() throws Exception {
		exception.expect(IllegalStateException.class);
		exception.expectMessage(containsString("public key used with not configured group (curve)"));
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build();
		builder.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
				.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setSupportedGroups("secp384r1")
				.setAdvancedCertificateVerifier(verifier)
				.build();
	}

	@Test
	public void testBuilderDetectsMissingIdentity() {
		exception.expect(IllegalStateException.class);
		exception.expectMessage(containsString("Identity must be set"));
		builder.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8).build();
	}

	@Test
	public void testBuilderDetectsMissingTrust() throws Exception {
		exception.expect(IllegalStateException.class);
		exception.expectMessage(containsString("trust must be set"));
		builder.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
				.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey()).build();
	}

	@Test
	public void testBuilderDetectsMissingPskStore() {
		exception.expect(IllegalStateException.class);
		exception.expectMessage(containsString("PSK store must be set"));
		builder.setSupportedCipherSuites(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8).build();
	}

	@Test
	public void testSetIdentityRequiresPrivateKey() {
		exception.expect(NullPointerException.class);
		exception.expectMessage("The private key must not be null!");
		builder.setIdentity(null, new Certificate[0], CertificateType.X_509);
	}

	@Test
	public void testSetIdentityRequiresCertChain() throws Exception {
		exception.expect(NullPointerException.class);
		exception.expectMessage("The certificate chain must not be null!");
		builder.setIdentity(DtlsTestTools.getPrivateKey(), null, CertificateType.X_509);
	}

	public void testSetIdentityWithoutCertificateTypeArray() throws Exception {
		builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getServerCertificateChain())
				.setClientAuthenticationRequired(false).build();
	}

	public void testSetIdentityWithNullCertificateTypeArray() throws Exception {
		builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getServerCertificateChain(),
				(CertificateType[]) null).setClientAuthenticationRequired(false).build();
	}

	public void testSetIdentityWithoutCertificateTypeList() throws Exception {
		builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getServerCertificateChain(),
				(List<CertificateType>) null).setClientAuthenticationRequired(false).build();
	}

	@Test
	public void testSetIdentityRequiresNoneEmptyCertificateTypeList() throws Exception {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("The certificate types must not be empty!");
		builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getServerCertificateChain(),
				new ArrayList<CertificateType>(0));
	}

	@Test
	public void testSetIdentityRequiresNoneEmptyCertChain() throws Exception {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("The certificate chain must not be empty!");
		builder.setIdentity(DtlsTestTools.getPrivateKey(), new Certificate[0], CertificateType.X_509);
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
	public void testBuildAllowsForAnonymousClientWithRpkTrust() {
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build();
		builder.setClientOnly().setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
				.setAdvancedCertificateVerifier(verifier).build();
	}

	@Test
	public void testBuildAllowsForAnonymousClientWithTrustStore() {
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllCertificates().build();
		builder.setClientOnly().setAdvancedCertificateVerifier(verifier).build();
	}

	@Test
	public void testBuildDetectsErrorForAnonymousClientUsingPSKCiphersOnly() {
		exception.expect(IllegalStateException.class);
		exception.expectMessage(containsString("PSK store must be set"));
		builder.setClientOnly().setSupportedCipherSuites(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8).build();
	}

	@Test
	public void testBuildDetectsErrorForAnonymousClientWithoutTrust() {
		exception.expect(IllegalStateException.class);
		exception.expectMessage(containsString("trust must be set"));
		builder.setClientOnly().setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8).build();
	}

	@Test
	public void testSetNoSignatureAndHashAlgorithms() throws IOException, GeneralSecurityException {
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build();
		DtlsConnectorConfig config = builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setAdvancedCertificateVerifier(verifier)
				.build();
		assertNotNull(config.getSupportedSignatureAlgorithms());
		assertThat(config.getSupportedSignatureAlgorithms(), is(SignatureAndHashAlgorithm.DEFAULT));
	}

	@Test
	public void testSetNoneSignatureAndHashAlgorithms() throws IOException, GeneralSecurityException {
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build();
		DtlsConnectorConfig config = builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setAdvancedCertificateVerifier(verifier)
				.setSupportedSignatureAlgorithms((String[]) null)
				.build();
		assertNotNull(config.getSupportedSignatureAlgorithms());
		assertThat(config.getSupportedSignatureAlgorithms(), is(SignatureAndHashAlgorithm.DEFAULT));
	}

	@Test
	public void testSetNullSignatureAndHashAlgorithms() throws IOException, GeneralSecurityException {
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build();
		DtlsConnectorConfig config = builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setAdvancedCertificateVerifier(verifier)
				.setSupportedSignatureAlgorithms(Collections.<SignatureAndHashAlgorithm>emptyList())
				.build();
		assertNotNull(config.getSupportedSignatureAlgorithms());
		assertThat(config.getSupportedSignatureAlgorithms(), is(SignatureAndHashAlgorithm.DEFAULT));
	}

	@Test
	public void testBuildForSignatureAndHashAlgorithmsRpk() throws IOException, GeneralSecurityException {
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build();
		builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setAdvancedCertificateVerifier(verifier)
				.setSupportedSignatureAlgorithms(SignatureAndHashAlgorithm.SHA1_WITH_ECDSA)
				.build();
	}

	@Test
	public void testBuildSignatureAndHashAlgorithmsX509() throws IOException, GeneralSecurityException {
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllCertificates().build();
		builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getServerCertificateChain())
				.setAdvancedCertificateVerifier(verifier)
				.setSupportedSignatureAlgorithms(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
				.build();
	}

	@Test
	public void testBuildDetectsErrorForSignatureAndHashAlgorithmsRpk() throws IOException, GeneralSecurityException {
		SignatureAndHashAlgorithm algo = new SignatureAndHashAlgorithm(HashAlgorithm.SHA256, SignatureAlgorithm.DSA);
		exception.expect(IllegalStateException.class);
		exception.expectMessage("supported signature and hash algorithms doesn't match the public key!");
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build();
		builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setAdvancedCertificateVerifier(verifier)
				.setSupportedSignatureAlgorithms(algo)
				.build();
	}

	@Test
	public void testBuildDetectsErrorForSignatureAndHashAlgorithmsX509() throws IOException, GeneralSecurityException {
		exception.expect(IllegalStateException.class);
		exception.expectMessage("supported signature and hash algorithms doesn't match the certificate chain!");
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllCertificates().build();
		builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getServerCertificateChain())
				.setAdvancedCertificateVerifier(verifier)
				.setSupportedSignatureAlgorithms(SignatureAndHashAlgorithm.SHA1_WITH_ECDSA)
				.build();
	}

	@Test
	public void testSupportedGroupForMixedCertificateChain() throws IOException, GeneralSecurityException {
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllCertificates().build();
		DtlsConnectorConfig config = builder
				.setIdentity(DtlsTestTools.getServerRsPrivateKey(), DtlsTestTools.getServerRsaCertificateChain())
				.setAdvancedCertificateVerifier(verifier)
				.build();
		assertNotNull(config.getSupportedGroups());
		assertFalse(config.getSupportedGroups().isEmpty());
	}

	@Test
	public void testGetCertificateChainReturnsNullForRpkOnlyConfiguration() throws Exception {
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build();
		// GIVEN a configuration supporting RawPublicKey only
		DtlsConnectorConfig config = builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
				.setAdvancedCertificateVerifier(verifier)
				.build();

		// WHEN retrieving the certificate chain
		List<X509Certificate> chain = config.getCertificateChain();

		// THEN
		assertThat("Certificate chain should be null for RawPublicKey only configuration", chain, is(nullValue()));
	}

	@Test
	public void testWantedAuthentication() throws Exception {
		// GIVEN a configuration supporting RawPublicKey only and wanted client authentication
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build();
		builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())
			.setAdvancedCertificateVerifier(verifier)
			.setClientAuthenticationWanted(true);
		// WHEN configuration is build
		DtlsConnectorConfig config = builder.build();

		// THEN
		assertThat(config.isClientAuthenticationWanted(), is(true));
		assertThat(config.isClientAuthenticationRequired(), is(false));
	}

	@Test
	public void testDisabledRequiredAuthentication() throws Exception {
		// GIVEN a configuration supporting RawPublicKey only and wanted client authentication
		builder.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey());
		builder.setClientAuthenticationRequired(false);
		// WHEN configuration is build
		DtlsConnectorConfig config = builder.build();

		// THEN
		assertThat(config.isClientAuthenticationWanted(), is(false));
		assertThat(config.isClientAuthenticationRequired(), is(false));
	}

	@Test
	public void testClientOnlyWantedAuthentication() throws Exception {
		exception.expect(IllegalStateException.class);
		exception.expectMessage("client authentication is not supported for client only!");
		// GIVEN a configuration supporting RawPublicKey only and wanted client authentication
		builder.setClientOnly()
		// WHEN client authentication is wanted
			.setClientAuthenticationWanted(true);
		// THEN fails
	}

	@Test
	public void testClientOnlyRequiredAuthentication() throws Exception {
		exception.expect(IllegalStateException.class);
		exception.expectMessage("client authentication is not supported for client only!");
		// GIVEN a configuration supporting RawPublicKey only and wanted client authentication
		builder.setClientOnly()
		// WHEN client authentication is required
				.setClientAuthenticationRequired(true);
		// THEN fails
	}

	@Test
	public void testServerOnlyWithDisabledRequiredAuthenticationFailsOnTrust() throws Exception {
		exception.expect(IllegalStateException.class);
		exception.expectMessage("configured trusted certificates or certificate verifier are not used for disabled client authentication!");
		// GIVEN a configuration supporting RawPublicKey only and wanted client authentication
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build();
		builder.setServerOnly(true)
				.setAdvancedCertificateVerifier(verifier)
				.setClientAuthenticationRequired(false)
		// WHEN configuration is build
				.build();
		// THEN fails
	}

	@Test
	public void testAntiReplayFilterAndWindowFilter() throws Exception {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("Anti replay filter is active!");
		builder.setUseAntiReplayFilter(true);
		builder.setUseExtendedWindowFilter(-1);
	}

	@Test
	public void testAntiReplayFilterDefault() throws Exception {
		builder.setAdvancedPskStore(new AdvancedSinglePskStore("ID", "KEY".getBytes()));

		// WHEN configuration is build
		DtlsConnectorConfig config = builder.build();

		// THEN
		assertThat(config.useAntiReplayFilter(), is(true));
		assertThat(config.useExtendedWindowFilter(), is(0));
	}

	@Test
	public void testAntiReplayFilterDefaultWithWindowFilter() throws Exception {
		builder.setAdvancedPskStore(new AdvancedSinglePskStore("ID", "KEY".getBytes()))
				.setUseExtendedWindowFilter(-1);
		
		// WHEN configuration is build
		DtlsConnectorConfig config = builder.build();

		// THEN
		assertThat(config.useAntiReplayFilter(), is(false));
		assertThat(config.useExtendedWindowFilter(), is(-1));
	}

	@Test
	public void testTrustStoreDoNotContainDuplicateSubject() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage(containsString("contains certificates duplicates"));
		X509Certificate[] trustedCertificates = new X509Certificate[2];
		trustedCertificates[0] = DtlsTestTools.getTrustedRootCA();
		trustedCertificates[1] = DtlsTestTools.getTrustedRootCA();
		StaticNewAdvancedCertificateVerifier.builder().setTrustedCertificates(trustedCertificates);
	}
}
