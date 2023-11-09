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
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeNotNull;
import static org.junit.Assume.assumeTrue;

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

import javax.net.ssl.X509KeyManager;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.config.CertificateAuthenticationMode;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.ExpectedExceptionWrapper;
import org.eclipse.californium.elements.util.JceNames;
import org.eclipse.californium.elements.util.JceProviderUtil;
import org.eclipse.californium.elements.util.SslContextUtil.Credentials;
import org.eclipse.californium.scandium.config.DtlsConfig.DtlsRole;
import org.eclipse.californium.scandium.dtls.CertificateIdentityResult;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm.HashAlgorithm;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm.SignatureAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedSinglePskStore;
import org.eclipse.californium.scandium.dtls.x509.KeyManagerCertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.NewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.SingleCertificateProvider;
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
		Configuration configuration = new Configuration();
		builder = DtlsConnectorConfig.builder(configuration).setAddress(endpoint);
	}

	@Test
	public void testSetSupportedCiphersRejectsNullCipher() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage(containsString("is not in"));
		builder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_NULL_WITH_NULL_NULL);
	}

	@Test
	public void testSetSupportedCiphersRejectsEmptyArray() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage(containsString("must not be empty"));
		builder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, new CipherSuite[] {});
	}

	@Test
	public void testSetSupportedCiphersRejectsNull() {
		exception.expect(NullPointerException.class);
		exception.expectMessage(containsString("must not be null"));
		builder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, (CipherSuite[]) null);
	}

	@Test
	public void testSetSupportedCiphersListRejectsNullCipher() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage(containsString("is not in"));
		builder.set(DtlsConfig.DTLS_CIPHER_SUITES, Arrays.asList(CipherSuite.TLS_NULL_WITH_NULL_NULL));
	}

	@Test
	public void testSetSupportedCiphersListRejectsEmptyArray() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage(containsString("must not be empty"));
		builder.set(DtlsConfig.DTLS_CIPHER_SUITES, new ArrayList<CipherSuite>(0));
	}

	@Test
	public void testBuilderSupportEdDsaForCertificate() throws Exception {
		assumeTrue("Ed25519 not supported by JCE", JceProviderUtil.isSupported(JceNames.ED25519));
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllCertificates().setTrustAllRPKs().build();
		Credentials credentials = DtlsTestTools.getCredentials("servereddsa");
		assumeNotNull("servereddsa credentials missing!", credentials);
		builder.setCertificateIdentityProvider(new SingleCertificateProvider(credentials.getPrivateKey(), credentials.getCertificateChain()))
				.setAdvancedCertificateVerifier(verifier)
				.build();
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
		builder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		DtlsConnectorConfig config = builder.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())).build();
		assertFalse(config.getSupportedCipherSuites().isEmpty());
		for (CipherSuite suite : config.getSupportedCipherSuites()) {
			assertThat(suite.getKeyExchange(), is(KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN));
		}
	}

	@Test
	public void testBuilderSetsAtLeastAllMandatoryCipherSuitesWhenKeysAndPskStoreAreSet() throws Exception {
		builder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE)
				.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false);
		DtlsConnectorConfig config = builder
				.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey()))
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
		builder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		builder.setAsList(DtlsConfig.DTLS_PRESELECTED_CIPHER_SUITES, CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
				CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
		DtlsConnectorConfig config = builder
				.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false)
				.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey()))
				.setAdvancedPskStore(new AdvancedSinglePskStore("ID", "KEY".getBytes()))
				.build();
		List<CipherSuite> cipherSuites = config.getSupportedCipherSuites();
		assertThat(cipherSuites,
				hasItems(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256));
		assertThat(cipherSuites, not(hasItems(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256)));
		assertThat(cipherSuites, not(hasItems(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)));
	}

	@Test
	public void testBuilderSetsNoNotRecommendedCipherSuitesWhenKeysAndPskStoreAreSet() throws Exception {
		builder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		DtlsConnectorConfig config = builder.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey()))
				.setAdvancedPskStore(new AdvancedSinglePskStore("ID", "KEY".getBytes())).build();
		List<CipherSuite> cipherSuites = config.getSupportedCipherSuites();
		for (CipherSuite cipherSuite :cipherSuites) {
			assertThat(cipherSuite.isRecommended(), is(true)); 
		}
	}

	@Test
	public void testBuilderDetectsNotRecommendedCiperSuite() {
		exception.expect(IllegalStateException.class);
		exception.expectMessage(containsString("Not recommended cipher suites"));
		builder.setAdvancedPskStore(new AdvancedSinglePskStore("ID", "KEY".getBytes()));
		builder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256).build();
	}

	@Test
	public void testBuilderDetectsNotRecommendedSignatureAndHashAlgorithms() {
		exception.expect(IllegalStateException.class);
		exception.expectMessage(containsString("Not recommended signature and hash algorithms"));
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build();
		builder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
				.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey()))
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, SignatureAndHashAlgorithm.SHA1_WITH_ECDSA)
				.setAdvancedCertificateVerifier(verifier)
				.build();
	}

	@Test
	public void testBuilderDetectsNotRecommendedSupportedGroup() {
		SupportedGroup notRecommended = null;
		for (SupportedGroup group : SupportedGroup.getUsableGroups()) {
			if (!group.isRecommended()) {
				notRecommended = group;
				break;
			}
		}
		assumeNotNull("no not recommended curve usable!", notRecommended);
		exception.expect(IllegalStateException.class);
		exception.expectMessage(containsString("Not recommended supported groups"));
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build();
		builder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
				.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey()))
				.setAsList(DtlsConfig.DTLS_CURVES, notRecommended)
				.setAdvancedCertificateVerifier(verifier)
				.build();
	}

	@Test
	public void testBuilderDetectsNoCurveForCertificate() throws Exception {
		exception.expect(IllegalStateException.class);
		exception.expectMessage(containsString("public key used with not configured group (curve)"));
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build();
		builder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
				.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey()))
				.setAsListFromText(DtlsConfig.DTLS_CURVES, "secp384r1")
				.setAdvancedCertificateVerifier(verifier)
				.build();
	}

	@Test
	public void testBuilderDetectsMissingIdentity() {
		exception.expect(IllegalStateException.class);
		exception.expectMessage(containsString("Identity must be set"));
		builder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8).build();
	}

	@Test
	public void testBuilderDetectsMissingTrust() throws Exception {
		exception.expect(IllegalStateException.class);
		exception.expectMessage(containsString("certificate verifier must be set"));
		builder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
				.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey())).build();
	}

	@Test
	public void testBuilderDetectsMissingPskStore() {
		exception.expect(IllegalStateException.class);
		exception.expectMessage(containsString("PSK store must be set"));
		builder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_PSK_WITH_AES_128_CCM_8).build();
	}

	@Test
	public void testSetIdentityRequiresPrivateKey() {
		exception.expect(NullPointerException.class);
		exception.expectMessage("Private key must not be null!");
		new SingleCertificateProvider(null, new Certificate[0], CertificateType.X_509);
	}

	@Test
	public void testSetIdentityRequiresCertChain() throws Exception {
		exception.expect(NullPointerException.class);
		exception.expectMessage("Certificate chain must not be null!");
		new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), null, CertificateType.X_509);
	}

	public void testSetIdentityWithoutCertificateTypeArray() throws Exception {
		builder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		builder.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getServerCertificateChain()))
				.build();
	}

	public void testSetIdentityWithNullCertificateTypeArray() throws Exception {
		builder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		builder.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getServerCertificateChain(),
				(CertificateType[]) null)).build();
	}

	public void testSetIdentityWithoutCertificateTypeList() throws Exception {
		builder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		builder.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getServerCertificateChain(),
				(List<CertificateType>) null)).build();
	}

	@Test
	public void testSetIdentityRequiresNoneEmptyCertificateTypeList() throws Exception {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("Certificate types must not be empty!");
		new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getServerCertificateChain(),
				new ArrayList<CertificateType>(0));
	}

	@Test
	public void testSetIdentityRequiresNoneEmptyCertChain() throws Exception {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("Certificate chain must not be empty!");
		new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), new Certificate[0], CertificateType.X_509);
	}

	@Test
	public void testSetIdentityRequiresPrivateAndPublicKey() throws IOException, GeneralSecurityException {
		PrivateKey privateKey = DtlsTestTools.getPrivateKey();
		PublicKey publicKey = DtlsTestTools.getPublicKey();
		try {
			new SingleCertificateProvider(privateKey, null);
			fail("Should have rejected null as public key");
		} catch (NullPointerException e) {
			// all is well
		}
		try {
			new SingleCertificateProvider(null, publicKey);
			fail("Should have rejected null as private key");
		} catch (NullPointerException e) {
			// all is well
		}
	}

	@Test
	public void testBuildAllowsForAnonymousClientWithRpkTrust() {
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build();
		builder.set(DtlsConfig.DTLS_ROLE, DtlsRole.CLIENT_ONLY);
		builder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
				.setAdvancedCertificateVerifier(verifier).build();
	}

	@Test
	public void testBuildAllowsForAnonymousClientWithTrustStore() {
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllCertificates().build();
		builder.set(DtlsConfig.DTLS_ROLE, DtlsRole.CLIENT_ONLY);
		builder.setAdvancedCertificateVerifier(verifier).build();
	}

	@Test
	public void testBuildAllowsForServerWithoutTrust() {
		builder.set(DtlsConfig.DTLS_ROLE, DtlsRole.SERVER_ONLY);
		builder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		builder.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getServerCertificateChain()))
		.build();
	}

	@Test
	public void testBuildDetectsErrorForAnonymousClientUsingPSKCiphersOnly() {
		exception.expect(IllegalStateException.class);
		exception.expectMessage(containsString("PSK store must be set"));
		builder.set(DtlsConfig.DTLS_ROLE, DtlsRole.CLIENT_ONLY);
		builder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_PSK_WITH_AES_128_CCM_8).build();
	}

	@Test
	public void testBuildDetectsErrorForAnonymousClientWithoutTrust() {
		exception.expect(IllegalStateException.class);
		exception.expectMessage(containsString("certificate verifier must be set"));
		builder.set(DtlsConfig.DTLS_ROLE, DtlsRole.CLIENT_ONLY);
		builder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8).build();
	}

	@Test
	public void testSetNoSignatureAndHashAlgorithms() throws IOException, GeneralSecurityException {
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build();
		DtlsConnectorConfig config = builder.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey()))
				.setAdvancedCertificateVerifier(verifier)
				.build();
		assertNotNull(config.getSupportedSignatureAlgorithms());
		assertThat(config.getSupportedSignatureAlgorithms(), is(SignatureAndHashAlgorithm.DEFAULT));
	}

	@Test
	public void testSetNoneSignatureAndHashAlgorithms() throws IOException, GeneralSecurityException {
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build();
		DtlsConnectorConfig config = builder.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey()))
				.setAdvancedCertificateVerifier(verifier)
				.set(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, null)
				.build();
		assertNotNull(config.getSupportedSignatureAlgorithms());
		assertThat(config.getSupportedSignatureAlgorithms(), is(SignatureAndHashAlgorithm.DEFAULT));
	}

	@Test
	public void testSetNullSignatureAndHashAlgorithms() throws IOException, GeneralSecurityException {
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build();
		DtlsConnectorConfig config = builder.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey()))
				.setAdvancedCertificateVerifier(verifier)
				.set(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, Collections.<SignatureAndHashAlgorithm>emptyList())
				.build();
		assertNotNull(config.getSupportedSignatureAlgorithms());
		assertThat(config.getSupportedSignatureAlgorithms(), is(SignatureAndHashAlgorithm.DEFAULT));
	}

	@Test
	public void testBuildForSignatureAndHashAlgorithmsRpk() throws IOException, GeneralSecurityException {
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build();
		builder.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey()))
				.setAdvancedCertificateVerifier(verifier)
				.set(DtlsConfig.DTLS_RECOMMENDED_SIGNATURE_AND_HASH_ALGORITHMS_ONLY, false)
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, SignatureAndHashAlgorithm.SHA1_WITH_ECDSA)
				.build();
	}

	@Test
	public void testBuildSignatureAndHashAlgorithmsX509() throws IOException, GeneralSecurityException {
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllCertificates().build();
		builder.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getServerCertificateChain()))
				.setAdvancedCertificateVerifier(verifier)
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
				.build();
	}

	@Test
	public void testBuildDetectsErrorForSignatureAndHashAlgorithmsRpk() throws IOException, GeneralSecurityException {
		SignatureAndHashAlgorithm algo = new SignatureAndHashAlgorithm(HashAlgorithm.SHA256, SignatureAlgorithm.RSA);
		exception.expect(IllegalStateException.class);
		exception.expectMessage("supported signature and hash algorithms");
		exception.expectMessage("doesn't match the public");
		exception.expectMessage("key!");
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build();
		builder.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey()))
				.setAdvancedCertificateVerifier(verifier)
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, algo)
				.build();
	}

	@Test
	public void testBuildDetectsErrorForSignatureAndHashAlgorithmsX509() throws IOException, GeneralSecurityException {
		exception.expect(IllegalStateException.class);
		exception.expectMessage("supported signature and hash algorithms ");
		exception.expectMessage(" doesn't match the certificate chain!");
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllCertificates().build();
		builder.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getServerCertificateChain()))
				.setAdvancedCertificateVerifier(verifier)
				.set(DtlsConfig.DTLS_RECOMMENDED_SIGNATURE_AND_HASH_ALGORITHMS_ONLY, false)
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, SignatureAndHashAlgorithm.SHA1_WITH_ECDSA)
				.build();
	}

	@Test
	public void testSupportedGroupForMixedCertificateChain() throws IOException, GeneralSecurityException {
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllCertificates().build();
		DtlsConnectorConfig config = builder
				.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getServerCaRsaPrivateKey(), DtlsTestTools.getServerCaRsaCertificateChain()))
				.setAdvancedCertificateVerifier(verifier)
				.build();
		assertNotNull(config.getSupportedGroups());
		assertFalse(config.getSupportedGroups().isEmpty());
		assertThat(config.getSupportedGroups(), hasItem(SupportedGroup.secp256r1));
	}

	@Test
	public void testSupportedCipherSuitesForKeyManager() throws IOException, GeneralSecurityException {
		X509KeyManager keyManager = DtlsTestTools.getServerKeyManager();
		KeyManagerCertificateProvider provider = new KeyManagerCertificateProvider(keyManager, CertificateType.X_509);
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllCertificates().build();
		DtlsConnectorConfig config = builder
				.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false)
				.setCertificateIdentityProvider(provider)
				.setAdvancedCertificateVerifier(verifier)
				.build();
		assertNotNull(config.getSupportedCipherSuites());
		assertFalse(config.getSupportedCipherSuites().isEmpty());
		assertThat(config.getSupportedCipherSuites(), hasItem(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
		assertThat(config.getSupportedCipherSuites(), hasItem(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256));
	}

	@Test
	public void testSupportedSignaturesForKeyManager() throws IOException, GeneralSecurityException {
		X509KeyManager keyManager = DtlsTestTools.getServerKeyManager();
		KeyManagerCertificateProvider provider = new KeyManagerCertificateProvider(keyManager, CertificateType.X_509);
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllCertificates().build();
		DtlsConnectorConfig config = builder
				.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false)
				.setCertificateIdentityProvider(provider)
				.setAdvancedCertificateVerifier(verifier)
				.build();
		assertNotNull(config.getSupportedSignatureAlgorithms());
		assertFalse(config.getSupportedSignatureAlgorithms().isEmpty());
		assertThat(config.getSupportedSignatureAlgorithms(), hasItem(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA));
		assertThat(config.getSupportedSignatureAlgorithms(), hasItem(SignatureAndHashAlgorithm.SHA256_WITH_RSA));
	}

	@Test
	public void testSupportedCurvesForKeyManager() throws IOException, GeneralSecurityException {
		X509KeyManager keyManager = DtlsTestTools.getServerKeyManager();
		KeyManagerCertificateProvider provider = new KeyManagerCertificateProvider(keyManager, CertificateType.X_509);
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder()
				.setTrustAllCertificates().build();
		DtlsConnectorConfig config = builder
				.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false)
				.setCertificateIdentityProvider(provider)
				.setAdvancedCertificateVerifier(verifier)
				.build();
		assertNotNull(config.getSupportedGroups());
		assertFalse(config.getSupportedGroups().isEmpty());
		assertThat(config.getSupportedGroups(), hasItem(SupportedGroup.secp256r1));
	}

	@Test
	public void testGetCertificateChainReturnsNullForRpkOnlyConfiguration() throws Exception {
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build();
		// GIVEN a configuration supporting RawPublicKey only
		DtlsConnectorConfig config = builder.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey()))
				.setAdvancedCertificateVerifier(verifier)
				.build();

		// WHEN retrieving the certificate chain
		CertificateIdentityResult result = config.getCertificateIdentityProvider().requestCertificateIdentity(ConnectionId.EMPTY, false, null, null, null, null, null);
		List<X509Certificate> chain = result.getCertificateChain();

		// THEN
		assertThat("Certificate chain should be null for RawPublicKey only configuration", chain, is(nullValue()));
	}

	@Test
	public void testServerOnlyWithDisabledRequiredAuthenticationFailsOnTrust() throws Exception {
		exception.expect(IllegalStateException.class);
		exception.expectMessage("configured certificate verifier is not used for client authentication mode NONE!");
		// GIVEN a configuration supporting RawPublicKey only and wanted client authentication
		builder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		builder.set(DtlsConfig.DTLS_ROLE, DtlsRole.SERVER_ONLY);
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build();
		builder.setAdvancedCertificateVerifier(verifier)
		// WHEN configuration is build
				.build();
		// THEN fails
	}

	@Test
	public void testAntiReplayFilterDefault() throws Exception {
		builder.setAdvancedPskStore(new AdvancedSinglePskStore("ID", "KEY".getBytes()));

		// WHEN configuration is build
		DtlsConnectorConfig config = builder.build();

		// THEN
		assertThat(config.get(DtlsConfig.DTLS_USE_ANTI_REPLAY_FILTER), is(true));
		assertThat(config.get(DtlsConfig.DTLS_USE_DISABLED_WINDOW_FOR_ANTI_REPLAY_FILTER), is(0));
	}

	@Test
	public void testAntiReplayFilterDefaultWithWindowFilter() throws Exception {
		builder.setAdvancedPskStore(new AdvancedSinglePskStore("ID", "KEY".getBytes()))
				.set(DtlsConfig.DTLS_USE_DISABLED_WINDOW_FOR_ANTI_REPLAY_FILTER, -1);
		
		// WHEN configuration is build
		DtlsConnectorConfig config = builder.build();

		// THEN
		assertThat(config.get(DtlsConfig.DTLS_USE_ANTI_REPLAY_FILTER), is(true));
		assertThat(config.get(DtlsConfig.DTLS_USE_DISABLED_WINDOW_FOR_ANTI_REPLAY_FILTER), is(-1));
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

	@SuppressWarnings("deprecation")
	@Test
	public void testDisableHelloVerifyRequestForPskWithoutPskCiperSuite() {
		exception.expect(IllegalStateException.class);
		exception.expectMessage(containsString("HELLO_VERIFY_REQUEST disabled for PSK, requires at least one PSK cipher suite!"));
		builder.set(DtlsConfig.DTLS_USE_HELLO_VERIFY_REQUEST_FOR_PSK, false);
		builder.setAdvancedCertificateVerifier(StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build());
		builder.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey()));
		builder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8).build();
	}

	@SuppressWarnings("deprecation")
	@Test
	public void testDisableHelloVerifyRequestForPskWithoutPskCiperSuite2() {
		exception.expect(IllegalStateException.class);
		exception.expectMessage(containsString("HELLO_VERIFY_REQUEST disabled"));
		builder.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey()));
		builder.set(DtlsConfig.DTLS_USE_HELLO_VERIFY_REQUEST_FOR_PSK, false);
		builder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		builder.build();
	}

	@Test
	public void testDisableHelloVerifyRequestWithoutPskCiperSuite() {
		builder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
		builder.set(DtlsConfig.DTLS_USE_HELLO_VERIFY_REQUEST, false);
		builder.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getPublicKey()));
		builder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		builder.build();
	}

}
