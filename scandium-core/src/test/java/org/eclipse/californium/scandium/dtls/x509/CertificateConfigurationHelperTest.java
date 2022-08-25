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
 *    Bosch.IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.x509;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assume.assumeNotNull;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.KeySpec;
import java.util.List;

import javax.net.ssl.X509KeyManager;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.SslContextUtil.Credentials;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.elements.util.TestCertificatesTools;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class CertificateConfigurationHelperTest {

	CertificateConfigurationHelper helper;

	@Before
	public void setUp() throws Exception {
		helper = new CertificateConfigurationHelper();
	}

	@Test
	public void testRawPublicKeySetupSupportsClientAndServer() {
		helper.addConfigurationDefaultsFor(DtlsTestTools.getClientPublicKey());
		assertThat(helper.canBeUsedForAuthentication(true), is(true));
		assertThat(helper.canBeUsedForAuthentication(false), is(true));
		List<SupportedGroup> defaultSupportedGroups = helper.getDefaultSupportedGroups();
		assertThat(defaultSupportedGroups.size(), is(1));
		assertThat(defaultSupportedGroups, hasItem(SupportedGroup.secp256r1));
		List<SignatureAndHashAlgorithm> defaultSignatureAndHashAlgorithms = helper
				.getDefaultSignatureAndHashAlgorithms();
		assertThat(defaultSignatureAndHashAlgorithms.size(), is(1));
		assertThat(defaultSignatureAndHashAlgorithms, hasItem(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA));
	}

	@Test
	public void testRawRsaPublicKeySetupSupportsClientAndServer() {
		helper.addConfigurationDefaultsFor(DtlsTestTools.getClientRsaPublicKey());
		assertThat(helper.canBeUsedForAuthentication(true), is(true));
		assertThat(helper.canBeUsedForAuthentication(false), is(true));
		List<SupportedGroup> defaultSupportedGroups = helper.getDefaultSupportedGroups();
		assertThat(defaultSupportedGroups.size(), is(0));
		List<SignatureAndHashAlgorithm> defaultSignatureAndHashAlgorithms = helper
				.getDefaultSignatureAndHashAlgorithms();
		assertThat(defaultSignatureAndHashAlgorithms.size(), is(1));
		assertThat(defaultSignatureAndHashAlgorithms, hasItem(SignatureAndHashAlgorithm.SHA256_WITH_RSA));
	}

	@Test
	public void testCertificateChainWithClientUsageSupportsClientOnly() {
		Credentials credentials = DtlsTestTools.getCredentials("clientext");
		helper.addConfigurationDefaultsFor(credentials.getCertificateChainAsList());
		assertThat(helper.canBeUsedForAuthentication(true), is(true));
		assertThat(helper.canBeUsedForAuthentication(false), is(false));
		List<SupportedGroup> defaultSupportedGroups = helper.getDefaultSupportedGroups();
		assertThat(defaultSupportedGroups.size(), is(1));
		assertThat(defaultSupportedGroups, hasItem(SupportedGroup.secp256r1));
		List<SignatureAndHashAlgorithm> defaultSignatureAndHashAlgorithms = helper
				.getDefaultSignatureAndHashAlgorithms();
		assertThat(defaultSignatureAndHashAlgorithms.size(), is(1));
		assertThat(defaultSignatureAndHashAlgorithms, hasItem(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA));
	}

	@Test
	public void testCertificateRsaChain() {
		Credentials credentials = DtlsTestTools.getCredentials("serverrsa");
		helper.addConfigurationDefaultsFor(credentials.getCertificateChainAsList());
		// no key usage extension
		assertThat(helper.canBeUsedForAuthentication(true), is(true));
		assertThat(helper.canBeUsedForAuthentication(false), is(true));
		List<SupportedGroup> defaultSupportedGroups = helper.getDefaultSupportedGroups();
		assertThat(defaultSupportedGroups.size(), is(1));
		assertThat(defaultSupportedGroups, hasItem(SupportedGroup.secp256r1));
		List<SignatureAndHashAlgorithm> defaultSignatureAndHashAlgorithms = helper
				.getDefaultSignatureAndHashAlgorithms();
		assertThat(defaultSignatureAndHashAlgorithms.size(), is(2));
		assertThat(defaultSignatureAndHashAlgorithms, hasItem(SignatureAndHashAlgorithm.SHA256_WITH_RSA));
		assertThat(defaultSignatureAndHashAlgorithms, hasItem(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA));
	}

	@Test
	public void testRsaCertificateChainWithoutKeyUsageSupportsClientAndServer() {
		helper.addConfigurationDefaultsFor(DtlsTestTools.getServerCaRsaCertificateChainAsList());
		assertThat(helper.canBeUsedForAuthentication(true), is(true));
		assertThat(helper.canBeUsedForAuthentication(false), is(true));
		List<SupportedGroup> defaultSupportedGroups = helper.getDefaultSupportedGroups();
		assertThat(defaultSupportedGroups.size(), is(1));
		assertThat(defaultSupportedGroups, hasItem(SupportedGroup.secp256r1));
		List<SignatureAndHashAlgorithm> defaultSignatureAndHashAlgorithms = helper
				.getDefaultSignatureAndHashAlgorithms();
		assertThat(defaultSignatureAndHashAlgorithms.size(), is(2));
		assertThat(defaultSignatureAndHashAlgorithms, hasItem(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA));
		assertThat(defaultSignatureAndHashAlgorithms, hasItem(SignatureAndHashAlgorithm.SHA256_WITH_RSA));
	}

	@Test
	public void testTrustedCertificatesSupportsClientAndServer() {
		Credentials credentials = DtlsTestTools.getCredentials("clientext");
		helper.addConfigurationDefaultsForTrusts(credentials.getCertificateChain());
		assertThat(helper.canBeUsedForAuthentication(true), is(true));
		assertThat(helper.canBeUsedForAuthentication(false), is(true));
		List<SupportedGroup> defaultSupportedGroups = helper.getDefaultSupportedGroups();
		assertThat(defaultSupportedGroups.size(), is(1));
		assertThat(defaultSupportedGroups, hasItem(SupportedGroup.secp256r1));
		List<SignatureAndHashAlgorithm> defaultSignatureAndHashAlgorithms = helper
				.getDefaultSignatureAndHashAlgorithms();
		assertThat(defaultSignatureAndHashAlgorithms.size(), is(1));
		assertThat(defaultSignatureAndHashAlgorithms, hasItem(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA));
	}

	@Test
	public void testTrustedRsaCertificatesSupportsClientAndServer() {
		helper.addConfigurationDefaultsForTrusts(DtlsTestTools.getServerCaRsaCertificateChain());
		assertThat(helper.canBeUsedForAuthentication(true), is(true));
		assertThat(helper.canBeUsedForAuthentication(false), is(true));
		List<SupportedGroup> defaultSupportedGroups = helper.getDefaultSupportedGroups();
		assertThat(defaultSupportedGroups.size(), is(1));
		assertThat(defaultSupportedGroups, hasItem(SupportedGroup.secp256r1));
		List<SignatureAndHashAlgorithm> defaultSignatureAndHashAlgorithms = helper
				.getDefaultSignatureAndHashAlgorithms();
		assertThat(defaultSignatureAndHashAlgorithms.size(), is(2));
		assertThat(defaultSignatureAndHashAlgorithms, hasItem(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA));
		assertThat(defaultSignatureAndHashAlgorithms, hasItem(SignatureAndHashAlgorithm.SHA256_WITH_RSA));
	}

	@Test
	public void testWithKeyManager() {
		X509KeyManager keyManager = DtlsTestTools.getServerKeyManager();
		KeyManagerCertificateProvider provider = new KeyManagerCertificateProvider(keyManager, CertificateType.X_509);
		provider.setupConfigurationHelper(helper);
		// no key usage extension
		assertThat(helper.canBeUsedForAuthentication(true), is(true));
		assertThat(helper.canBeUsedForAuthentication(false), is(true));
		List<SupportedGroup> defaultSupportedGroups = helper.getDefaultSupportedGroups();
		assertThat(defaultSupportedGroups.size(), is(1));
		assertThat(defaultSupportedGroups, hasItem(SupportedGroup.secp256r1));
		List<SignatureAndHashAlgorithm> defaultSignatureAndHashAlgorithms = helper
				.getDefaultSignatureAndHashAlgorithms();
		assertThat(defaultSignatureAndHashAlgorithms.size(), is(2));
		assertThat(defaultSignatureAndHashAlgorithms, hasItem(SignatureAndHashAlgorithm.SHA256_WITH_RSA));
		assertThat(defaultSignatureAndHashAlgorithms, hasItem(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA));
	}

	@Test
	public void testWithEdDsaKeyManager() {
		X509KeyManager edDsaKeyManager = DtlsTestTools.getServerEdDsaKeyManager();
		assumeNotNull("EdDSA KeyManager is not available!", edDsaKeyManager);
		KeyManagerCertificateProvider provider = new KeyManagerCertificateProvider(edDsaKeyManager,
				CertificateType.X_509);
		provider.setupConfigurationHelper(helper);
		// no key usage extension
		assertThat(helper.canBeUsedForAuthentication(true), is(true));
		assertThat(helper.canBeUsedForAuthentication(false), is(true));
		List<SupportedGroup> defaultSupportedGroups = helper.getDefaultSupportedGroups();
		assertThat(defaultSupportedGroups.size(), is(2));
		assertThat(defaultSupportedGroups, hasItem(SupportedGroup.X25519));
		assertThat(defaultSupportedGroups, hasItem(SupportedGroup.secp256r1));
		List<SignatureAndHashAlgorithm> defaultSignatureAndHashAlgorithms = helper
				.getDefaultSignatureAndHashAlgorithms();
		assertThat(defaultSignatureAndHashAlgorithms.size(), is(3));
		assertThat(defaultSignatureAndHashAlgorithms, hasItem(SignatureAndHashAlgorithm.SHA256_WITH_RSA));
		assertThat(defaultSignatureAndHashAlgorithms, hasItem(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA));
		assertThat(defaultSignatureAndHashAlgorithms, hasItem(SignatureAndHashAlgorithm.INTRINSIC_WITH_ED25519));
	}

	@Test
	public void testWithKeyManagerEcdsaOnly() {
		X509KeyManager keyManager = DtlsTestTools.getKeyManager(TestCertificatesTools.serverCredentials);
		KeyManagerCertificateProvider provider = new KeyManagerCertificateProvider(keyManager, CertificateType.X_509);
		provider.setupConfigurationHelper(helper);
		// no key usage extension
		assertThat(helper.canBeUsedForAuthentication(true), is(true));
		assertThat(helper.canBeUsedForAuthentication(false), is(true));
		List<SupportedGroup> defaultSupportedGroups = helper.getDefaultSupportedGroups();
		assertThat(defaultSupportedGroups.size(), is(1));
		assertThat(defaultSupportedGroups, hasItem(SupportedGroup.secp256r1));
		List<SignatureAndHashAlgorithm> defaultSignatureAndHashAlgorithms = helper
				.getDefaultSignatureAndHashAlgorithms();
		assertThat(defaultSignatureAndHashAlgorithms.size(), is(1));
		assertThat(defaultSignatureAndHashAlgorithms, hasItem(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA));
	}

	@Test
	public void testWithKeyManagerRsaOnly() {
		X509KeyManager keyManager = DtlsTestTools.getKeyManager(TestCertificatesTools.serverRsaCredentials);
		KeyManagerCertificateProvider provider = new KeyManagerCertificateProvider(keyManager, CertificateType.X_509);
		provider.setupConfigurationHelper(helper);
		// no key usage extension
		assertThat(helper.canBeUsedForAuthentication(true), is(true));
		assertThat(helper.canBeUsedForAuthentication(false), is(true));
		List<SupportedGroup> defaultSupportedGroups = helper.getDefaultSupportedGroups();
		assertThat(defaultSupportedGroups.size(), is(1));
		assertThat(defaultSupportedGroups, hasItem(SupportedGroup.secp256r1));
		List<SignatureAndHashAlgorithm> defaultSignatureAndHashAlgorithms = helper
				.getDefaultSignatureAndHashAlgorithms();
		assertThat(defaultSignatureAndHashAlgorithms.size(), is(2));
		assertThat(defaultSignatureAndHashAlgorithms, hasItem(SignatureAndHashAlgorithm.SHA256_WITH_RSA));
		assertThat(defaultSignatureAndHashAlgorithms, hasItem(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA));
	}

	@Test
	public void testWithKeyManagerRsaRawPublicKeyOnly() {
		X509KeyManager keyManager = DtlsTestTools.getKeyManager(TestCertificatesTools.serverRsaCredentials);
		KeyManagerCertificateProvider provider = new KeyManagerCertificateProvider(keyManager,
				CertificateType.RAW_PUBLIC_KEY);
		provider.setupConfigurationHelper(helper);
		// no key usage extension
		assertThat(helper.canBeUsedForAuthentication(true), is(true));
		assertThat(helper.canBeUsedForAuthentication(false), is(true));
		List<SupportedGroup> defaultSupportedGroups = helper.getDefaultSupportedGroups();
		assertThat(defaultSupportedGroups.size(), is(0));
		List<SignatureAndHashAlgorithm> defaultSignatureAndHashAlgorithms = helper
				.getDefaultSignatureAndHashAlgorithms();
		assertThat(defaultSignatureAndHashAlgorithms.size(), is(1));
		assertThat(defaultSignatureAndHashAlgorithms, hasItem(SignatureAndHashAlgorithm.SHA256_WITH_RSA));
	}

	/**
	 * The test verifies, that the demo ECDSA keys of Leshan could be verified.
	 * 
	 * Since java 15 the public keys must ensure, that the passed in value is a
	 * positive number. Otherwise the key may not be applicable for signature
	 * verification.
	 * 
	 * The key are copied from <a href=
	 * "https://github.com/eclipse/leshan/blob/master/leshan-server-cf/src/test/java/org/eclipse/leshan/server/californium/bootstrap/LeshanBootstrapServerBuilderTest.java#L61-L85"
	 * target="_blank"> LeshanBootstrapServerBuilderTest</a>.
	 * 
	 * @throws Exception if an error occurs.
	 */
	@Test
	public void testWithLeshanDemoRPK() throws Exception {
		// Get point values
		byte[] publicX = StringUtil.hex2ByteArray("89c048261979208666f2bfb188be1968fc9021c416ce12828c06f4e314c167b5");
		byte[] publicY = StringUtil.hex2ByteArray("cbf1eb7587f08e01688d9ada4be859137ca49f79394bad9179326b3090967b68");
		byte[] privateS = StringUtil.hex2ByteArray("e67b68d2aaeb6550f19d98cade3ad62b39532e02e6b422e1f7ea189dabaea5d2");

		// Get Elliptic Curve Parameter spec for secp256r1
		AlgorithmParameters algoParameters = AlgorithmParameters.getInstance("EC");
		algoParameters.init(new ECGenParameterSpec("secp256r1"));
		ECParameterSpec parameterSpec = algoParameters.getParameterSpec(ECParameterSpec.class);

		// Create key specs
		KeySpec publicKeySpec = new ECPublicKeySpec(new ECPoint(new BigInteger(1, publicX), new BigInteger(1, publicY)),
				parameterSpec);
		KeySpec privateKeySpec = new ECPrivateKeySpec(new BigInteger(1, privateS), parameterSpec);

		// Get keys
		PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(publicKeySpec);
		PrivateKey privateKey = KeyFactory.getInstance("EC").generatePrivate(privateKeySpec);
		helper.verifyKeyPair(privateKey, publicKey);
	}

}
