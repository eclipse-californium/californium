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

import java.util.List;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.SslContextUtil.Credentials;
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
	public void testRsaCertificateChainWithoutKeyUsageSupportsClientAndServer() {
		helper.addConfigurationDefaultsFor(DtlsTestTools.getServerRsaCertificateChainAsList());
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
		helper.addConfigurationDefaultsForTrusts(DtlsTestTools.getServerRsaCertificateChain());
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

}
