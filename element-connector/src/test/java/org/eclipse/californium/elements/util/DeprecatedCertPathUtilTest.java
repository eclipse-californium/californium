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
package org.eclipse.californium.elements.util;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * Test cases verifying the cert path generator.
 */
@SuppressWarnings("deprecation")
public class DeprecatedCertPathUtilTest {

	private static final char[] KEY_STORE_PASSWORD = "endPass".toCharArray();
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";

	@Rule
	public ExpectedException exception = ExpectedException.none();

	private X509Certificate[] clientChainExtUsage;
	private X509Certificate[] clientSelfsigned;

	private List<X509Certificate> clientChainExtUsageList;
	private List<X509Certificate> clientSelfsignedList;

	@Before
	public void init() throws IOException, GeneralSecurityException {
		clientChainExtUsage = SslContextUtil.loadCredentials(SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION,
				"clientext", KEY_STORE_PASSWORD, KEY_STORE_PASSWORD).getCertificateChain();
		clientSelfsigned = SslContextUtil.loadCredentials(SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION, "self",
				KEY_STORE_PASSWORD, KEY_STORE_PASSWORD).getCertificateChain();
		clientChainExtUsageList = Arrays.asList(clientChainExtUsage);
		clientSelfsignedList = Arrays.asList(clientSelfsigned);
	}

	@Test
	public void testServerCertificateValidationWithoutTrust() throws Exception {
		exception.expect(CertPathValidatorException.class);
		exception.expectMessage("certificates are not trusted!");
		List<X509Certificate> path = Arrays.asList(TestCertificatesTools.getServerCertificateChain());
		CertPath certPath = CertPathUtil.generateCertPath(path);
		CertPathUtil.validateCertificatePath(false, certPath, null);
	}

	@Test
	public void testServerCertificateValidation() throws Exception {
		X509Certificate[] certificates = TestCertificatesTools.getServerCertificateChain();
		CertPath certPath = CertPathUtil.generateCertPath(Arrays.asList(certificates));
		CertPath verifiedPath = CertPathUtil.validateCertificatePath(false, certPath, new X509Certificate[0]);
		assertEquals(Arrays.asList(certificates), verifiedPath.getCertificates());
	}

	@Test
	public void testServerCertificateValidationUnknownTrust() throws Exception {
		exception.expect(CertPathValidatorException.class);
		exception.expectMessage("Path does not chain with any of the trust anchors");
		X509Certificate[] serverCertificates = TestCertificatesTools.getServerCertificateChain();
		CertPath certPath = CertPathUtil.generateCertPath(Arrays.asList(serverCertificates));
		CertPathUtil.validateCertificatePath(false, certPath, clientSelfsigned);
	}

	@Test
	public void testServerCertificateValidationWithTrust() throws Exception {
		X509Certificate[] certificates = TestCertificatesTools.getServerCertificateChain();
		CertPath certPath = CertPathUtil.generateCertPath(Arrays.asList(certificates));
		CertPath verifiedPath = CertPathUtil.validateCertificatePath(false, certPath,
				TestCertificatesTools.getTrustedCertificates());
		assertEquals(Arrays.asList(certificates), verifiedPath.getCertificates());
	}

	@Test
	public void testServerCertificateValidationWithIntermediateTrustFails() throws Exception {
		exception.expect(CertPathValidatorException.class);
		exception.expectMessage("Path does not chain with any of the trust anchors");
		X509Certificate[] certificates = TestCertificatesTools.getServerCertificateChain();
		X509Certificate[] trusts = new X509Certificate[] {certificates[1]};
		CertPath certPath = CertPathUtil.generateCertPath(Arrays.asList(certificates));
		CertPath verifiedPath = CertPathUtil.validateCertificatePath(false, certPath, trusts);
		assertEquals(Arrays.asList(certificates), verifiedPath.getCertificates());
	}

	@Test
	public void testServerCertificateTruncatingValidationWithIntermediateTrust() throws Exception {
		X509Certificate[] certificates = TestCertificatesTools.getServerCertificateChain();
		X509Certificate[] trusts = new X509Certificate[] { certificates[1] };
		X509Certificate[] verfied = new X509Certificate[] { certificates[0] };
		CertPath certPath = CertPathUtil.generateCertPath(Arrays.asList(certificates));
		CertPath verifiedPath = CertPathUtil.validateCertificatePath(true, certPath, trusts);
		assertEquals(Arrays.asList(verfied), verifiedPath.getCertificates());
	}

	@Test
	public void testServerCertificateValidationWithSelfTrustFails() throws Exception {
		exception.expect(CertPathValidatorException.class);
		exception.expectMessage("Path does not chain with any of the trust anchors");
		X509Certificate[] certificates = TestCertificatesTools.getServerCertificateChain();
		X509Certificate[] trusts = new X509Certificate[] {certificates[0]};
		CertPath certPath = CertPathUtil.generateCertPath(Arrays.asList(certificates));
		CertPath verifiedPath = CertPathUtil.validateCertificatePath(false, certPath, trusts);
		assertEquals(Arrays.asList(certificates), verifiedPath.getCertificates());
	}

	@Test
	public void testServerCertificateTruncatingValidationWithSelfTrust() throws Exception {
		X509Certificate[] certificates = TestCertificatesTools.getServerCertificateChain();
		X509Certificate[] trusts = new X509Certificate[] {certificates[0]};
		X509Certificate[] verfied = new X509Certificate[] {certificates[0]};
		CertPath certPath = CertPathUtil.generateCertPath(Arrays.asList(certificates));
		CertPath verifiedPath = CertPathUtil.validateCertificatePath(true, certPath, trusts);
		assertEquals(Arrays.asList(verfied), verifiedPath.getCertificates());
	}

	@Test
	public void testClientExtCertificateValidationWithTrust() throws Exception {
		CertPath certPath = CertPathUtil.generateCertPath(clientChainExtUsageList);
		CertPath verifiedPath = CertPathUtil.validateCertificatePath(false, certPath,
				TestCertificatesTools.getTrustedCertificates());
		assertEquals(clientChainExtUsage.length, verifiedPath.getCertificates().size());
	}

	@Test
	public void testServerCertificateInvalidPath() throws Exception {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("Given certificates do not form a chain");
		X509Certificate[] certificates = TestCertificatesTools.getServerCertificateChain();
		certificates[1] = clientChainExtUsage[0];
		CertPath certPath = CertPathUtil.generateCertPath(Arrays.asList(certificates));
		CertPathUtil.validateCertificatePath(false, certPath, TestCertificatesTools.getTrustedCertificates());
	}

	@Test
	public void testServerCertificateInvalidPath2() throws Exception {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("Given certificates do not form a chain, root is not the last!");
		X509Certificate[] certificates = TestCertificatesTools.getServerCertificateChain();
		certificates[0] = clientSelfsigned[0];
		CertPath certPath = CertPathUtil.generateCertPath(Arrays.asList(certificates));
		CertPathUtil.validateCertificatePath(false, certPath, TestCertificatesTools.getTrustedCertificates());
	}

	@Test
	public void testSelfSignedValidation() throws Exception {
		CertPath certPath = CertPathUtil.generateCertPath(clientSelfsignedList);
		CertPath verifiedPath = CertPathUtil.validateCertificatePath(false, certPath, new X509Certificate[0]);
		assertEquals(clientSelfsignedList, verifiedPath.getCertificates());
	}

	@Test
	public void testSelfSignedValidationTrust() throws Exception {
		CertPath certPath = CertPathUtil.generateCertPath(clientSelfsignedList);
		CertPath verifiedPath = CertPathUtil.validateCertificatePath(false, certPath, clientSelfsigned);
		assertEquals(clientSelfsignedList, verifiedPath.getCertificates());
	}

}
