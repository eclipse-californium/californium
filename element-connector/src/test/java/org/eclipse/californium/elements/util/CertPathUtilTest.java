/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * Test cases verifying the cert path generator.
 */
public class CertPathUtilTest {

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
	public void testGenerateCertPath() throws Exception {
		CertPath generateCertPath = CertPathUtil.generateCertPath(clientChainExtUsageList);
		assertEquals(clientChainExtUsageList, generateCertPath.getCertificates());
	}

	@Test
	public void testGenerateTruncatedCertPath() throws Exception {

		List<X509Certificate> truncated = new ArrayList<X509Certificate>(clientChainExtUsageList);
		truncated.remove(truncated.size() - 1);
		truncated.remove(truncated.size() - 1);
		CertPath generateCertPath = CertPathUtil.generateCertPath(clientChainExtUsageList,
				clientChainExtUsageList.size() - 2);
		assertEquals(truncated.size(), generateCertPath.getCertificates().size());
		assertEquals(truncated, generateCertPath.getCertificates());
	}

	@Test
	public void testToX509CertificatesList() throws Exception {
		List<Certificate> list = new ArrayList<Certificate>(clientChainExtUsageList);
		List<X509Certificate> x509List = CertPathUtil.toX509CertificatesList(list);
		assertEquals(list, x509List);
	}

	@Test
	public void testToX509CertificatesListUsingInvalidCertificate() throws Exception {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("Given certificate is not X.509! Dummy");

		List<Certificate> list = new ArrayList<Certificate>(clientChainExtUsageList);
		list.add(new Certificate("Dummy") {

			@Override
			public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException,
					InvalidKeyException, NoSuchProviderException, SignatureException {
			}

			@Override
			public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException,
					InvalidKeyException, NoSuchProviderException, SignatureException {
			}

			@Override
			public String toString() {
				return "Dummy";
			}

			@Override
			public PublicKey getPublicKey() {
				return null;
			}

			@Override
			public byte[] getEncoded() throws CertificateEncodingException {
				return Bytes.EMPTY;
			}
		});
		CertPathUtil.toX509CertificatesList(list);
	}

	@Test
	public void testCanBeUsedToVerifySignature() throws Exception {
		X509Certificate[] certificates = TestCertificatesTools.getTrustedCertificates();
		X509Certificate[] clientCertificates = TestCertificatesTools.getClientCertificateChain();
		X509Certificate[] serverCertificates = TestCertificatesTools.getServerCertificateChain();
		assertTrue(CertPathUtil.canBeUsedToVerifySignature(certificates[0]));
		assertTrue(CertPathUtil.canBeUsedToVerifySignature(certificates[1]));
		assertFalse(CertPathUtil.canBeUsedToVerifySignature(clientCertificates[0]));
		assertFalse(CertPathUtil.canBeUsedToVerifySignature(serverCertificates[0]));
		assertFalse(CertPathUtil.canBeUsedToVerifySignature(clientSelfsigned[0]));
	}

	@Test
	public void testCanBeUsedForClientAuthentication() throws Exception {
		X509Certificate caCertificate = TestCertificatesTools.getTrustedCA();
		X509Certificate[] clientCertificates = TestCertificatesTools.getClientCertificateChain();
		assertFalse(CertPathUtil.canBeUsedForAuthentication(caCertificate, true));
		assertTrue(CertPathUtil.canBeUsedForAuthentication(clientCertificates[0], true));
		assertTrue(CertPathUtil.canBeUsedForAuthentication(clientChainExtUsage[0], true));
		assertTrue(CertPathUtil.canBeUsedForAuthentication(clientSelfsigned[0], true));
	}

	@Test
	public void testCanBeUsedForServerAuthentication() throws Exception {
		X509Certificate caCertificate = TestCertificatesTools.getTrustedCA();
		X509Certificate[] serverCertificates = TestCertificatesTools.getServerCertificateChain();
		assertFalse(CertPathUtil.canBeUsedForAuthentication(caCertificate, false));
		assertTrue(CertPathUtil.canBeUsedForAuthentication(serverCertificates[0], false));
		assertFalse(CertPathUtil.canBeUsedForAuthentication(clientChainExtUsage[0], false));
		assertTrue(CertPathUtil.canBeUsedForAuthentication(clientSelfsigned[0], false));
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
	public void testServerCertificateValidationWithThrust() throws Exception {
		X509Certificate[] certificates = TestCertificatesTools.getServerCertificateChain();
		CertPath certPath = CertPathUtil.generateCertPath(Arrays.asList(certificates));
		CertPath verifiedPath = CertPathUtil.validateCertificatePath(false, certPath,
				TestCertificatesTools.getTrustedCertificates());
		assertEquals(Arrays.asList(certificates), verifiedPath.getCertificates());
	}

	@Test
	public void testClientExtCertificateValidationWithThrust() throws Exception {
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
	public void testSelfSignedValidationThrust() throws Exception {
		CertPath certPath = CertPathUtil.generateCertPath(clientSelfsignedList);
		CertPath verifiedPath = CertPathUtil.validateCertificatePath(false, certPath, clientSelfsigned);
		assertEquals(clientSelfsignedList, verifiedPath.getCertificates());
	}

	@Test
	public void testGenerateValidationCertPath() throws Exception {

		List<X509Certificate> truncated = new ArrayList<X509Certificate>(clientChainExtUsageList);
		truncated.remove(truncated.size() - 1);

		CertPath generateCertPath = CertPathUtil.generateValidatableCertPath(clientChainExtUsageList, null);
		assertEquals(truncated, generateCertPath.getCertificates());
	}

	@Test
	public void testGenerateValidationCertPathForIssuer() throws Exception {
		List<X500Principal> certificateAuthorities = new ArrayList<X500Principal>();
		certificateAuthorities.add(clientChainExtUsage[1].getSubjectX500Principal());
		List<X509Certificate> truncated = new ArrayList<X509Certificate>(clientChainExtUsageList);
		truncated.remove(truncated.size() - 1);
		truncated.remove(truncated.size() - 1);

		CertPath generateCertPath = CertPathUtil.generateValidatableCertPath(clientChainExtUsageList,
				certificateAuthorities);
		assertEquals(truncated.size(), generateCertPath.getCertificates().size());
		assertEquals(truncated, generateCertPath.getCertificates());
	}

	@Test
	public void testGenerateValidationCertPathForUnknownIssuer() throws Exception {
		List<X500Principal> certificateAuthorities = new ArrayList<X500Principal>();
		certificateAuthorities.add(clientSelfsigned[0].getSubjectX500Principal());

		CertPath generateCertPath = CertPathUtil.generateValidatableCertPath(clientChainExtUsageList,
				certificateAuthorities);
		assertEquals(0, generateCertPath.getCertificates().size());
	}

	@Test
	public void testGenerateValidationCertPathSelfSigned() throws Exception {

		CertPath generateCertPath = CertPathUtil.generateValidatableCertPath(clientSelfsignedList, null);
		assertEquals(clientSelfsignedList, generateCertPath.getCertificates());
	}

}
