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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeThat;

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

import org.eclipse.californium.elements.category.Small;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.ExpectedException;

/**
 * Test cases verifying the cert path generator and validator.
 * 
 * <pre>
 *                  +-- caalt (cf-ca)
 *                  |
 *                  |
 * root (cf-root) --+-- carsa (cf-ca-rsa) --+-- serverrsa (cf-server-rsa)
 *                  |
 *                  |
 *                  |                       +-- ca2 (cf-ca2) --+-- serverlarge (cf-serverlarge)
 *                  |                       |
 *                  +-- ca (cf-ca) ---------+-- server (cf-server)
 *                                          |
 *                                          +-- client (cf-client)
 *                                          |
 *                                          +-- clientext (cf-clientext)
 * 
 * self (cf-self)
 * 
 * nosigning (cf-nosigning)
 * 
 * </pre>
 */
@Category(Small.class)
public class CertPathUtilTest {

	private static final char[] KEY_STORE_PASSWORD = "endPass".toCharArray();
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";

	private static final X509Certificate[] ALL = new X509Certificate[0];

	@Rule
	public ExpectedException exception = ExpectedExceptionWrapper.none();

	private X509Certificate[] clientChainExtUsage;
	private X509Certificate[] clientSelfsigned;
	private X509Certificate[] server;
	private X509Certificate[] serverLarge;

	private List<X509Certificate> clientChainExtUsageList;
	private List<X509Certificate> clientSelfsignedList;
	private List<X509Certificate> serverLargeList;

	private void expectTrustAnchorError() {
		exception.expectMessage(anyOf(containsString("Path does not chain with any of the trust anchors"),
				containsString("Trust anchor for certification path not found")));
	}

	@Before
	public void init() throws IOException, GeneralSecurityException {
		// includes root!
		clientChainExtUsage = SslContextUtil.loadCredentials(SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION,
				"clientext", KEY_STORE_PASSWORD, KEY_STORE_PASSWORD).getCertificateChain();
		assumeThat(clientChainExtUsage.length, is(3));

		clientSelfsigned = SslContextUtil.loadCredentials(SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION, "self",
				KEY_STORE_PASSWORD, KEY_STORE_PASSWORD).getCertificateChain();
		assumeThat(clientSelfsigned.length, is(1));

		server = SslContextUtil.loadCredentials(SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION, "server",
				KEY_STORE_PASSWORD, KEY_STORE_PASSWORD).getCertificateChain();
		assumeThat(server.length, is(2));

		serverLarge = SslContextUtil.loadCredentials(SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION, "serverlarge",
				KEY_STORE_PASSWORD, KEY_STORE_PASSWORD).getCertificateChain();
		assumeThat(serverLarge.length, is(3));

		clientChainExtUsageList = Arrays.asList(clientChainExtUsage);
		clientSelfsignedList = Arrays.asList(clientSelfsigned);
		serverLargeList = Arrays.asList(serverLarge);
	}

	@Test
	public void testGenerateCertPath() throws Exception {
		CertPath generateCertPath = CertPathUtil.generateCertPath(clientChainExtUsageList);
		assertEquals(clientChainExtUsageList, generateCertPath.getCertificates());
	}

	@Test
	public void testGenerateTruncatedCertPath() throws Exception {

		List<X509Certificate> truncated = new ArrayList<>(clientChainExtUsageList);
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
		exception.expectMessage("Given certificate is not X.509!");

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
		CertPathUtil.validateCertificatePathWithIssuer(false, certPath, null);
	}

	/**
	 * Certificate-path: server, ca
	 * Trust: "all"
	 * Expected result: pass => server, ca
	 * @throws Exception if an unexpected error occurs
	 */
	@Test
	public void testServerCertificateValidation() throws Exception {
		List<X509Certificate> certificates = TestCertificatesTools.getServerCertificateChainAsList();
		CertPath certPath = CertPathUtil.generateCertPath(certificates);
		CertPath verifiedPath = CertPathUtil.validateCertificatePathWithIssuer(false, certPath, ALL);
		TestCertificatesTools.assertEquals(certificates, verifiedPath.getCertificates());
	}

	/**
	 * Certificate-path: server, ca
	 * Trust: self
	 * Expected result: fail
	 * @throws Exception if an unexpected error occurs
	 */
	@Test
	public void testServerCertificateValidationUnknownTrust() throws Exception {
		exception.expect(CertPathValidatorException.class);
		expectTrustAnchorError();
		List<X509Certificate> serverCertificates = TestCertificatesTools.getServerCertificateChainAsList();
		CertPath certPath = CertPathUtil.generateCertPath(serverCertificates);
		CertPathUtil.validateCertificatePathWithIssuer(false, certPath, clientSelfsigned);
	}

	/**
	 * Certificate-path: server, ca
	 * Trust: root, ca, caalt, carsa, ca2
	 * Expected result: pass => server, ca, root
	 * @throws Exception if an unexpected error occurs
	 */
	@Test
	public void testServerCertificateValidationWithTrust() throws Exception {
		List<X509Certificate> certificates = TestCertificatesTools.getServerCertificateChainAsList();
		List<X509Certificate> verified = new ArrayList<>(certificates);
		verified.add(TestCertificatesTools.getTrustedRootCA());
		CertPath certPath = CertPathUtil.generateCertPath(certificates);
		CertPath verifiedPath = CertPathUtil.validateCertificatePathWithIssuer(false, certPath,
				TestCertificatesTools.getTrustedCertificates());
		TestCertificatesTools.assertEquals(verified, verifiedPath.getCertificates());
	}

	/**
	 * Certificate-path: server, ca
	 * Trust: "first match", root, ca, caalt, carsa, ca2
	 * Expected result: pass => server, ca
	 * @throws Exception if an unexpected error occurs
	 */
	@Test
	public void testServerCertificateValidationTruncatedWithTrust() throws Exception {
		List<X509Certificate> certificates = TestCertificatesTools.getServerCertificateChainAsList();
		CertPath certPath = CertPathUtil.generateCertPath(certificates);
		CertPath verifiedPath = CertPathUtil.validateCertificatePathWithIssuer(true, certPath,
				TestCertificatesTools.getTrustedCertificates());
		TestCertificatesTools.assertEquals(certificates, verifiedPath.getCertificates());
	}

	/**
	 * Certificate-path: serverlarge, ca2, ca
	 * Trust: root, ca, caalt, carsa, ca2
	 * Expected result: pass => serverlarge, ca2, ca, root
	 * @throws Exception if an unexpected error occurs
	 */
	@Test
	public void testServerLargeCertificateValidationWithTrust() throws Exception {
		List<X509Certificate> verified = new ArrayList<>(serverLargeList);
		verified.add(TestCertificatesTools.getTrustedRootCA());
		CertPath certPath = CertPathUtil.generateCertPath(serverLargeList);
		CertPath verifiedPath = CertPathUtil.validateCertificatePathWithIssuer(false, certPath,
				TestCertificatesTools.getTrustedCertificates());
		TestCertificatesTools.assertEquals(verified, verifiedPath.getCertificates());
	}

	/**
	 * Certificate-path: serverlarge, ca2, ca
	 * Trust: "first match", root, ca, caalt, carsa, ca2
	 * Expected result: pass => serverlarge, ca2
	 * @throws Exception if an unexpected error occurs
	 */
	@Test
	public void testServerLargeCertificateValidationTruncatedWithTrust() throws Exception {
		List<X509Certificate> verified = new ArrayList<>();
		verified.add(serverLarge[0]);
		verified.add(serverLarge[1]);
		CertPath certPath = CertPathUtil.generateCertPath(serverLargeList);
		CertPath verifiedPath = CertPathUtil.validateCertificatePathWithIssuer(true, certPath,
				TestCertificatesTools.getTrustedCertificates());
		TestCertificatesTools.assertEquals(verified, verifiedPath.getCertificates());
	}

	/**
	 * Certificate-path: serverlarge, ca2
	 * 1.
	 * Trust: "first match", ca, caalt
	 * Expected result: pass => serverlarge, ca2, ca
	 * 2.
	 * Trust: "first match", caalt, ca
	 * Expected result: pass => serverlarge, ca2, ca
	 * @throws Exception if an unexpected error occurs
	 */
	@Test
	public void testServerLargeCertificateValidationTruncatedWithAmbiguousTrust() throws Exception {
		X509Certificate ca = TestCertificatesTools.getTrustedCA();
		X509Certificate caalt = TestCertificatesTools.getAlternativeCA();
		List<X509Certificate> path = new ArrayList<>();
		path.add(serverLarge[0]);
		path.add(serverLarge[1]);
		List<X509Certificate> verified = new ArrayList<>();
		verified.add(serverLarge[0]);
		verified.add(serverLarge[1]);
		verified.add(ca);
		X509Certificate[] trusts = new X509Certificate[] { ca, caalt };
		CertPath certPath = CertPathUtil.generateCertPath(path);
		CertPath verifiedPath = CertPathUtil.validateCertificatePathWithIssuer(true, certPath, trusts);
		TestCertificatesTools.assertEquals(verified, verifiedPath.getCertificates());

		trusts = new X509Certificate[] { caalt, ca };
		verifiedPath = CertPathUtil.validateCertificatePathWithIssuer(true, certPath, trusts);
		TestCertificatesTools.assertEquals(verified, verifiedPath.getCertificates());
	}

	/**
	 * Certificate-path: server, ca
	 * Trust: "first match", root
	 * Expected result: pass => server, ca, root
	 * @throws Exception if an unexpected error occurs
	 */
	@Test
	public void testServerCertificateValidationWithRootTrust() throws Exception {
		X509Certificate root = TestCertificatesTools.getTrustedRootCA();
		List<X509Certificate> certificates = TestCertificatesTools.getServerCertificateChainAsList();
		X509Certificate[] trusts = new X509Certificate[] { root };
		List<X509Certificate> verified = new ArrayList<>(certificates);
		verified.add(root);
		CertPath certPath = CertPathUtil.generateCertPath(certificates);
		CertPath verifiedPath = CertPathUtil.validateCertificatePathWithIssuer(true, certPath, trusts);
		TestCertificatesTools.assertEquals(verified, verifiedPath.getCertificates());
	}

	/**
	 * Certificate-path: server, ca
	 * Trust: ca
	 * Expected result: fail (ca is not self-signed)
	 * @throws Exception if an unexpected error occurs
	 */
	@Test
	public void testServerCertificateValidationWithIntermediateTrustFails() throws Exception {
		exception.expect(CertPathValidatorException.class);
		expectTrustAnchorError();
		List<X509Certificate> certificates = TestCertificatesTools.getServerCertificateChainAsList();
		X509Certificate[] trusts = new X509Certificate[] { TestCertificatesTools.getTrustedCA() };
		CertPath certPath = CertPathUtil.generateCertPath(certificates);
		CertPathUtil.validateCertificatePathWithIssuer(false, certPath, trusts);
	}

	/**
	 * Certificate-path: server, ca
	 * Trust: "first match", ca
	 * Expected result: pass => server ca
	 * @throws Exception if an unexpected error occurs
	 */
	@Test
	public void testServerCertificateTruncatingValidationWithIntermediateTrust() throws Exception {
		List<X509Certificate> certificates = TestCertificatesTools.getServerCertificateChainAsList();
		X509Certificate[] trusts = new X509Certificate[] { TestCertificatesTools.getTrustedCA() };
		CertPath certPath = CertPathUtil.generateCertPath(certificates);
		CertPath verifiedPath = CertPathUtil.validateCertificatePathWithIssuer(true, certPath, trusts);
		TestCertificatesTools.assertEquals(certificates, verifiedPath.getCertificates());
	}

	/**
	 * Certificate-path: server
	 * 1.
	 * Trust: ca, caalt
	 * Expected result: pass => server, ca
	 * 2.
	 * Trust: caalt, ca
	 * Expected result: pass => server, ca
	 * @throws Exception if an unexpected error occurs
	 */
	@Test
	public void testServerCertificateValidationWithAmbiguousTrust() throws Exception {
		X509Certificate server = TestCertificatesTools.getServerCertificateChain()[0];
		X509Certificate ca = TestCertificatesTools.getTrustedCA();
		X509Certificate caalt = TestCertificatesTools.getAlternativeCA();
		X509Certificate[] path = new X509Certificate[] { server };
		X509Certificate[] trusts = new X509Certificate[] { ca, caalt };
		X509Certificate[] verfied = new X509Certificate[] { server, ca };
		CertPath certPath = CertPathUtil.generateCertPath(Arrays.asList(path));
		CertPath verifiedPath = CertPathUtil.validateCertificatePathWithIssuer(false, certPath, trusts);
		TestCertificatesTools.assertEquals(verfied, verifiedPath.getCertificates());

		X509Certificate[] trusts2 = new X509Certificate[] { caalt, ca };
		verifiedPath = CertPathUtil.validateCertificatePathWithIssuer(false, certPath, trusts2);
		TestCertificatesTools.assertEquals(verfied, verifiedPath.getCertificates());
	}

	/**
	 * Certificate-path: server
	 * 1.
	 * Trust: "first match", ca, caalt
	 * Expected result: pass => server, ca
	 * 2.
	 * Trust: caalt, ca
	 * Expected result: pass => server, ca
	 * @throws Exception if an unexpected error occurs
	 */
	@Test
	public void testServerCertificateTruncatingValidationWithTruncatedAmbiguousTrust() throws Exception {
		X509Certificate server = TestCertificatesTools.getServerCertificateChain()[0];
		X509Certificate ca = TestCertificatesTools.getTrustedCA();
		X509Certificate caalt = TestCertificatesTools.getAlternativeCA();
		X509Certificate[] path = new X509Certificate[] { server };
		X509Certificate[] trusts = new X509Certificate[] { ca, caalt };
		X509Certificate[] verfied = new X509Certificate[] { server, ca };
		CertPath certPath = CertPathUtil.generateCertPath(Arrays.asList(path));
		CertPath verifiedPath = CertPathUtil.validateCertificatePathWithIssuer(true, certPath, trusts);
		TestCertificatesTools.assertEquals(verfied, verifiedPath.getCertificates());

		X509Certificate[] trusts2 = new X509Certificate[] { caalt, ca };
		verifiedPath = CertPathUtil.validateCertificatePathWithIssuer(true, certPath, trusts2);
		TestCertificatesTools.assertEquals(verfied, verifiedPath.getCertificates());
	}

	/**
	 * Certificate-path: server, ca
	 * Trust: server
	 * Expected result: fail (server is not self-signed)
	 * @throws Exception if an unexpected error occurs
	 */
	@Test
	public void testServerCertificateValidationWithSelfTrustFails() throws Exception {
		exception.expect(CertPathValidatorException.class);
		expectTrustAnchorError();
		X509Certificate[] certificates = TestCertificatesTools.getServerCertificateChain();
		X509Certificate[] trusts = new X509Certificate[] {certificates[0]};
		CertPath certPath = CertPathUtil.generateCertPath(Arrays.asList(certificates));
		CertPathUtil.validateCertificatePathWithIssuer(false, certPath, trusts);
	}

	/**
	 * Certificate-path: server, ca
	 * Trust:  "first match", server
	 * Expected result: pass => server
	 * @throws Exception if an unexpected error occurs
	 */
	@Test
	public void testServerCertificateTruncatingValidationWithSelfTrust() throws Exception {
		X509Certificate[] certificates = TestCertificatesTools.getServerCertificateChain();
		X509Certificate[] trusts = new X509Certificate[] {certificates[0]};
		X509Certificate[] verfied = new X509Certificate[] {certificates[0]};
		CertPath certPath = CertPathUtil.generateCertPath(Arrays.asList(certificates));
		CertPath verifiedPath = CertPathUtil.validateCertificatePathWithIssuer(true, certPath, trusts);
		TestCertificatesTools.assertEquals(verfied, verifiedPath.getCertificates());
	}

	/**
	 * Certificate-path: clientext, ca, root
	 * Trust: root, ca, caalt, carsa, ca2
	 * Expected result: pass => clientext, ca, root
	 * 
	 * (clientext-chain includes root!)
	 * @throws Exception if an unexpected error occurs
	 */
	@Test
	public void testClientExtCertificateValidationWithTrust() throws Exception {
		CertPath certPath = CertPathUtil.generateCertPath(clientChainExtUsageList);
		CertPath verifiedPath = CertPathUtil.validateCertificatePathWithIssuer(false, certPath,
				TestCertificatesTools.getTrustedCertificates());
		TestCertificatesTools.assertEquals(clientChainExtUsageList, verifiedPath.getCertificates());
	}

	/**
	 * Certificate-path: server, clientext
	 * Trust: root, ca, caalt, carsa, ca2
	 * Expected result: fail
	 * @throws Exception if an unexpected error occurs
	 */
	@Test
	public void testServerCertificateInvalidPath() throws Exception {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("Given certificates do not form a chain");
		X509Certificate[] certificates = TestCertificatesTools.getServerCertificateChain();
		certificates[1] = clientChainExtUsage[0];
		CertPath certPath = CertPathUtil.generateCertPath(Arrays.asList(certificates));
		CertPathUtil.validateCertificatePathWithIssuer(false, certPath, TestCertificatesTools.getTrustedCertificates());
	}

	/**
	 * Certificate-path: self, ca
	 * Trust: root, ca, caalt, carsa, ca2
	 * Expected result: fail
	 * @throws Exception if an unexpected error occurs
	 */
	@Test
	public void testServerCertificateInvalidPath2() throws Exception {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("Given certificates do not form a chain, root is not the last!");
		X509Certificate[] certificates = TestCertificatesTools.getServerCertificateChain();
		certificates[0] = clientSelfsigned[0];
		CertPath certPath = CertPathUtil.generateCertPath(Arrays.asList(certificates));
		CertPathUtil.validateCertificatePathWithIssuer(false, certPath, TestCertificatesTools.getTrustedCertificates());
	}

	/**
	 * Certificate-path: self
	 * Trust: all
	 * Expected result: pass => self
	 * @throws Exception if an unexpected error occurs
	 */
	@Test
	public void testSelfSignedValidation() throws Exception {
		CertPath certPath = CertPathUtil.generateCertPath(clientSelfsignedList);
		CertPath verifiedPath = CertPathUtil.validateCertificatePathWithIssuer(false, certPath, ALL);
		TestCertificatesTools.assertEquals(clientSelfsignedList, verifiedPath.getCertificates());
	}

	/**
	 * Certificate-path: self
	 * Trust: self
	 * Expected result: pass => self
	 * @throws Exception if an unexpected error occurs
	 */
	@Test
	public void testSelfSignedValidationTrust() throws Exception {
		CertPath certPath = CertPathUtil.generateCertPath(clientSelfsignedList);
		CertPath verifiedPath = CertPathUtil.validateCertificatePathWithIssuer(false, certPath, clientSelfsigned);
		TestCertificatesTools.assertEquals(clientSelfsignedList, verifiedPath.getCertificates());
	}

	/**
	 * Certificate-path: self
	 * Trust: "first match", self
	 * Expected result: pass => self
	 * @throws Exception if an unexpected error occurs
	 */
	@Test
	public void testSelfSignedValidationTruncatedTrust() throws Exception {
		CertPath certPath = CertPathUtil.generateCertPath(clientSelfsignedList);
		CertPath verifiedPath = CertPathUtil.validateCertificatePathWithIssuer(true, certPath, clientSelfsigned);
		TestCertificatesTools.assertEquals(clientSelfsignedList, verifiedPath.getCertificates());
	}

	@Test
	public void testGenerateValidationCertPath() throws Exception {

		List<X509Certificate> truncated = new ArrayList<>(clientChainExtUsageList);
		truncated.remove(truncated.size() - 1);

		CertPath generateCertPath = CertPathUtil.generateValidatableCertPath(clientChainExtUsageList, null);
		TestCertificatesTools.assertEquals(truncated, generateCertPath.getCertificates());
	}

	@Test
	public void testGenerateValidationCertPathForIssuer() throws Exception {
		List<X500Principal> certificateAuthorities = new ArrayList<>();
		certificateAuthorities.add(clientChainExtUsage[1].getSubjectX500Principal());
		List<X509Certificate> truncated = new ArrayList<>(clientChainExtUsageList);
		truncated.remove(truncated.size() - 1);
		truncated.remove(truncated.size() - 1);

		CertPath generateCertPath = CertPathUtil.generateValidatableCertPath(clientChainExtUsageList,
				certificateAuthorities);
		TestCertificatesTools.assertEquals(truncated, generateCertPath.getCertificates());
	}

	@Test
	public void testGenerateValidationCertPathForUnknownIssuer() throws Exception {
		List<X500Principal> certificateAuthorities = new ArrayList<>();
		certificateAuthorities.add(clientSelfsigned[0].getSubjectX500Principal());

		CertPath generateCertPath = CertPathUtil.generateValidatableCertPath(clientChainExtUsageList,
				certificateAuthorities);
		assertEquals(0, generateCertPath.getCertificates().size());
	}

	@Test
	public void testGenerateValidationCertPathForSingleCertificateAndUnknownIssuer() throws Exception {
		List<X509Certificate> path = new ArrayList<>();
		path.add(clientChainExtUsage[0]);
		List<X500Principal> certificateAuthorities = new ArrayList<>();
		certificateAuthorities.add(clientSelfsigned[0].getSubjectX500Principal());

		CertPath generateCertPath = CertPathUtil.generateValidatableCertPath(path, certificateAuthorities);
		assertEquals(0, generateCertPath.getCertificates().size());
	}

	@Test
	public void testGenerateValidationCertPathSelfSigned() throws Exception {

		CertPath generateCertPath = CertPathUtil.generateValidatableCertPath(clientSelfsignedList, null);
		assertEquals(clientSelfsignedList, generateCertPath.getCertificates());
	}

	@Test
	public void testMatchDestination() throws Exception {
		assertTrue(CertPathUtil.matchDestination(serverLarge[0], "cf-serverlarge"));
		assertFalse(CertPathUtil.matchDestination(server[0], "cf-server"));
		assertTrue(CertPathUtil.matchDestination(server[0], "californium.eclipseprojects.io"));
		assertFalse(CertPathUtil.matchDestination(server[0], "foreign.server"));
		assertFalse(CertPathUtil.matchDestination(server[0], "*.server"));
		assertTrue(CertPathUtil.matchLiteralIP(server[0], "127.0.0.1"));
		assertFalse(CertPathUtil.matchLiteralIP(server[0], "127.0.0.2"));
	}

	@Test
	public void testMatchLiteralIP() throws Exception {
		assertTrue(CertPathUtil.matchLiteralIP("127.0.0.1", "127.0.0.1"));
		assertTrue(CertPathUtil.matchLiteralIP("2001::1", "2001:0:0:0:0:0:0:1"));
		assertFalse(CertPathUtil.matchLiteralIP("127.0.0.1", "127.0.0.2"));
		assertFalse(CertPathUtil.matchLiteralIP("2001::2", "2001:0:0:0:0:0:0:1"));
	}
}
