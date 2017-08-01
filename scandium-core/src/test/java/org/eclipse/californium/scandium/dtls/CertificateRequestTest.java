/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.CertificateRequest.ClientCertificateType;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm.HashAlgorithm;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm.SignatureAlgorithm;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * Verifies behavior of {@link CertificateRequest}.
 *
 */
@Category(Small.class)
public class CertificateRequestTest {

	private static InetSocketAddress peerAddress = new InetSocketAddress(InetAddress.getLoopbackAddress(), 10000);

	/**
	 * Verifies that an ECDSA key is considered incompatible with the <em>dss_fixed_dh</em> certificate type.
	 * 
	 * @throws Exception if the key cannot be loaded.
	 */
	@Test
	public void testIsSupportedKeyTypeFailsForUnsupportedKeyAlgorithm() throws Exception {

		PublicKey key = DtlsTestTools.getClientPublicKey();
		CertificateRequest req = new CertificateRequest(peerAddress);
		req.addCertificateType(ClientCertificateType.DSS_FIXED_DH);
		assertFalse(req.isSupportedKeyType(key));
	}

	/**
	 * Verifies that an ECDSA key is considered compatible with the <em>ecdsa_sign</em> certificate type.
	 * 
	 * @throws Exception if the key cannot be loaded.
	 */
	@Test
	public void testIsSupportedKeyTypeSucceedsForSupportedKeyAlgorithm() throws Exception {

		PublicKey key = DtlsTestTools.getClientPublicKey();
		CertificateRequest req = new CertificateRequest(peerAddress);
		req.addCertificateType(ClientCertificateType.ECDSA_SIGN);
		assertTrue(req.isSupportedKeyType(key));
	}

	/**
	 * Verifies that a certificate without the <em>digitalSignature</em> key usage is considered incompatible
	 * with a certificate type requiring signing.
	 * 
	 * @throws Exception if the key cannot be loaded.
	 */
	@Test
	public void testIsSupportedKeyTypeFailsForCertWithoutDigitalSignatureKeyUsage() throws Exception {

		X509Certificate cert = DtlsTestTools.getTrustedCertificates()[0];
		CertificateRequest req = new CertificateRequest(peerAddress);
		req.addCertificateType(ClientCertificateType.ECDSA_SIGN);
		assertFalse(req.isSupportedKeyType(cert));
	}

	/**
	 * Verifies that a certificate allowed for the <em>digitalSignature</em> key usage is considered compatible
	 * with a certificate type requiring signing.
	 * 
	 * @throws Exception if the key cannot be loaded.
	 */
	@Test
	public void testIsSupportedKeyTypeSucceedsForCertWithDigitalSignatureKeyUsage() throws Exception {

		X509Certificate cert = DtlsTestTools.getClientCertificateChain()[0];
		CertificateRequest req = new CertificateRequest(peerAddress);
		req.addCertificateType(ClientCertificateType.ECDSA_SIGN);
		assertTrue(req.isSupportedKeyType(cert));
	}

	/**
	 * Verifies that an EC based key is considered incompatible with only non-EC based signature algorithms.
	 * 
	 * @throws Exception if the key cannot be loaded.
	 */
	@Test
	public void testGetSignatureAndHashAlgorithmFailsForNonMatchingSupportedSignatureAlgorithms() throws Exception {

		PublicKey key = DtlsTestTools.getClientPublicKey();
		assertThat(key.getAlgorithm(), is("EC"));
		CertificateRequest req = new CertificateRequest(peerAddress);
		req.addCertificateType(ClientCertificateType.ECDSA_SIGN);
		req.addSignatureAlgorithm(new SignatureAndHashAlgorithm(HashAlgorithm.SHA256, SignatureAlgorithm.RSA));
		req.addSignatureAlgorithm(new SignatureAndHashAlgorithm(HashAlgorithm.MD5, SignatureAlgorithm.DSA));
		req.addSignatureAlgorithm(new SignatureAndHashAlgorithm(HashAlgorithm.NONE, SignatureAlgorithm.ANONYMOUS));
		assertThat(req.getSignatureAndHashAlgorithm(key), is(nullValue()));
	}

	/**
	 * Verifies that an EC based key is considered compatible with a set of signature algorithms containing at least one
	 * EC based algorithm.
	 * 
	 * @throws Exception if the key cannot be loaded.
	 */
	@Test
	public void testGetSignatureAndHashAlgorithmSucceedsForMatchingSupportedSignatureAlgorithms() throws Exception {

		// GIVEN a certificate request preferring an RSA based signature algorithm but also supporting an ECDSA based
		// algorithm
		PublicKey key = DtlsTestTools.getClientPublicKey();
		assertThat(key.getAlgorithm(), is("EC"));
		CertificateRequest req = new CertificateRequest(peerAddress);
		req.addCertificateType(ClientCertificateType.ECDSA_SIGN);
		SignatureAndHashAlgorithm preferredAlgorithm = new SignatureAndHashAlgorithm(HashAlgorithm.SHA256, SignatureAlgorithm.RSA);
		SignatureAndHashAlgorithm ecdsaBasedAlgorithm = new SignatureAndHashAlgorithm(HashAlgorithm.SHA256, SignatureAlgorithm.ECDSA);
		req.addSignatureAlgorithm(preferredAlgorithm);
		req.addSignatureAlgorithm(new SignatureAndHashAlgorithm(HashAlgorithm.NONE, SignatureAlgorithm.ANONYMOUS));
		req.addSignatureAlgorithm(ecdsaBasedAlgorithm);

		// WHEN negotiating the signature algorithm to use with the server
		SignatureAndHashAlgorithm negotiatedAlgorithm = req.getSignatureAndHashAlgorithm(key);

		// THEN the negotiated algorithm is the ECDSA based one
		assertThat(negotiatedAlgorithm, is(ecdsaBasedAlgorithm));
	}

	/**
	 * Verifies that the maximum length of the certificate authorities vector is not exceeded.
	 */
	@Test
	public void testAddCertificateAuthorityAssertsMaxLength() {

		CertificateRequest req = new CertificateRequest(peerAddress);
		X500Principal authority = new X500Principal("O=Eclipse, OU=Hono Project, CN=test");
		int encodedLength = 2 + authority.getEncoded().length;
		int maxLength = (1 << 16) - 1;
		int maxNoOfAuthorities = (int) Math.floor(maxLength / encodedLength);
		for (int i = 0; i < maxNoOfAuthorities; i++) {
			assertTrue(req.addCertificateAuthority(authority));
		}
		// next one should exceed max length
		assertFalse(req.addCertificateAuthority(authority));
	}

	/**
	 * Verifies that a certificate chain is truncated so that it does not include any trusted certificates.
	 * 
	 * @throws Exception if the key cannot be loaded.
	 */
	@Test
	public void testTruncateCertificateChainReturnsNonTrustedCertsOnly() throws Exception {

		// GIVEN a certificate request with a root CA trust anchor
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		X509Certificate[] clientChain = DtlsTestTools.getClientCertificateChain();
		X509Certificate[] trustAnchor = new X509Certificate[1];
		trustAnchor[0] = DtlsTestTools.getTrustedRootCA();
		Set<TrustAnchor> trustAnchors = getTrustAnchors(trustAnchor);
		CertificateRequest req = new CertificateRequest(peerAddress);
		req.addCertificateAuthorities(trustAnchor);

		// WHEN removing trusted certificates from a certificate chain rooting in the trust anchor
		List<X509Certificate> truncatedChain = Arrays.asList(req.removeTrustedCertificates(clientChain));
		CertPath clientPath = factory.generateCertPath(truncatedChain);

		// THEN none of the trust anchors is part of the truncated chain
		for (X509Certificate trustedCert : trustAnchor) {
			if (isCertificatePartOfChain(trustedCert, truncatedChain)) {
				fail("truncated certificate list should not contain any trust anchors");
			}
		}
		// and the truncated chain can still be validated successfully based on the trust anchors
		PKIXParameters params = new PKIXParameters(trustAnchors);
		params.setRevocationEnabled(false);

		CertPathValidator validator = CertPathValidator.getInstance("PKIX");
		validator.validate(clientPath, params);
	}

	/**
	 * Verifies that a certificate chain is not truncated when it consists of untrusted certificates only.
	 *
	 * @throws Exception if the key cannot be loaded.
	 */
	@Test
	public void testTruncateCertificateChainReturnsAllNonTrustedCerts() throws Exception {
		X509Certificate[] certChain = DtlsTestTools.getClientCertificateChain();
		CertificateRequest req = new CertificateRequest(peerAddress);
		X509Certificate[] truncatedChain = req.removeTrustedCertificates(certChain);

		assertTrue(truncatedChain.length == certChain.length);
	}

	private static boolean isCertificatePartOfChain(X509Certificate cert, List<X509Certificate> chain) {
		for (X509Certificate certOfChain : chain) {
			if (cert.getSubjectX500Principal().equals(certOfChain.getSubjectX500Principal())) {
				return true;
			}
		}
		return false;
	}

	private static Set<TrustAnchor> getTrustAnchors(X509Certificate[] trustedCertificates) {
		Set<TrustAnchor> result = new HashSet<>();
		if (trustedCertificates != null) {
			for (X509Certificate cert : trustedCertificates) {
				result.add(new TrustAnchor((X509Certificate) cert, null));
			}
		}
		return result;
	}
}
