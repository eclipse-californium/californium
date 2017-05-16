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

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

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
	 * Verifies that an EC based key is considered incompatible with non-EC based signature algorithms.
	 * 
	 * @throws Exception if the key cannot be loaded.
	 */
	@Test
	public void testGetSignatureAndHashAlgorithmFailsForNonMatchingSupportedSignatureAlgorithms() throws Exception {

		PublicKey key = DtlsTestTools.getClientPublicKey();
		CertificateRequest req = new CertificateRequest(peerAddress);
		req.addCertificateType(ClientCertificateType.ECDSA_SIGN);
		req.addSignatureAlgorithm(new SignatureAndHashAlgorithm(HashAlgorithm.SHA256, SignatureAlgorithm.RSA));
		assertThat(req.getSignatureAndHashAlgorithm(key), is(nullValue()));
	}

	/**
	 * Verifies that an EC based key is considered incompatible with an EC based signature algorithms.
	 * 
	 * @throws Exception if the key cannot be loaded.
	 */
	@Test
	public void testGetSignatureAndHashAlgorithmSucceedsForMatchingSupportedSignatureAlgorithms() throws Exception {

		PublicKey key = DtlsTestTools.getClientPublicKey();
		CertificateRequest req = new CertificateRequest(peerAddress);
		req.addCertificateType(ClientCertificateType.ECDSA_SIGN);
		SignatureAndHashAlgorithm matchingAlgorithm = new SignatureAndHashAlgorithm(HashAlgorithm.SHA256, SignatureAlgorithm.ECDSA);
		req.addSignatureAlgorithm(new SignatureAndHashAlgorithm(HashAlgorithm.SHA256, SignatureAlgorithm.RSA));
		req.addSignatureAlgorithm(matchingAlgorithm);
		assertThat(req.getSignatureAndHashAlgorithm(key), is(matchingAlgorithm));
	}

	/**
	 * Verifies that a certificate chain is truncated so that it does not include any trusted certificates.
	 * 
	 * @throws Exception if the key cannot be loaded.
	 */
	@Test
	public void testTruncateCertificateChainReturnsNonTrustedCertsOnly() throws Exception {

		X509Certificate[] clientChain = DtlsTestTools.getClientCertificateChain();
		X509Certificate[] trustAnchor = DtlsTestTools.getTrustedCertificates();
		X509Certificate trustedCertToRemove = null;

		for (X509Certificate trustedCert : trustAnchor) {
			if (isCertificatePartOfChain(trustedCert, clientChain)) {
				trustedCertToRemove = trustedCert;
				break;
			}
		}
		assertThat(trustedCertToRemove, is(notNullValue()));

		CertificateRequest req = new CertificateRequest(peerAddress);
		req.addCertificateAuthorities(trustAnchor);
		X509Certificate[] truncatedChain = req.removeTrustedCertificates(clientChain);
		assertTrue(truncatedChain.length < clientChain.length);
		assertFalse(isCertificatePartOfChain(trustedCertToRemove, truncatedChain));
	}

	private static boolean isCertificatePartOfChain(X509Certificate cert, X509Certificate[] chain) {
		for (X509Certificate certOfChain : chain) {
			if (cert.getSubjectX500Principal().equals(certOfChain.getSubjectX500Principal())) {
				return true;
			}
		}
		return false;
	}
}
