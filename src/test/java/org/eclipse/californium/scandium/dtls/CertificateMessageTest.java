/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 469158
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 469593 (validation of peer certificate chain)
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Enumeration;

import org.junit.Before;
import org.junit.Test;

public class CertificateMessageTest {

	CertificateMessage message;
	Certificate[] certificateChain;
	Certificate[] trustAnchor;
	
	@Before
	public void setUp() throws Exception {
		KeyStore trustStore = DtlsTestTools.loadKeyStore(DtlsTestTools.TRUST_STORE_LOCATION, DtlsTestTools.TRUST_STORE_PASSWORD);
		trustAnchor = new Certificate[trustStore.size()];
		int i = 0;
		for (Enumeration<String> e = trustStore.aliases(); e.hasMoreElements(); ) {
			trustAnchor[i++] = trustStore.getCertificate(e.nextElement());
		}
	}

	@Test
	public void testVerifyCertificateSucceedsForExampleCertificates() throws IOException, GeneralSecurityException {

		givenACertificateMessage("server");
		assertThatCertificateVerificationSucceeds();
		
		givenACertificateMessage("client");
		assertThatCertificateVerificationSucceeds();
	}
	
	@Test
	public void testVerifyCertificateFailsIfTrustAnchorIsEmpty() throws IOException, GeneralSecurityException {

		givenACertificateMessage("client");
		assertThatCertificateValidationFailsForEmptyTrustAnchor();
	}
	
	private void assertThatCertificateVerificationSucceeds() {
		try {
			message.verifyCertificate(trustAnchor);
			// all is well
		} catch (HandshakeException e) {
			fail("Verification of certificate should have succeeded");
		}
	}
	
	private void assertThatCertificateValidationFailsForEmptyTrustAnchor() {
		try {
			message.verifyCertificate(null);
			fail("Verification of certificate should have failed");
		} catch (HandshakeException e) {
			// all is well
		}
	}
	
	private void givenACertificateMessage(String certChain) throws IOException, GeneralSecurityException {
		certificateChain = DtlsTestTools.getCertificateChainFromStore(DtlsTestTools.KEY_STORE_LOCATION, DtlsTestTools.KEY_STORE_PASSWORD,
				certChain);
		message = new CertificateMessage(certificateChain);
	}

}
