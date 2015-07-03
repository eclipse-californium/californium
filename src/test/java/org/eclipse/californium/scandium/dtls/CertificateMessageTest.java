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

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Enumeration;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class CertificateMessageTest {

	CertificateMessage message;
	Certificate[] certificateChain;
	Certificate[] trustAnchor;
	InetSocketAddress peerAddress;
	
	@Before
	public void setUp() throws Exception {
		peerAddress = new InetSocketAddress("localhost", 5684);
		KeyStore trustStore = DtlsTestTools.loadKeyStore(DtlsTestTools.TRUST_STORE_LOCATION, DtlsTestTools.TRUST_STORE_PASSWORD);
		trustAnchor = new Certificate[trustStore.size()];
		int i = 0;
		for (Enumeration<String> e = trustStore.aliases(); e.hasMoreElements(); ) {
			trustAnchor[i++] = trustStore.getCertificate(e.nextElement());
		}
	}

	@Test
	public void testSerializationUsingRawPublicKey() throws IOException, GeneralSecurityException, HandshakeException {
		givenACertificateMessage("server", true);
		PublicKey pk = message.getPublicKey();
		assertNotNull(pk);
		byte[] serialized = message.toByteArray();
		CertificateMessage msg = (CertificateMessage) HandshakeMessage.fromByteArray(
				serialized, KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, true, peerAddress);
		assertThat(msg.getPublicKey(), is(pk));
	}
	
	@Test
	public void testVerifyCertificateSucceedsForExampleCertificates() throws IOException, GeneralSecurityException {

		givenACertificateMessage("server", false);
		assertThatCertificateVerificationSucceeds();
		
		givenACertificateMessage("client", false);
		assertThatCertificateVerificationSucceeds();
	}
	
	@Test
	public void testVerifyCertificateFailsIfTrustAnchorIsEmpty() throws IOException, GeneralSecurityException {

		givenACertificateMessage("client", false);
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
	
	private void givenACertificateMessage(String certChainName, boolean useRawPublicKey) throws IOException, GeneralSecurityException {
		certificateChain = DtlsTestTools.getCertificateChainFromStore(DtlsTestTools.KEY_STORE_LOCATION, DtlsTestTools.KEY_STORE_PASSWORD,
				certChainName);
		if (useRawPublicKey) {
			message = new CertificateMessage(certificateChain[0].getPublicKey().getEncoded(), peerAddress);
		} else {
			message = new CertificateMessage(certificateChain, peerAddress);
		}
	}

}
