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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - improve handling of empty messages
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix 477074 (erroneous encoding of RPK)
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
import org.eclipse.californium.scandium.util.DatagramReader;
import org.eclipse.californium.scandium.util.DatagramWriter;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class CertificateMessageTest {

	CertificateMessage message;
	Certificate[] certificateChain;
	Certificate[] trustAnchor;
	InetSocketAddress peerAddress;
	byte[] serializedMessage;
	PublicKey serverPublicKey;
	
	@Before
	public void setUp() throws Exception {
		peerAddress = new InetSocketAddress("localhost", 5684);
		certificateChain = DtlsTestTools.getCertificateChainFromStore(
				DtlsTestTools.KEY_STORE_LOCATION,
				DtlsTestTools.KEY_STORE_PASSWORD,
				DtlsTestTools.SERVER_NAME);
		serverPublicKey = certificateChain[0].getPublicKey();
		KeyStore trustStore = DtlsTestTools.loadKeyStore(DtlsTestTools.TRUST_STORE_LOCATION, DtlsTestTools.TRUST_STORE_PASSWORD);
		trustAnchor = new Certificate[trustStore.size()];
		int i = 0;
		for (Enumeration<String> e = trustStore.aliases(); e.hasMoreElements(); ) {
			trustAnchor[i++] = trustStore.getCertificate(e.nextElement());
		}
	}

	@Test
	public void testEmptyCertificateMessageSerialization() {
		
		givenAnEmptyCertificateMessage();
		assertSerializedMessageLength(3);

		givenAnEmptyRawPublicKeyCertificateMessage();
		assertSerializedMessageLength(3);
	}

	@Test
	public void testFromByteArrayHandlesEmptyMessageCorrectly() {
		serializedMessage = new byte[]{0x00, 0x00, 0x00}; // length = 0 (empty message)
		// parse expecting X.509 payload
		message = CertificateMessage.fromByteArray(serializedMessage, false, peerAddress);
		assertSerializedMessageLength(3);

		// parse expecting RawPublicKey payload
		message = CertificateMessage.fromByteArray(serializedMessage, true, peerAddress);
		assertSerializedMessageLength(3);
	}

	/**
	 * Verify that a serialized certificate message containing a raw public key as
	 * specified in RFC 7250 section 3 can be parsed successfully.
	 */
	@Test
	public void testFromByteArrayCompliesWithRfc7250() throws Exception {
		givenASerializedRawPublicKeyCertificateMessage(serverPublicKey);
		message = CertificateMessage.fromByteArray(serializedMessage, true, peerAddress);
		assertThat(message.getPublicKey(), is(serverPublicKey));
	}

	/**
	 * Verify that a certificate message containing a raw public key is serialized
	 * as specified in RFC 7250.
	 */
	@Test
	public void testFragmentToByteArrayCompliesWithRfc7250() throws Exception {
		givenARawPublicKeyCertificateMessage(serverPublicKey);
		serializedMessage = message.fragmentToByteArray();
		assertThatSerializedRawPublicKeyMessageCompliesWithRfc7250();
	}

	private void assertThatSerializedRawPublicKeyMessageCompliesWithRfc7250() {
		long rpkLength = (long) serverPublicKey.getEncoded().length;
		assertThat((long) serializedMessage.length, is(rpkLength + 3));
		
		DatagramReader reader = new DatagramReader(serializedMessage);
		long length = reader.readLong(24);
		assertThat(length, is(rpkLength));
	}

	@Test
	public void testSerializationUsingRawPublicKey() throws IOException, GeneralSecurityException, HandshakeException {
		givenACertificateMessage(DtlsTestTools.SERVER_NAME, true);
		PublicKey pk = message.getPublicKey();
		assertNotNull(pk);
		serializedMessage = message.toByteArray();
		CertificateMessage msg = (CertificateMessage) HandshakeMessage.fromByteArray(
				serializedMessage, KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, true, peerAddress);
		assertThat(msg.getPublicKey(), is(pk));
	}

	@Test
	public void testSerializationUsingX509() throws IOException, GeneralSecurityException, HandshakeException {
		givenACertificateMessage(DtlsTestTools.SERVER_NAME, false);
		PublicKey pk = message.getPublicKey();
		assertNotNull(pk);
		serializedMessage = message.toByteArray();
		message = (CertificateMessage) HandshakeMessage.fromByteArray(
				serializedMessage, KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, false, peerAddress);
		assertThat(message.getPublicKey(), is(pk));
		assertThatCertificateVerificationSucceeds();
	}

	@Test
	public void testVerifyCertificateSucceedsForExampleCertificates() throws IOException, GeneralSecurityException {

		givenACertificateMessage(DtlsTestTools.SERVER_NAME, false);
		assertThatCertificateVerificationSucceeds();

		givenACertificateMessage(DtlsTestTools.CLIENT_NAME, false);
		assertThatCertificateVerificationSucceeds();
	}

	@Test
	public void testVerifyCertificateFailsIfTrustAnchorIsEmpty() throws IOException, GeneralSecurityException {

		givenACertificateMessage(DtlsTestTools.CLIENT_NAME, false);
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

	private void assertSerializedMessageLength(int length) {
		assertThat(message.getMessageLength(), is(length));
		byte[] serializedMsg = message.fragmentToByteArray();
		assertThat(serializedMsg.length, is(length));
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

	private void givenARawPublicKeyCertificateMessage(PublicKey publicKey) {
		message = new CertificateMessage(publicKey.getEncoded(), peerAddress);
	}

	private void givenASerializedRawPublicKeyCertificateMessage(PublicKey publicKey) throws IOException, GeneralSecurityException {
		byte[] rawPublicKey = publicKey.getEncoded();
		DatagramWriter writer = new DatagramWriter();
		writer.writeLong(rawPublicKey.length, 24);
		writer.writeBytes(rawPublicKey);
		serializedMessage = writer.toByteArray();
	}

	private void givenAnEmptyCertificateMessage() {
		message = new CertificateMessage(new Certificate[]{}, peerAddress);
	}

	private void givenAnEmptyRawPublicKeyCertificateMessage() {
		message = new CertificateMessage(new byte[]{}, peerAddress);
	}
}
