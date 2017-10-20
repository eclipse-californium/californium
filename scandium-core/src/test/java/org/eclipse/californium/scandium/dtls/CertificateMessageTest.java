/*******************************************************************************
 * Copyright (c) 2015 - 2017 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use DtlsTestTools' accessors to explicitly retrieve
 *                                                    client & server keys and certificate chains
 *    Ludwig Seitz (RISE SICS) - Moved verifyCertificate() tests to HandshakerTest
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class CertificateMessageTest {

	CertificateMessage message;
	X509Certificate[] certificateChain;
	X509Certificate[] trustAnchor;
	InetSocketAddress peerAddress;
	byte[] serializedMessage;
	PublicKey serverPublicKey;

	@Before
	public void setUp() throws Exception {
		peerAddress = new InetSocketAddress(InetAddress.getLoopbackAddress(), 5684);
		certificateChain = DtlsTestTools.getServerCertificateChain();
		serverPublicKey = DtlsTestTools.getPublicKey();
		trustAnchor = DtlsTestTools.getTrustedCertificates();
	}

	@Test
	public void testCertificateMessageDoesNotContainRootCert() throws IOException, GeneralSecurityException {
		givenACertificateMessage(DtlsTestTools.getServerCertificateChain(), false);
		assertThatCertificateChainDoesNotContainRootCert(message.getCertificateChain());
	}

	private static void assertThatCertificateChainDoesNotContainRootCert(CertPath chain) {
		X500Principal issuer = null;
		for (Certificate c : chain.getCertificates()) {
			assertThat(c, instanceOf(X509Certificate.class));
			X509Certificate cert = (X509Certificate) c;
			assertThat(cert.getSubjectX500Principal(), is(not(cert.getIssuerX500Principal())));
			if (issuer != null) {
				assertThat(issuer, is(cert.getSubjectX500Principal()));
			}
			issuer = cert.getIssuerX500Principal();
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
	public void testFromByteArrayHandlesEmptyMessageCorrectly() throws HandshakeException {
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
		givenACertificateMessage(DtlsTestTools.getServerCertificateChain(), true);
		PublicKey pk = message.getPublicKey();
		assertNotNull(pk);
		serializedMessage = message.toByteArray();
		CertificateMessage msg = (CertificateMessage) HandshakeMessage.fromByteArray(
				serializedMessage, KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, true, peerAddress);
		assertThat(msg.getPublicKey(), is(pk));
	}

	@Test
	public void testSerializationUsingX509() throws IOException, GeneralSecurityException, HandshakeException {
		givenACertificateMessage(DtlsTestTools.getServerCertificateChain(), false);
		PublicKey pk = message.getPublicKey();
		assertNotNull(pk);
		serializedMessage = message.toByteArray();
		message = (CertificateMessage) HandshakeMessage.fromByteArray(
				serializedMessage, KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, false, peerAddress);
		assertThat(message.getPublicKey(), is(pk));
	}

	private void assertSerializedMessageLength(int length) {
		assertThat(message.getMessageLength(), is(length));
		byte[] serializedMsg = message.fragmentToByteArray();
		assertThat(serializedMsg.length, is(length));
	}
	
	private void givenACertificateMessage(X509Certificate[] chain, boolean useRawPublicKey) throws IOException, GeneralSecurityException {
		certificateChain = chain;
		if (useRawPublicKey) {
			message = new CertificateMessage(chain[0].getPublicKey().getEncoded(), peerAddress);
		} else {
			message = new CertificateMessage(chain, peerAddress);
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
		message = new CertificateMessage(new X509Certificate[]{}, peerAddress);
	}

	private void givenAnEmptyRawPublicKeyCertificateMessage() {
		message = new CertificateMessage(new byte[]{}, peerAddress);
	}
}
