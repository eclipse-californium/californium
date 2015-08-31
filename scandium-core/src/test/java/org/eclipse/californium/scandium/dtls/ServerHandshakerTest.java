/*******************************************************************************
 * Copyright (c) 2014, 2015 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 464383
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add test case for validating fix for bug 473678
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.CertificateTypeExtension.CertificateType;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.util.DatagramWriter;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class ServerHandshakerTest {

	final static CipherSuite SERVER_CIPHER_SUITE = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256;

	static PrivateKey privateKey;
	static Certificate[] certificateChain;
	ServerHandshaker handshaker;
	DTLSSession session;
	InetSocketAddress endpoint = InetSocketAddress.createUnresolved("localhost", 10000);
	byte[] sessionId = new byte[]{(byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F};
	byte[] supportedClientCiphers;
	byte[] random;
	byte[] clientHelloMsg;
	
	@BeforeClass
	public static void loadKeys() throws IOException, GeneralSecurityException {
		privateKey = DtlsTestTools.getPrivateKey();
		certificateChain = DtlsTestTools.getCertificateChainFromStore(
				DtlsTestTools.KEY_STORE_LOCATION, DtlsTestTools.KEY_STORE_PASSWORD, "server");
	}
	
	@Before
	public void setup() throws Exception {
		KeyStore trustStore = DtlsTestTools.loadKeyStore(DtlsTestTools.TRUST_STORE_LOCATION, DtlsTestTools.TRUST_STORE_PASSWORD);
		Certificate[] trustedCertificates = new Certificate[trustStore.size()];
		int j = 0;
		for (Enumeration<String> e = trustStore.aliases(); e.hasMoreElements(); ) {
			trustedCertificates[j++] = trustStore.getCertificate(e.nextElement());
		}
		
		session = new DTLSSession(endpoint, false);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(endpoint);
		builder.setIdentity(privateKey, certificateChain, false)
			.setTrustStore(trustedCertificates)
			.setSupportedCipherSuites(new CipherSuite[]{SERVER_CIPHER_SUITE});
		handshaker = new ServerHandshaker(session, null, builder.build());

		DatagramWriter writer = new DatagramWriter();
		// uint32 gmt_unix_time
		Date now = new Date();
		writer.writeLong(Math.round(now.getTime() / 1000), 32);
		// opaque random_bytes[28]
		for (int i = 0; i < 28; i++) {
			writer.write(i, 8);
		}
		random = writer.toByteArray();

		// ciphers supported by client
		supportedClientCiphers = new byte[]{
				(byte) 0xFF, (byte) 0xA8, // fantasy cipher (non-existent)
				(byte) 0xC0, (byte) 0xA8, // TLS_PSK_WITH_AES_128_CCM_8
				(byte) 0xC0, (byte) 0x23};// TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
	}

	@Test
	public void testReceiveClientHelloIncludesUnknownCiphersInHandshakeHashGeneration() throws HandshakeException {

		List<byte[]> extensions = new LinkedList<>();
		extensions.add(DtlsTestTools.newSupportedEllipticCurvesExtension(getArbitrarySupportedGroup().getId()));

		processClientHello(0, extensions);

		byte[] loggedMsg = new byte[clientHelloMsg.length];
		// copy the received ClientHello message from the handshakeMessages buffer
		System.arraycopy(handshaker.handshakeMessages, 0, loggedMsg, 0, clientHelloMsg.length);
		// and verify that it is equal to the original ClientHello message
		// sent by the client
		assertArrayEquals(clientHelloMsg, loggedMsg);
	}

	@Test
	public void testReceiveClientHelloDoesNotNegotiateNullCipher() throws HandshakeException {

		supportedClientCiphers = new byte[]{(byte) 0x00, (byte) 0x00}; // TLS_NULL_WITH_NULL_NULL

		try {
			// process Client Hello including Cookie
			processClientHello(0, null);
			fail("Server should have aborted cipher negotiation");
		} catch (HandshakeException e) {
			// server has aborted handshake as required
			assertEquals(AlertMessage.AlertLevel.FATAL, e.getAlert().getLevel());
			assertThat(handshaker.getCipherSuite(), nullValue());
		}
	}

	@Test
	public void testReceiveClientHelloAbortsOnUnknownClientCertificateType() throws HandshakeException {

		List<byte[]> extensions = new LinkedList<>();
		// certificate type 0x05 is not defined by IANA
		extensions.add(DtlsTestTools.newClientCertificateTypesExtension(0x05));

		try {
			processClientHello(0, extensions);
			fail("Should have thrown " + HandshakeException.class.getSimpleName());
		} catch (HandshakeException e) {
			assertThat(handshaker.getCipherSuite(), is(SERVER_CIPHER_SUITE));
			assertThat(handshaker.getNegotiatedClientCertificateType(), nullValue());
		}
	}

	@Test
	public void testReceiveClientHelloAbortsOnNonMatchingClientCertificateTypes() {
		List<byte[]> extensions = new LinkedList<>();
		// certificate type OpenPGP is not supported by Scandium
		extensions.add(DtlsTestTools.newClientCertificateTypesExtension(
				CertificateType.OPEN_PGP.getCode()));

		try {
			processClientHello(0, extensions);
			fail("Should have thrown " + HandshakeException.class.getSimpleName());
		} catch(HandshakeException e) {
			// check if handshake has been aborted due to unsupported certificate
			assertEquals(AlertDescription.UNSUPPORTED_CERTIFICATE, e.getAlert().getDescription());
			assertThat(handshaker.getCipherSuite(), is(SERVER_CIPHER_SUITE));
			assertThat(handshaker.getNegotiatedClientCertificateType(), nullValue());
		}
	}

	@Test
	public void testReceiveClientHelloNegotiatesSupportedCertificateType() throws Exception {

		List<byte[]> extensions = new LinkedList<>();
		extensions.add(DtlsTestTools.newSupportedEllipticCurvesExtension(getArbitrarySupportedGroup().getId()));
		// certificate type OpenPGP is not supported
		// certificate type X.509 is supported
		extensions.add(DtlsTestTools.newClientCertificateTypesExtension(
				CertificateType.OPEN_PGP.getCode(), CertificateType.X_509.getCode()));

		processClientHello(0, extensions);
		assertThat(handshaker.getCipherSuite(), is(SERVER_CIPHER_SUITE));
		assertThat(handshaker.getNegotiatedClientCertificateType(), is(CertificateType.X_509));
		assertThat(handshaker.getNegotiatedServerCertificateType(), is(CertificateType.X_509));
	}

	@Test
	public void testReceiveClientHelloAbortsOnUnknownServerCertificateType() throws HandshakeException {
		List<byte[]> extensions = new LinkedList<>();
		// certificate type 0x05 is not defined by IANA
		extensions.add(DtlsTestTools.newServerCertificateTypesExtension(0x05));

		try {
			processClientHello(0, extensions);
			fail("Should have thrown " + HandshakeException.class.getSimpleName());
		} catch(HandshakeException e) {
			// check if handshake has been aborted due to unsupported certificate
			assertEquals(AlertDescription.UNSUPPORTED_CERTIFICATE, e.getAlert().getDescription());
			assertThat(handshaker.getCipherSuite(), is(SERVER_CIPHER_SUITE));
			assertThat(handshaker.getNegotiatedServerCertificateType(), nullValue());
		}
	}

	@Test
	public void testReceiveClientHelloAbortsOnUnsupportedEcCurveIds() throws HandshakeException {

		List<byte[]> extensions = new LinkedList<>();
		// curveId 0x0000 is not assigned by IANA
		extensions.add(DtlsTestTools.newSupportedEllipticCurvesExtension(0x0000));
		try {
			processClientHello(0, extensions);
			fail("Should have thrown " + HandshakeException.class.getSimpleName());
		} catch(HandshakeException e) {
			assertThat(handshaker.getCipherSuite(), nullValue());
			assertThat(handshaker.getNegotiatedSupportedGroup(), nullValue());
		}
	}

	@Test()
	public void testReceiveClientHelloNegotiatesSupportedEcCurveId() throws HandshakeException {

		List<byte[]> extensions = new LinkedList<>();
		SupportedGroup supportedGroup = getArbitrarySupportedGroup();
		// curveId 0x0000 is not assigned by IANA
		extensions.add(DtlsTestTools.newSupportedEllipticCurvesExtension(0x0000, supportedGroup.getId()));
		processClientHello(0, extensions);
		assertThat(handshaker.getCipherSuite(), is(SERVER_CIPHER_SUITE));
		assertThat(handshaker.getNegotiatedSupportedGroup(), is(supportedGroup));
	}

	/**
	 * Fix 473678.
	 * 
	 * Assert that handshaker picks an arbitrary supported group if client omits
	 * <em>Supported Elliptic Curves Extension</em>.
	 */
	@Test()
	public void testReceiveClientHelloPicksCurveIfClientOmitsSupportedCurveExtension() throws HandshakeException {

		// omit supported elliptic curves extension
		processClientHello(0, null);
		assertThat(handshaker.getCipherSuite(), is(SERVER_CIPHER_SUITE));
		assertThat(handshaker.getNegotiatedSupportedGroup(), notNullValue());
	}


	@Test
	public void testDoProcessMessageProcessesQueuedMessages() throws Exception {
		Record nextRecord = givenAHandshakerWithAQueuedMessage();
		handshaker.processMessage(nextRecord);
		assertThatAllMessagesHaveBeenProcessedInOrder();
	}

	private Record givenAHandshakerWithAQueuedMessage() throws Exception {

		InetSocketAddress senderAddress = new InetSocketAddress(5000);
		processClientHello(0, null);
		assertThat(handshaker.getNextReceiveSeq(), is(1));
		// create client CERTIFICATE msg
		Certificate[] clientChain = DtlsTestTools.getCertificateChainFromStore(
				DtlsTestTools.KEY_STORE_LOCATION,
				DtlsTestTools.KEY_STORE_PASSWORD,
				"client");
		CertificateMessage certificateMsg = new CertificateMessage(clientChain, endpoint);
		certificateMsg.setMessageSeq(1);
		Record certificateMsgRecord = getRecordForMessage(0, 1, certificateMsg, senderAddress);
		
		// create client KEY_EXCHANGE msg
		ECDHClientKeyExchange keyExchangeMsg = new ECDHClientKeyExchange(
				clientChain[0].getPublicKey(), endpoint);
		keyExchangeMsg.setMessageSeq(2);
		Record keyExchangeRecord = getRecordForMessage(0, 2, keyExchangeMsg, senderAddress);

		handshaker.processMessage(keyExchangeRecord);
		assertThat(handshaker.clientKeyExchange, nullValue());
		assertFalse("Client's KEY_EXCHANGE message should have been queued",
				handshaker.queuedMessages.isEmpty());
		return certificateMsgRecord;
	}
	
	private void assertThatAllMessagesHaveBeenProcessedInOrder() {
		assertThat(handshaker.getNextReceiveSeq(), is(3));
		assertThat("Client's CERTIFICATE message should have been processed",
				handshaker.clientCertificate, notNullValue());
		assertThat("Client's KEY_EXCHANGE message should have been processed",
				handshaker.clientKeyExchange, notNullValue());
		assertTrue("All (processed) messages should have been removed from inbound messages queue",
				handshaker.queuedMessages.isEmpty());

	}

	private DTLSFlight processClientHello(int messageSeq, List<byte[]> helloExtensions) throws HandshakeException {

		return processClientHello(0, 0, messageSeq, null, supportedClientCiphers, helloExtensions);
	}

	private DTLSFlight processClientHello(int epoch, long sequenceNo, int messageSeq, byte[] cookie,
			byte[] supportedCiphers, List<byte[]> helloExtensions) throws HandshakeException {

		byte[] clientHelloFragment = newClientHelloFragment(cookie, supportedCiphers, helloExtensions);
		clientHelloMsg = newHandshakeMessage(HandshakeType.CLIENT_HELLO, messageSeq, clientHelloFragment);
		byte[] dtlsRecord = DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), epoch,
				sequenceNo, clientHelloMsg);
		List<Record> list = Record.fromByteArray(dtlsRecord, endpoint);
		assertFalse("Should be able to deserialize DTLS Record from byte array", list.isEmpty());
		Record record = list.get(0);
		return handshaker.processMessage(record);
	}

	private byte[] newHandshakeMessage(HandshakeType type, int messageSeq, byte[] fragment) {
		int length = 8 + 24 + 16 + 24 + 24 + fragment.length;
		DatagramWriter writer = new DatagramWriter();
		writer.write(type.getCode(), 8);
		writer.write(length, 24);
		writer.write(messageSeq, 16);
		writer.write(0, 24); // fragment offset is always 0
		writer.write(length, 24);
		writer.writeBytes(fragment);
		return writer.toByteArray();
	}

	/**
	 * Creates a ClientHello message as defined by
	 * <a href="http://tools.ietf.org/html/rfc5246#page-39">Client Hello</a>
	 * 
	 * @return the bytes of the message
	 */
	private byte[] newClientHelloFragment(byte[] cookie, byte[] supportedCipherSuites,
			List<byte[]> helloExtensions) {
		DatagramWriter writer = new DatagramWriter();
		// Protocol version (DTLS 1.2)
		writer.write(254, 8);
		writer.write(253, 8);

		writer.writeBytes(random);

		// Session ID
		writer.write(sessionId.length, 8);
		writer.writeBytes(sessionId);

		// write cookie
		if (cookie == null) {
			writer.write(0,  8);
		} else {
			writer.write(cookie.length, 8);
			writer.writeBytes(cookie);
		}

		// supported Cipher Suites
		writer.write(supportedCipherSuites.length, 16);
		writer.writeBytes(supportedCipherSuites);

		// a single compression method is supported
		writer.write(1, 8);
		writer.writeByte((byte) 0x00); // compression method "null"

		if (helloExtensions != null && !helloExtensions.isEmpty()) {
			DatagramWriter extensionsWriter = new DatagramWriter();
			for (byte[] extension : helloExtensions) {
				extensionsWriter.writeBytes(extension);
			}
			byte[] extBytes = extensionsWriter.toByteArray();
			writer.write(extBytes.length, 16);
			writer.writeBytes(extBytes);
		}
		return writer.toByteArray();
	}

	private Record getRecordForMessage(int epoch, int seqNo, HandshakeMessage msg, InetSocketAddress peer) {
		byte[] dtlsRecord = DtlsTestTools.newDTLSRecord(msg.getContentType().getCode(), epoch,
				seqNo, msg.toByteArray());
		List<Record> list = Record.fromByteArray(dtlsRecord, peer);
		assertFalse("Should be able to deserialize DTLS Record from byte array", list.isEmpty());
		return list.get(0);
	}

	/**
	 * Gets an arbitrary <code>SupportedGroup</code> implemented by the JRE's
	 * cryptography provider(s).
	 * 
	 * @return the group
	 */
	private SupportedGroup getArbitrarySupportedGroup() {
		List<SupportedGroup> supportedGroups = SupportedGroup.getPreferredGroups();
		if (!supportedGroups.isEmpty()) {
			return supportedGroups.get(0);
		} else {
			return SupportedGroup.secp256r1;
		}
	}
}
