/*******************************************************************************
 * Copyright (c) 2015, 2016 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - consolidate and fix record buffering and message re-assembly
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use ephemeral ports in endpoint addresses
 *    Kai Hudalla (Bosch Software Innovations GmbH) - derive max fragment length from network MTU
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use DtlsTestTools' accessors to explicitly retrieve
 *                                                    client & server keys and certificate chains
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use SessionListener to trigger sending of pending
 *                                                    APPLICATION messages
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.category.Medium;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateTypeExtension.CertificateType;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.eclipse.californium.scandium.util.ServerNames;
import org.eclipse.californium.scandium.util.ServerName.NameType;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Medium.class)
public class ServerHandshakerTest {

	final static CipherSuite SERVER_CIPHER_SUITE = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256;
	final static int ETHERNET_MTU = 1500;

	static PrivateKey privateKey;
	static X509Certificate[] certificateChain;
	static X509Certificate[] trustedCertificates;

	DtlsConnectorConfig config;
	ServerHandshaker handshaker;
	DTLSSession session;
	InetSocketAddress endpoint;
	byte[] sessionId = new byte[]{(byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F};
	byte[] supportedClientCiphers;
	byte[] random;
	byte[] clientHelloMsg;
	SimpleRecordLayer recordLayer;

	@BeforeClass
	public static void loadKeys() throws IOException, GeneralSecurityException {
		privateKey = DtlsTestTools.getPrivateKey();
		certificateChain = DtlsTestTools.getServerCertificateChain();
		trustedCertificates = DtlsTestTools.getTrustedCertificates();
	}

	@Before
	public void setup() throws Exception {
		endpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
		session = new DTLSSession(endpoint, false);
		recordLayer = new SimpleRecordLayer();
		config = new DtlsConnectorConfig.Builder(endpoint)
				.setIdentity(privateKey, certificateChain, false)
				.setTrustStore(trustedCertificates)
				.setSupportedCipherSuites(new CipherSuite[]{SERVER_CIPHER_SUITE})
				.build();
		handshaker = newHandshaker(config, session);

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
	public void testConstructorAdjustsMaxFragmentSize() throws HandshakeException {
		// given a network interface with standard ethernet MTU (1500 bytes)
		int networkMtu = ETHERNET_MTU;

		// when instantiating a ServerHandshaker to negotiate a new session
		handshaker = new ServerHandshaker(session, recordLayer, null, config, networkMtu);

		// then a fragment created under the session's current write state should
		// fit into a single unfragmented UDP datagram
		assertTrue(session.getMaxDatagramSize() <= networkMtu);
	}

	@Test
	public void testReceiveClientHelloProcessesMaxFragmentLengthExtension() throws Exception {
		// given a server bound to a network interface on an ethernet (MTU 1500 bytes)
		// and a constrained client that can only handle fragments of max 512 bytes
		List<byte[]> extensions = new LinkedList<>();
		extensions.add(DtlsTestTools.newMaxFragmentLengthExtension(1)); // code 1 = 512 bytes

		// when the client sends its CLIENT_HELLO message
		processClientHello(0, extensions);

		// then a fragment created under the session's current write state can
		// not contain more than 512 bytes and the SERVER_HELLO message sent
		// to the client contains a MaxFragmentLength extension indicating a length
		// of 512 bytes
		assertTrue(session.getMaxFragmentLength() <= 512);
		assertThat(recordLayer.getSentFlight(), is(notNullValue()));
		Record record = recordLayer.getSentFlight().getMessages().get(0);
		ServerHello serverHello = (ServerHello) record.getFragment();
		MaxFragmentLengthExtension ext = serverHello.getMaxFragmentLength(); 
		assertThat(ext, is(notNullValue()));
		assertThat(ext.getFragmentLength().length(), is(512));
	}

	/**
	 * Verifies that the server names indicated by a client are stored in the session being negotiated.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testReceiveClientHelloProcessesServerNameExtension() throws Exception {

		// GIVEN a client indicating a host name in its CLIENT_HELLO
		List<byte[]> extensions = new LinkedList<>();
		extensions.add(DtlsTestTools.newServerNameExtension("iot.eclipse.org"));

		// WHEN the client sends its CLIENT_HELLO message
		processClientHello(0, extensions);

		// THEN the server names conveyed in the CLIENT_HELLO message
		// are stored in the handshaker
		ServerNames serverNames = handshaker.getIndicatedServerNames();
		assertNotNull(serverNames);
		assertThat(new String(serverNames.get(NameType.HOST_NAME)), is("iot.eclipse.org"));
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
			assertThat(session.getCipherSuite(), is(CipherSuite.TLS_NULL_WITH_NULL_NULL));
		}
	}

	/**
	 * Verifies that the server considers the certificate types supported by the
	 * client when selecting an appropriate cipher suite. In particular, the server
	 * must not select a certificate based suite if it doesn't support the type of
	 * certificate indicated by the client.
	 */
	@Test
	public void testNegotiateCipherSuiteConsidersSupportedCertType() throws Exception {

		// GIVEN a server handshaker that supports a public key based cipher using RawPublicKeys
		// only as well as a pre-shared key based cipher
		config = new DtlsConnectorConfig.Builder(endpoint)
				.setIdentity(privateKey, DtlsTestTools.getPublicKey())
				.setSupportedCipherSuites(new CipherSuite[]{
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
						CipherSuite.TLS_PSK_WITH_AES_128_CCM_8})
				.setPskStore(new StaticPskStore("client", "secret".getBytes()))
				.build();
		handshaker = newHandshaker(config, session);

		// WHEN a client sends a hello message indicating that it only supports X.509 certs
		// but offering both a public key based as well as a pre-shared key based cipher
		// supported by the server
		supportedClientCiphers = new byte[]{(byte) 0xC0, (byte) 0xAE, // TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
																				(byte) 0xC0, (byte) 0xA8};// TLS_PSK_WITH_AES_128_CCM_8
		List<byte[]> extensions = new LinkedList<>();
		SupportedGroup supportedGroup = getArbitrarySupportedGroup();
		extensions.add(DtlsTestTools.newSupportedEllipticCurvesExtension(supportedGroup.getId()));

		processClientHello(0, extensions);

		// THEN the server selects the PSK based cipher because it does not consider the public
		// key based cipher a valid option due to the client's lacking support for RPKs
		assertThat(session.getCipherSuite(), is(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8));
		assertThat(handshaker.getNegotiatedServerCertificateType(), is(nullValue()));
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
			assertThat(session.getCipherSuite(), is(CipherSuite.TLS_NULL_WITH_NULL_NULL));
			assertThat(handshaker.getNegotiatedClientCertificateType(), is(nullValue()));
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
			assertThat(session.getCipherSuite(), is(CipherSuite.TLS_NULL_WITH_NULL_NULL));
			assertThat(handshaker.getNegotiatedClientCertificateType(), is(nullValue()));
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
		assertThat(session.getCipherSuite(), is(SERVER_CIPHER_SUITE));
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
			assertThat(session.getCipherSuite(), is(CipherSuite.TLS_NULL_WITH_NULL_NULL));
			assertThat(handshaker.getNegotiatedServerCertificateType(), is(nullValue()));
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
			assertThat(session.getCipherSuite(), is(CipherSuite.TLS_NULL_WITH_NULL_NULL));
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
		assertThat(session.getCipherSuite(), is(SERVER_CIPHER_SUITE));
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
		assertThat(session.getCipherSuite(), is(SERVER_CIPHER_SUITE));
		assertThat(handshaker.getNegotiatedSupportedGroup(), notNullValue());
	}

	@Test
	public void testDoProcessMessageProcessesQueuedMessages() throws Exception {
		Record nextRecord = givenAHandshakerWithAQueuedMessage();
		handshaker.processMessage(nextRecord);
		assertThatAllMessagesHaveBeenProcessedInOrder();
	}

	private ServerHandshaker newHandshaker(final DtlsConnectorConfig config, final DTLSSession session) throws HandshakeException {
		return new ServerHandshaker(session, recordLayer, null, config, ETHERNET_MTU);
	}

	private Record givenAHandshakerWithAQueuedMessage() throws Exception {

		InetSocketAddress senderAddress = new InetSocketAddress(5000);
		processClientHello(0, null);
		assertThat(handshaker.getNextReceiveSeq(), is(1));
		// create client CERTIFICATE msg
		X509Certificate[] clientChain = DtlsTestTools.getClientCertificateChain();
		CertificateMessage certificateMsg = new CertificateMessage(clientChain, endpoint);
		certificateMsg.setMessageSeq(1);
		Record certificateMsgRecord = getRecordForMessage(0, 1, certificateMsg, senderAddress);

		// create client KEY_EXCHANGE msg
		ECDHClientKeyExchange keyExchangeMsg = new ECDHClientKeyExchange(clientChain[0].getPublicKey(), endpoint);
		keyExchangeMsg.setMessageSeq(2);
		Record keyExchangeRecord = getRecordForMessage(0, 2, keyExchangeMsg, senderAddress);

		// put KEY_EXCHANGE message with seq no. 2 to inbound message queue 
		handshaker.processMessage(keyExchangeRecord);
		assertThat(handshaker.clientKeyExchange, nullValue());
		assertFalse("Client's KEY_EXCHANGE message should have been queued",
				handshaker.inboundMessageBuffer.isEmpty());

		return certificateMsgRecord;
	}

	private void assertThatAllMessagesHaveBeenProcessedInOrder() {
		assertThat(handshaker.getNextReceiveSeq(), is(3));
		assertThat("Client's CERTIFICATE message should have been processed",
				handshaker.clientCertificate, notNullValue());
		assertThat("Client's KEY_EXCHANGE message should have been processed",
				handshaker.clientKeyExchange, notNullValue());
		assertTrue("All (processed) messages should have been removed from inbound messages queue",
				handshaker.inboundMessageBuffer.isEmpty());

	}

	private void processClientHello(int messageSeq, List<byte[]> helloExtensions) throws HandshakeException {

		processClientHello(0, 0, messageSeq, null, supportedClientCiphers, helloExtensions);
	}

	private void processClientHello(int epoch, long sequenceNo, int messageSeq, byte[] cookie,
			byte[] supportedCiphers, List<byte[]> helloExtensions) throws HandshakeException {

		byte[] clientHelloFragment = newClientHelloFragment(cookie, supportedCiphers, helloExtensions);
		clientHelloMsg = newHandshakeMessage(HandshakeType.CLIENT_HELLO, messageSeq, clientHelloFragment);
		byte[] dtlsRecord = DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), epoch,
				sequenceNo, clientHelloMsg);
		List<Record> list = Record.fromByteArray(dtlsRecord, endpoint);
		assertFalse("Should be able to deserialize DTLS Record from byte array", list.isEmpty());
		Record record = list.get(0);
		handshaker.processMessage(record);
	}

	private static byte[] newHandshakeMessage(HandshakeType type, int messageSeq, byte[] fragment) {
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

	private static Record getRecordForMessage(int epoch, int seqNo, DTLSMessage msg, InetSocketAddress peer) {
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
	private static SupportedGroup getArbitrarySupportedGroup() {
		List<SupportedGroup> supportedGroups = SupportedGroup.getPreferredGroups();
		if (!supportedGroups.isEmpty()) {
			return supportedGroups.get(0);
		} else {
			return SupportedGroup.secp256r1;
		}
	}
}
