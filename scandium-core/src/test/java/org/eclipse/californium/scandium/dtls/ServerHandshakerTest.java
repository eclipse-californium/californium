/*******************************************************************************
 * Copyright (c) 2015, 2016 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - report expired certificates
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.rule.ThreadsRule;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.TestScheduledExecutorService;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedSinglePskStore;
import org.eclipse.californium.scandium.dtls.x509.NewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.StaticNewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.util.ServerName.NameType;
import org.eclipse.californium.scandium.util.ServerNames;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Medium.class)
public class ServerHandshakerTest {

	final static CipherSuite SERVER_CIPHER_SUITE = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
	final static int ETHERNET_MTU = 1500;

	static PrivateKey privateKey;
	static X509Certificate[] certificateChain;
	static X509Certificate[] trustedCertificates;

	@Rule
	public ThreadsRule cleanup = new ThreadsRule();

	DtlsConnectorConfig config;
	ServerHandshaker handshaker;
	DTLSSession session;
	InetSocketAddress endpoint;
	byte[] sessionId = new byte[]{(byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F};
	byte[] supportedClientCiphers;
	byte[] random;
	byte[] clientHelloMsg;
	SimpleRecordLayer recordLayer;
	ScheduledExecutorService timer;

	@BeforeClass
	public static void loadKeys() throws IOException, GeneralSecurityException {
		privateKey = DtlsTestTools.getPrivateKey();
		certificateChain = DtlsTestTools.getServerCertificateChain();
		trustedCertificates = DtlsTestTools.getTrustedCertificates();
	}

	@Before
	public void setup() throws Exception {
		timer = new TestScheduledExecutorService();
		endpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
		session = new DTLSSession(endpoint);
		recordLayer = new SimpleRecordLayer();
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustedCertificates(trustedCertificates).build();
		config = DtlsConnectorConfig.builder()
				.setAddress(endpoint)
				.setSniEnabled(true)
				.setIdentity(privateKey, certificateChain, CertificateType.X_509)
				.setAdvancedCertificateVerifier(verifier)
				.setSupportedCipherSuites(SERVER_CIPHER_SUITE)
				.build();
		handshaker = newHandshaker(config, session);

		DatagramWriter writer = new DatagramWriter();
		// uint32 gmt_unix_time
		writer.writeLong(System.currentTimeMillis() / 1000, 32);
		// opaque random_bytes[28]
		for (int i = 0; i < 28; i++) {
			writer.write(i, 8);
		}
		random = writer.toByteArray();

		// ciphers supported by client
		supportedClientCiphers = new byte[]{
				(byte) 0xFF, (byte) 0xA8, // fantasy cipher (non-existent)
				(byte) 0xC0, (byte) 0xA8, // TLS_PSK_WITH_AES_128_CCM_8
				(byte) 0xC0, (byte) 0xAE, // TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
				(byte) 0xC0, (byte) 0x23};// TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
	}

	@After
	public void tearDown() {
		timer.shutdown();
		timer = null;
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
		Record record = recordLayer.getSentFlight().get(0);
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
		ServerNames serverNames = handshaker.getSession().getServerNames();
		assertNotNull(serverNames);
		assertThat(new String(serverNames.get(NameType.HOST_NAME)), is("iot.eclipse.org"));
	}

	@Test
	public void testReceiveClientHelloIncludesUnknownCiphersInHandshakeHashGeneration() throws Exception {

		List<byte[]> extensions = new LinkedList<>();
		extensions.add(DtlsTestTools.newSupportedEllipticCurvesExtension(getArbitrarySupportedGroup().getId()));

		processClientHello(0, extensions);

		// access the received ClientHello message from the handshakeMessages buffer
		byte[] receivedMsg = handshaker.handshakeMessages.get(0).toByteArray();
		// and verify that it is equal to the original ClientHello message
		// sent by the client
		assertArrayEquals(clientHelloMsg, receivedMsg);
	}

	@Test
	public void testReceiveClientHelloDoesNotNegotiateNullCipher() throws Exception {

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
		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build();
		config = DtlsConnectorConfig.builder()
				.setAddress(endpoint)
				.setIdentity(privateKey, DtlsTestTools.getPublicKey())
				.setSupportedCipherSuites(
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
						CipherSuite.TLS_PSK_WITH_AES_128_CCM_8)
				.setAdvancedPskStore(new AdvancedSinglePskStore("client", "secret".getBytes()))
				.setAdvancedCertificateVerifier(verifier)
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
	public void testReceiveClientHelloAbortsOnUnknownClientCertificateType() throws Exception {

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
	public void testReceiveClientHelloAbortsOnNonMatchingClientCertificateTypes() throws Exception {
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
	public void testReceiveClientHelloAbortsOnUnknownServerCertificateType() throws Exception {
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
	public void testReceiveClientHelloAbortsOnUnsupportedEcCurveIds() throws Exception {

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
	public void testReceiveClientHelloNegotiatesSupportedEcCurveId() throws Exception {

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
	public void testReceiveClientHelloPicksCurveIfClientOmitsSupportedCurveExtension() throws Exception {

		// omit supported elliptic curves extension
		processClientHello(0, null);
		assertThat(session.getCipherSuite(), is(SERVER_CIPHER_SUITE));
		assertThat(handshaker.getNegotiatedSupportedGroup(), notNullValue());
	}

	@Test
	public void testDoProcessMessageProcessesQueuedMessages() throws Exception {
		Record nextRecord = givenAHandshakerWithAQueuedMessage();
		try {
			nextRecord.applySession(handshaker.getSession());
			handshaker.processMessage(nextRecord);
		} catch (HandshakeException e) {
			HandshakerTest.failedHandshake(e);
		}
		assertThatAllMessagesHaveBeenProcessedInOrder();
	}

	private ServerHandshaker newHandshaker(final DtlsConnectorConfig config, final DTLSSession session) throws HandshakeException {
		Connection connection = new Connection(session.getPeer(), new SyncSerialExecutor());
		connection.setConnectionId(new ConnectionId(new byte[] { 1, 2, 3, 4 }));
		ServerHandshaker handshaker =  new ServerHandshaker(0, session, recordLayer, timer, connection, config);
		recordLayer.setHandshaker(handshaker);
		return handshaker;
	}

	private Record givenAHandshakerWithAQueuedMessage() throws Exception {

		InetSocketAddress senderAddress = new InetSocketAddress(5000);
		processClientHello(0, null);
		assertThat(handshaker.getNextReceiveMessageSequenceNumber(), is(1));
		// create client CERTIFICATE msg
		X509Certificate[] clientChain = DtlsTestTools.getClientCertificateChain();
		CertificateMessage certificateMsg = new CertificateMessage(Arrays.asList(clientChain), endpoint);
		certificateMsg.setMessageSeq(1);
		Record certificateMsgRecord =  DtlsTestTools.getRecordForMessage(0, 1, certificateMsg, senderAddress);

		// create client KEY_EXCHANGE msg
		SupportedGroup supportedGroup = XECDHECryptography.SupportedGroup.getPreferredGroups().get(0);
		XECDHECryptography ecdhe = new XECDHECryptography(supportedGroup);
		byte[] encoded = ecdhe.getEncodedPoint();
		ECDHClientKeyExchange keyExchangeMsg = new ECDHClientKeyExchange(encoded, endpoint);
		keyExchangeMsg.setMessageSeq(2);
		Record keyExchangeRecord =  DtlsTestTools.getRecordForMessage(0, 2, keyExchangeMsg, senderAddress);

		// put KEY_EXCHANGE message with seq no. 2 to inbound message queue
		keyExchangeRecord.applySession(handshaker.getSession());
		handshaker.processMessage(keyExchangeRecord);
		
		assertThat(handshaker.handshakeMessages.size(), is(6));
		assertFalse("Client's KEY_EXCHANGE message should have been queued",
				handshaker.isInboundMessageProcessed());

		return certificateMsgRecord;
	}

	private void assertThatAllMessagesHaveBeenProcessedInOrder() {
		assertThat(handshaker.getNextReceiveMessageSequenceNumber(), is(3));
		assertThat("Client's CERTIFICATE message should have been processed",
				getHandshakeMessage(6, HandshakeType.CERTIFICATE), notNullValue());
		assertThat("Client's KEY_EXCHANGE message should have been processed",
				getHandshakeMessage(7, HandshakeType.CLIENT_KEY_EXCHANGE), notNullValue());
		assertTrue("All (processed) messages should have been removed from inbound messages queue",
				handshaker.isInboundMessageProcessed());

	}

	private void processClientHello(int messageSeq, List<byte[]> helloExtensions) throws Exception {

		processClientHello(0, 0, messageSeq, null, supportedClientCiphers, helloExtensions);
	}

	private void processClientHello(int epoch, long sequenceNo, int messageSeq, byte[] cookie,
			byte[] supportedCiphers, List<byte[]> helloExtensions) throws Exception {

		byte[] clientHelloFragment = newClientHelloFragment(cookie, supportedCiphers, helloExtensions);
		clientHelloMsg = newHandshakeMessage(HandshakeType.CLIENT_HELLO, messageSeq, clientHelloFragment);
		byte[] dtlsRecord = DtlsTestTools.newDTLSRecord(ContentType.HANDSHAKE.getCode(), epoch,
				sequenceNo, clientHelloMsg);
		List<Record> list = DtlsTestTools.fromByteArray(dtlsRecord, endpoint, null, ClockUtil.nanoRealtime());
		assertFalse("Should be able to deserialize DTLS Record from byte array", list.isEmpty());
		Record record = list.get(0);
		record.applySession(handshaker.getSession());
		handshaker.processMessage(record);
	}

	private static byte[] newHandshakeMessage(HandshakeType type, int messageSeq, byte[] fragment) {
		DatagramWriter writer = new DatagramWriter();
		writer.write(type.getCode(), 8);
		writer.write(fragment.length, 24);
		writer.write(messageSeq, 16);
		writer.write(0, 24); // fragment offset is always 0
		writer.write(fragment.length, 24);
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

	public HandshakeMessage getHandshakeMessage(int index, HandshakeType type) {
		HandshakeMessage message = handshaker.handshakeMessages.get(index);
		if (message.getMessageType() == type) {
			return message;
		}
		return null;
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
