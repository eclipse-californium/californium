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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - replace custom HMAC implementation
 *                                                    with standard algorithm
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add test case for verifying re-assembly
 *                                                    of fragmented messages
 *    Kai Hudalla (Bosch Software Innovations GmbH) - consolidate and fix record buffering and message re-assembly
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use DtlsTestTools' accessors to explicitly retrieve
 *                                                    client & server keys and certificate chains
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use SessionListener to trigger sending of pending
 *                                                    APPLICATION messages
 *    Bosch Software Innovations GmbH - move PRF tests to PseudoRandomFunctionTest
 *    Ludwig Seitz (RISE SICS) - Moved verifyCertificate() tests here from CertificateMessage
 *    Achim Kraus (Bosch Software Innovations GmbH) - report expired certificates
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.rule.ThreadsRule;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.TestSynchroneExecutor;
import org.eclipse.californium.elements.util.TestScheduledExecutorService;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConfig.DtlsRole;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.RandomManager;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.dtls.x509.NewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.StaticNewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Test cases verifying the {@code Handshaker}'s message buffering and reassembling behavior.
 *
 */
@Category(Medium.class)
public class HandshakerTest {
	@Rule
	public ThreadsRule cleanup = new ThreadsRule();

	TestHandshaker handshakerWithoutAnchors;
	TestHandshaker handshakerWithAnchors;
	DTLSSession session;
	X509Certificate[] certificateChain;
	X509Certificate[] trustAnchor;
	CertificateMessage certificateMessage;
	FragmentedHandshakeMessage[] handshakeMessageFragments;
	SimpleRecordLayer recordLayer;
	CertificateMessage message;
	// TODO: check usage
	PublicKey serverPublicKey;
	ScheduledExecutorService timer;

	/**
	 * Report failure during handshake and certification validation. Fail
	 * explicitly on expired certificates.
	 * 
	 * @param e exception to fail with
	 */
	public static void failedHandshake(Exception e) {
		Throwable cause = e.getCause();
		if (cause instanceof CertPathValidatorException) {
			cause = cause.getCause();
		}
		if (cause instanceof CertificateExpiredException) {
			fail("Please renew certificates in demo-certs! " + cause.getMessage());
		}
		e.printStackTrace();
		fail(e.toString());
	}

	@Before
	public void setUp() throws Exception {
		timer = new TestScheduledExecutorService();

		session = new DTLSSession();
		session.setReceiveCertificateType(CertificateType.X_509);
		certificateChain = DtlsTestTools.getServerCertificateChain();
		trustAnchor = DtlsTestTools.getTrustedCertificates();
		certificateMessage = createCertificateMessage(1, certificateChain);
		serverPublicKey = DtlsTestTools.getPublicKey();
		recordLayer = new SimpleRecordLayer();

		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder()
				.setTrustedRPKs(new RawPublicKeyIdentity(serverPublicKey)).build();
		Configuration configuration = new Configuration();
		configuration.set(DtlsConfig.DTLS_ROLE, DtlsRole.CLIENT_ONLY);
		DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder(configuration);
		builder.setAdvancedCertificateVerifier(verifier);

		handshakerWithoutAnchors = new TestHandshaker(session, recordLayer, builder.build());

		verifier = StaticNewAdvancedCertificateVerifier.builder()
				.setTrustedRPKs(new RawPublicKeyIdentity(serverPublicKey))
				.setTrustedCertificates(trustAnchor).build();
		builder = DtlsConnectorConfig.builder(configuration);
		builder.setAdvancedCertificateVerifier(verifier);

		handshakerWithAnchors = new TestHandshaker(session, recordLayer, builder.build());
	}

	@After
	public void tearDown() {
		timer.shutdown();
		timer = null;
	}

	@Test
	public void testProcessMessageBuffersUnexpectedChangeCipherSpecMessage() throws Exception {
		Configuration configuration = new Configuration();
		configuration.set(DtlsConfig.DTLS_ROLE, DtlsRole.CLIENT_ONLY);
		DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder(configuration)
				.setAdvancedCertificateVerifier(StaticNewAdvancedCertificateVerifier.builder()
						.setTrustedRPKs(new RawPublicKeyIdentity(serverPublicKey)).build());

		session.setCipherSuite(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8);

		// GIVEN a handshaker not yet expecting the peer's ChangeCipherSpec message
		TestHandshaker handshaker = new TestHandshaker(session, recordLayer, builder.build());
		recordLayer.setHandshaker(handshaker);
		// create keys
		handshaker.createKeys();

		// WHEN the peer sends its ChangeCipherSpec message
		ChangeCipherSpecMessage ccs = new ChangeCipherSpecMessage();
		Record ccsRecord = getRecordForMessage(0, 5, ccs);
		recordLayer.processRecord(ccsRecord, handshaker.getConnection());

		// THEN the ChangeCipherSpec message is not processed until the missing message arrives
		assertThat(handshaker.getDtlsContext().getReadEpoch(), is(0));
		handshaker.expectChangeCipherSpecMessage();
		PSKClientKeyExchange msg = new PSKClientKeyExchange(new PskPublicInformation("id"));
		msg.setMessageSeq(0);
		Record keyExchangeRecord = getRecordForMessage(0, 6, msg);
		recordLayer.processRecord(keyExchangeRecord, handshaker.getConnection());
		assertThat(handshaker.getDtlsContext().getReadEpoch(), is(1));
	}

	@Test
	public void testProcessMessageBuffersFinishedMessageUntilChangeCipherSpecIsReceived() throws Exception {
		Configuration configuration = new Configuration();
		configuration.set(DtlsConfig.DTLS_ROLE, DtlsRole.CLIENT_ONLY);
		DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder(configuration)
				.setAdvancedCertificateVerifier(StaticNewAdvancedCertificateVerifier.builder()
						.setTrustedRPKs(new RawPublicKeyIdentity(serverPublicKey)).build());

		// GIVEN a handshaker expecting the peer's ChangeCipherSpec message
		TestHandshaker handshaker = new TestHandshaker(session, recordLayer, builder.build());
		recordLayer.setHandshaker(handshaker);
		handshaker.expectChangeCipherSpecMessage();

		// WHEN the peer's FINISHED message is received out-of-sequence before the ChangeCipherSpec message
		Mac hmac = Mac.getInstance("HmacSHA256");
		Finished finished = new Finished(hmac, new SecretKeySpec(new byte[]{0x00, 0x01}, "MAC"), true, new byte[]{0x00, 0x00});
		finished.setMessageSeq(0);
		Record finishedRecord = getRecordForMessage(1, 0, finished);
		handshaker.addRecordsOfNextEpochForDeferredProcessing(finishedRecord);

		// THEN the FINISHED message is not processed until the missing CHANGE_CIPHER_SPEC message has been
		// received and processed
		assertFalse(handshaker.finishedProcessed.get());
		ChangeCipherSpecMessage ccs = new ChangeCipherSpecMessage();
		Record ccsRecord = getRecordForMessage(0, 5, ccs);
		recordLayer.processRecord(ccsRecord, handshaker.getConnection());
		assertThat(handshaker.getDtlsContext().getReadEpoch(), is(1));
		assertTrue(handshaker.finishedProcessed.get());
	}

	@Test
	public void testProcessMessageDiscardsDuplicateRecord() throws HandshakeException, GeneralSecurityException {
		int current = 0;
		int next = 1;
		Record record0 = createClientHelloRecord(session, 0, current, current);
		Record record1 = getRecordClone(record0);
		Record record2 = createClientHelloRecord(session, 0, next, next);

		recordLayer.setHandshaker(handshakerWithoutAnchors);

		recordLayer.processRecord(record0, handshakerWithoutAnchors.getConnection());
		assertThat(handshakerWithoutAnchors.receivedMessages[current], is(1));

		// send record with same record sequence number again
		recordLayer.processRecord(record1, handshakerWithoutAnchors.getConnection());
		assertThat(handshakerWithoutAnchors.receivedMessages[current], is(1));

		// send record with next record sequence number
		recordLayer.processRecord(record2, handshakerWithoutAnchors.getConnection());
		assertThat(handshakerWithoutAnchors.receivedMessages[next], is(1));
	}

	@Test
	public void testProcessMessageRemoveExtraRecords() throws HandshakeException, GeneralSecurityException {
		int current = 0;
		int next = 1;
		int last = 2;
		Record record0 = createClientHelloRecord(session, 0, current, current);
		Record record1 = createClientHelloRecord(session, 0, next, next);
		Record record2 = createClientHelloRecord(session, 0, next + 1, next);
		Record record3 = createClientHelloRecord(session, 0, next + 2, last);

		recordLayer.setHandshaker(handshakerWithoutAnchors);

		// send record with future handshake sequence number
		recordLayer.processRecord(record1, handshakerWithoutAnchors.getConnection());
		assertThat(handshakerWithoutAnchors.receivedMessages[next], is(0));

		// send second record with future handshake sequence number
		recordLayer.processRecord(record2, handshakerWithoutAnchors.getConnection());
		assertThat(handshakerWithoutAnchors.receivedMessages[next], is(0));

		// send record with more future handshake sequence number
		recordLayer.processRecord(record3, handshakerWithoutAnchors.getConnection());
		assertThat(handshakerWithoutAnchors.receivedMessages[last], is(0));

		// send record with matching handshake sequence number
		// flush processing of other record
		recordLayer.processRecord(record0, handshakerWithoutAnchors.getConnection());
		assertThat(handshakerWithoutAnchors.receivedMessages[current], is(1));
		assertThat(handshakerWithoutAnchors.receivedMessages[next], is(1));
		assertThat(handshakerWithoutAnchors.receivedMessages[last], is(1));
	}

	@Test
	public void testProcessMessageReassemblesFragmentedMessages() throws GeneralSecurityException, HandshakeException {
		int nextSeqNo = 0;
		int futureSeqNo = 1;

		recordLayer.setHandshaker(handshakerWithoutAnchors);

		givenAHandshakerWithAQueuedFragmentedMessage(futureSeqNo);

		// when processing the missing message with nextseqNo
		Record record = getRecordForMessage(0, 0, createCertificateMessage(nextSeqNo, certificateChain));
		recordLayer.processRecord(record, handshakerWithoutAnchors.getConnection());

		// assert that all fragments have been re-assembled and the resulting message with
		// the future sequence no has been processed
		assertThat(handshakerWithoutAnchors.receivedMessages[nextSeqNo], is(1));
		assertThat(handshakerWithoutAnchors.receivedMessages[futureSeqNo], is(1));
		assertTrue(handshakerWithoutAnchors.isInboundMessageProcessed());
	}

	@Test
	public void testHandleFragmentationReassemblesMessagesSentInOrder() throws Exception {
		givenAFragmentedHandshakeMessage(certificateMessage);
		HandshakeMessage result = null;
		for (FragmentedHandshakeMessage fragment : handshakeMessageFragments) {
			GenericHandshakeMessage last = handshakerWithoutAnchors.reassembleFragment(fragment);
			if (last != null) {
				result = HandshakeMessage.fromGenericHandshakeMessage(last, handshakerWithoutAnchors.getParameter());
			} else {
				result = null;
			}
		}
		assertThatReassembledMessageEqualsOriginalMessage(result);
	}

	@Test
	public void testHandleFragmentationBuffersMessagesSentInReverseOrder() throws Exception {
		givenAFragmentedHandshakeMessage(certificateMessage);
		HandshakeMessage result = null;
		for (int i = handshakeMessageFragments.length - 1; i >= 0; i--) {
			GenericHandshakeMessage last = handshakerWithoutAnchors.reassembleFragment(handshakeMessageFragments[i]);
			if (last != null) {
				result = HandshakeMessage.fromGenericHandshakeMessage(last, handshakerWithoutAnchors.getParameter());
			} else {
				result = null;
			}
		}
		assertThatReassembledMessageEqualsOriginalMessage(result);
	}

	@Test
	public void testHandleFragmentationReassemblesOverlappingMessages() throws Exception {
		givenAFragmentedHandshakeMessage(certificateMessage, 250, 500);
		HandshakeMessage result = null;
		for (FragmentedHandshakeMessage fragment : handshakeMessageFragments) {
			GenericHandshakeMessage last = handshakerWithoutAnchors.reassembleFragment(fragment);
			if (result == null && last != null) {
				result = HandshakeMessage.fromGenericHandshakeMessage(last, handshakerWithoutAnchors.getParameter());
			}
		}
		assertThatReassembledMessageEqualsOriginalMessage(result);
	}

	@Test
	public void testHandleFragmentationReassemblesMissOverlappingMessages() throws Exception {
		givenAMissFragmentedHandshakeMessage(certificateMessage, 100,  200);
		HandshakeMessage result = null;
		for (FragmentedHandshakeMessage fragment : handshakeMessageFragments) {
			GenericHandshakeMessage last = handshakerWithoutAnchors.reassembleFragment(fragment);
			if (result == null && last != null) {
				result = HandshakeMessage.fromGenericHandshakeMessage(last, handshakerWithoutAnchors.getParameter());
			}
		}
		assertThatReassembledMessageEqualsOriginalMessage(result);
	}

	@Test
	public void testVerifyCertificateSucceedsForExampleCertificates() throws IOException, GeneralSecurityException {
		givenACertificateMessage(DtlsTestTools.getServerCertificateChain(), false);
		assertThatCertificateVerificationSucceeds();

		givenACertificateMessage(DtlsTestTools.getClientCertificateChain(), false);
		assertThatCertificateVerificationSucceeds();
	}

	@Test
	public void testVerifyRPKSucceeds() throws IOException, GeneralSecurityException {
		givenARawPublicKeyCertificateMessage(serverPublicKey);
		assertThatCertificateVerificationSucceeds();
	}

	@Test
	public void testVerifyRpkFailsIfRpkIsUntrusted() throws IOException, GeneralSecurityException {
		givenARawPublicKeyCertificateMessage(DtlsTestTools.getClientPublicKey());
		assertThatCertificateVerificationFails();
	}

	@Test
	public void testVerifyCertificateFailsIfTrustAnchorIsEmpty() throws IOException, GeneralSecurityException {

		givenACertificateMessage(DtlsTestTools.getClientCertificateChain(), false);
		assertThatCertificateValidationFailsForEmptyTrustAnchor();
	}

	private void givenAHandshakerWithAQueuedFragmentedMessage(int seqNo) throws HandshakeException, GeneralSecurityException {
		// create records containing fragmented message with seqNo 1
		givenAFragmentedHandshakeMessage(createCertificateMessage(seqNo, certificateChain));

		int i = 1;
		for (FragmentedHandshakeMessage fragment : handshakeMessageFragments) {
			Record record = getRecordForMessage(0, i++, fragment);
			recordLayer.processRecord(record, handshakerWithoutAnchors.getConnection());
		}
		assertThat(handshakerWithoutAnchors.receivedMessages[seqNo], is(0));
		assertFalse(handshakerWithoutAnchors.isInboundMessageProcessed());
	}

	private void givenAFragmentedHandshakeMessage(HandshakeMessage message) {
		givenAFragmentedHandshakeMessage(message, 500, 500);
	}

	private void givenAFragmentedHandshakeMessage(HandshakeMessage message, int fragmentStep, int maxFragmentSize) {
		List<FragmentedHandshakeMessage> fragments = new LinkedList<>();
		byte[] serializedMsg = message.fragmentToByteArray();
		int fragmentOffset = 0;
		while (fragmentOffset < serializedMsg.length) {
			int fragmentLength = Math.min(maxFragmentSize, serializedMsg.length - fragmentOffset);
			byte[] fragment = new byte[fragmentLength];
			System.arraycopy(serializedMsg, fragmentOffset, fragment, 0, fragmentLength);
			FragmentedHandshakeMessage msg = new FragmentedHandshakeMessage(message.getMessageType(),
					serializedMsg.length, message.getMessageSeq(), fragmentOffset, fragment);
			fragments.add(msg);
			if (fragmentOffset + fragmentLength == serializedMsg.length) {
				fragmentOffset += fragmentLength;
			} else {
				fragmentOffset += Math.min(fragmentLength, fragmentStep);
			}
		}
		handshakeMessageFragments = fragments.toArray(new FragmentedHandshakeMessage[] {});
	}

	private void givenAMissFragmentedHandshakeMessage(HandshakeMessage message, int fragmentStep, int maxFragmentSize) {
		givenAFragmentedHandshakeMessage(message, fragmentStep, maxFragmentSize);
		List<FragmentedHandshakeMessage> fragments = new LinkedList<>(Arrays.asList(handshakeMessageFragments));
		fragments.remove(fragments.size() - 1);
		fragments.remove(fragments.size() / 2);
		givenAFragmentedHandshakeMessage(message, fragmentStep / 2, maxFragmentSize / 2);
		fragments.addAll(Arrays.asList(handshakeMessageFragments));
		handshakeMessageFragments = fragments.toArray(new FragmentedHandshakeMessage[] {});
	}

	private void givenACertificateMessage(X509Certificate[] chain, boolean useRawPublicKey)
			throws IOException, GeneralSecurityException {
		if (useRawPublicKey) {
			message = new CertificateMessage(chain[0].getPublicKey().getEncoded());
		} else {
			message = new CertificateMessage(Arrays.asList(chain));
		}
	}

	private void givenARawPublicKeyCertificateMessage(PublicKey publicKey) {
		message = new CertificateMessage(publicKey.getEncoded());
	}

	private void assertThatReassembledMessageEqualsOriginalMessage(HandshakeMessage result) {
		assertThat(result, is(instanceOf(CertificateMessage.class)));
		CertificateMessage reassembled = (CertificateMessage) result;
		assertThat(reassembled.getPublicKey(), is(certificateMessage.getPublicKey()));
		assertThat(reassembled.getMessageSeq(), is(certificateMessage.getMessageSeq()));
	}

	private void assertThatCertificateVerificationSucceeds() {
		try {
			handshakerWithAnchors.verifyCertificate(message, false);
			// all is well
		} catch (HandshakeException e) {
			failedHandshake(e);
		}
	}

	private void assertThatCertificateVerificationFails() {
		try {
			handshakerWithAnchors.verifyCertificate(message, false);
			fail("Verification of certificate should have failed");
		} catch (HandshakeException e) {
			// all is well
		}
	}

	private void assertThatCertificateValidationFailsForEmptyTrustAnchor() {
		try {
			handshakerWithoutAnchors.verifyCertificate(message, false);
			fail("Verification of certificate should have failed");
		} catch (HandshakeException e) {
			// all is well
		}
	}

	private static Record createClientHelloRecord(DTLSSession context, int epoch, long sequenceNo, int messageSeqNo) throws GeneralSecurityException {
		ClientHello clientHello = new ClientHello(ProtocolVersion.VERSION_DTLS_1_2, context, Collections.<SignatureAndHashAlgorithm> emptyList(), null, null, SupportedGroup.getPreferredGroups());
		clientHello.setMessageSeq(messageSeqNo);
		return getRecordForMessage(epoch, sequenceNo, clientHello);
	}

	private static  CertificateMessage createCertificateMessage(int seqNo, X509Certificate[] chain) {
		CertificateMessage result = new CertificateMessage(Arrays.asList(chain));
		result.setMessageSeq(seqNo);
		return result;
	}

	private static Record getRecordForMessage(int epoch, long seqNo, DTLSMessage msg) {
		byte[] dtlsRecord = DtlsTestTools.newDTLSRecord(msg.getContentType().getCode(), epoch,
				seqNo, msg.toByteArray());
		List<Record> list = DtlsTestTools.fromByteArray(dtlsRecord, null, ClockUtil.nanoRealtime());
		assertFalse("Should be able to deserialize DTLS Record from byte array", list.isEmpty());
		return list.get(0);
	}

	private static Record getRecordClone(final Record record) {
		byte[] dtlsRecord = record.toByteArray();
		List<Record> list = DtlsTestTools.fromByteArray(dtlsRecord, null, ClockUtil.nanoRealtime());
		assertFalse("Should be able to deserialize DTLS Record from byte array", list.isEmpty());
		return list.get(0);
	}

	private static final HandshakeState[] EMPTY_FOR_TEST = {};

	private class TestHandshaker extends Handshaker {


		private final int[] receivedMessages = new int[10];

		private AtomicBoolean finishedProcessed = new AtomicBoolean(false);

		TestHandshaker(DTLSSession session, RecordLayer recordLayer, DtlsConnectorConfig config) {
			super(0, 0, recordLayer, timer, new Connection(config.getAddress()).setConnectorContext(TestSynchroneExecutor.TEST_EXECUTOR, null),
					config);
			getConnection().setConnectionId(new ConnectionId(new byte[] { 1, 2, 3, 4 }));
			getSession().set(session);
			setExpectedStates(EMPTY_FOR_TEST);
		}

		@Override
		protected boolean isClient() {
			return false;
		}

		public void createKeys() {
			byte[] secret = Bytes.createBytes(RandomManager.currentSecureRandom(), 48);
			SecretKey masterSecret = SecretUtil.create(secret, "MAC");
			clientRandom = new Random();
			serverRandom = new Random();
			calculateKeys(masterSecret);
		}

		@Override
		protected void doProcessMessage(HandshakeMessage message) throws HandshakeException {
			receivedMessages[message.getMessageSeq()] += 1;
			if (message.getMessageType() == HandshakeType.FINISHED) {
				finishedProcessed.set(true);
			}
		}

		@Override
		protected void processMasterSecret() {
		}

		@Override
		protected void processCertificateVerified() {
		}

		@Override
		protected void processCertificateIdentityAvailable() throws HandshakeException {
		}
	}
}
