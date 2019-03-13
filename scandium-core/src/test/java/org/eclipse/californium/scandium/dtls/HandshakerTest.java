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

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.scandium.category.Medium;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig.Builder;
import org.eclipse.californium.scandium.dtls.rpkstore.InMemoryRpkTrustStore;
import org.eclipse.californium.scandium.dtls.rpkstore.TrustedRpkStore;
import org.eclipse.californium.scandium.dtls.x509.StaticCertificateVerifier;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Test cases verifying the {@code Handshaker}'s message buffering and reassembling behavior.
 *
 */
@Category(Medium.class)
public class HandshakerTest {

	final int[] receivedMessages = new int[10];
	InetSocketAddress endpoint = InetSocketAddress.createUnresolved("localhost", 10000);
	Handshaker handshaker;
	Handshaker handshakerWithAnchors;
	DTLSSession session;
	X509Certificate[] certificateChain;
	X509Certificate[] trustAnchor;
	CertificateMessage certificateMessage;
	FragmentedHandshakeMessage[] handshakeMessageFragments;
	RecordLayer recordLayer;
	CertificateMessage message;
	InetSocketAddress peerAddress;
	PublicKey serverPublicKey;
	TrustedRpkStore rpkStore;

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
		for (int i = 0; i < receivedMessages.length; i++) {
			receivedMessages[i++] = 0;
		}

		session = new DTLSSession(endpoint);
		session.setReceiveCertificateType(CertificateType.X_509);
		session.setParameterAvailable();
		certificateChain = DtlsTestTools.getServerCertificateChain();
		trustAnchor = DtlsTestTools.getTrustedCertificates();
		certificateMessage = createCertificateMessage(1);
		recordLayer = mock(RecordLayer.class);
		serverPublicKey = DtlsTestTools.getPublicKey();
		peerAddress = new InetSocketAddress(InetAddress.getLoopbackAddress(), 5684);
		rpkStore = new InMemoryRpkTrustStore(Collections.singleton(new RawPublicKeyIdentity(serverPublicKey)));
		DtlsConnectorConfig.Builder builder = new Builder();
		builder.setClientOnly();
		builder.setCertificateVerifier(new StaticCertificateVerifier(null));
		builder.setRpkTrustStore(rpkStore);
		
		handshaker = new Handshaker(false, 0, session, recordLayer, null, builder.build(), 1500) {

			@Override
			public void startHandshake() {
			}

			@Override
			protected void doProcessMessage(DTLSMessage message) throws GeneralSecurityException, HandshakeException {
				if (message instanceof HandshakeMessage) {
					receivedMessages[((HandshakeMessage) message).getMessageSeq()] += 1;
					incrementNextReceiveSeq();
				}
			}
		};

		builder = new Builder();
		builder.setClientOnly();
		builder.setCertificateVerifier(new StaticCertificateVerifier(trustAnchor));
		builder.setRpkTrustStore(rpkStore);

		handshakerWithAnchors = new Handshaker(false, 0, session, recordLayer, null,
				 builder.build(), 1500) {

			@Override
			public void startHandshake() {
			}

			@Override
			protected void doProcessMessage(DTLSMessage message) throws GeneralSecurityException, HandshakeException {
				if (message instanceof HandshakeMessage) {
					receivedMessages[((HandshakeMessage) message).getMessageSeq()] += 1;
					incrementNextReceiveSeq();
				}
			}
		};
	}

	@Test
	public void testProcessMessageBuffersUnexpectedChangeCipherSpecMessage() throws Exception {
		DtlsConnectorConfig.Builder builder = new Builder();
		builder.setClientOnly();
		builder.setRpkTrustStore(rpkStore);

		// GIVEN a handshaker not yet expecting the peer's ChangeCipherSpec message
		ChangeCipherSpecTestHandshaker handshaker = new ChangeCipherSpecTestHandshaker(session, recordLayer, builder.build());

		// WHEN the peer sends its ChangeCipherSpec message
		InetSocketAddress senderAddress = new InetSocketAddress(5000);

		ChangeCipherSpecMessage ccs = new ChangeCipherSpecMessage(endpoint);
		Record ccsRecord = getRecordForMessage(0, 5, ccs, senderAddress);
		handshaker.processMessage(ccsRecord);

		// THEN the ChangeCipherSpec message is not processed until the missing message arrives
		assertFalse(handshaker.changeCipherSpecProcessed.get());
		handshaker.expectChangeCipherSpecMessage();
		PSKClientKeyExchange msg = new PSKClientKeyExchange(new PskPublicInformation("id"), endpoint);
		msg.setMessageSeq(0);
		Record keyExchangeRecord = getRecordForMessage(0, 6, msg, senderAddress);
		handshaker.processMessage(keyExchangeRecord);
		assertTrue(handshaker.changeCipherSpecProcessed.get());
	}

	@Test
	public void testProcessMessageBuffersFinishedMessageUntilChangeCipherSpecIsReceived() throws Exception {

		final InetSocketAddress senderAddress = new InetSocketAddress(5000);
		DtlsConnectorConfig.Builder builder = new Builder();
		builder.setClientOnly();
		builder.setRpkTrustStore(rpkStore);

		// GIVEN a handshaker expecting the peer's ChangeCipherSpec message
		ChangeCipherSpecTestHandshaker handshaker = new ChangeCipherSpecTestHandshaker(session, recordLayer, builder.build());
		handshaker.expectChangeCipherSpecMessage();

		// WHEN the peer's FINISHED message is received out-of-sequence before the ChangeCipherSpec message
		Finished finished = new Finished("HmacSHA256", new byte[]{0x00, 0x01}, true, new byte[]{0x00, 0x00}, endpoint);
		finished.setMessageSeq(0);
		Record finishedRecord = getRecordForMessage(1, 0, finished, senderAddress);
		handshaker.processMessage(finishedRecord);

		// THEN the FINISHED message is not processed until the missing CHANGE_CIPHER_SPEC message has been
		// received and processed
		assertFalse(handshaker.finishedProcessed.get());
		ChangeCipherSpecMessage ccs = new ChangeCipherSpecMessage(endpoint);
		Record ccsRecord = getRecordForMessage(0, 5, ccs, senderAddress);
		handshaker.processMessage(ccsRecord);
		assertTrue(handshaker.changeCipherSpecProcessed.get());
		assertTrue(handshaker.finishedProcessed.get());
	}

	@Test
	public void testProcessMessageDiscardsDuplicateRecord() throws HandshakeException, GeneralSecurityException {
		int current = 0;
		int next = 1;
		Record record0 = createRecord(0, current, current);
		Record record1 = createRecord(0, next, next);
	
		handshaker.processMessage(record0);
		assertThat(receivedMessages[current], is(1));

		// send record with same record sequence number again
		handshaker.processMessage(record0);
		assertThat(receivedMessages[current], is(1));

		// send record with next record sequence number
		handshaker.processMessage(record1);
		assertThat(receivedMessages[next], is(1));
	}

	@Test
	public void testProcessMessageReassemblesFragmentedMessages() throws GeneralSecurityException, HandshakeException {
		int nextSeqNo = 0;
		int futureSeqNo = 1;
		givenAHandshakerWithAQueuedFragmentedMessage(futureSeqNo);

		// when processing the missing message with nextseqNo
		Record firstRecord = new Record(ContentType.HANDSHAKE, 0, 0, createCertificateMessage(nextSeqNo), session,
				false, 0);
		handshaker.processMessage(firstRecord);

		// assert that all fragments have been re-assembled and the resulting message with
		// the future sequence no has been processed
		assertThat(receivedMessages[nextSeqNo], is(1));
		assertThat(receivedMessages[futureSeqNo], is(1));
		assertTrue(handshaker.inboundMessageBuffer.isEmpty());
	}

	private void givenAHandshakerWithAQueuedFragmentedMessage(int seqNo) throws HandshakeException, GeneralSecurityException {
		// create records containing fragmented message with seqNo 1
		givenAFragmentedHandshakeMessage(createCertificateMessage(seqNo));

		int i = 1;
		for (FragmentedHandshakeMessage fragment : handshakeMessageFragments) {
			Record record = new Record(ContentType.HANDSHAKE, 0, i++, fragment, session, false, 0);
			handshaker.processMessage(record);
		}
		assertThat(receivedMessages[seqNo], is(0));
		assertFalse(handshaker.inboundMessageBuffer.isEmpty());
	}

	@Test
	public void testHandleFragmentationReassemblesMessagesSentInOrder() throws Exception {
		givenAFragmentedHandshakeMessage(certificateMessage);
		HandshakeMessage result = null;
		for (FragmentedHandshakeMessage fragment : handshakeMessageFragments) {
			result = handshaker.handleFragmentation(fragment);
		}
		assertThatReassembledMessageEqualsOriginalMessage(result);
	}

	@Test
	public void testHandleFragmentationBuffersMessagesSentInReverseOrder() throws Exception {
		givenAFragmentedHandshakeMessage(certificateMessage);
		HandshakeMessage result = null;
		for (int i = handshakeMessageFragments.length - 1; i >= 0; i--) {
			result = handshaker.handleFragmentation(handshakeMessageFragments[i]);
		}
		assertThatReassembledMessageEqualsOriginalMessage(result);
	}

	@Test
	public void testHandleFragmentationReassemblesOverlappingMessages() throws Exception {
		givenAFragmentedHandshakeMessage(certificateMessage, 250, 500);
		HandshakeMessage result = null;
		for (FragmentedHandshakeMessage fragment : handshakeMessageFragments) {
			HandshakeMessage last = handshaker.handleFragmentation(fragment);
			if (result == null) {
				result = last;
			}
		}
		assertThatReassembledMessageEqualsOriginalMessage(result);
	}

	@Test
	public void testHandleFragmentationReassemblesMissOverlappingMessages() throws Exception {
		givenAMissFragmentedHandshakeMessage(certificateMessage, 100,  200);
		HandshakeMessage result = null;
		for (FragmentedHandshakeMessage fragment : handshakeMessageFragments) {
			HandshakeMessage last = handshaker.handleFragmentation(fragment);
			if (result == null) {
				result = last;
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
					serializedMsg.length, message.getMessageSeq(), fragmentOffset, fragment, endpoint);
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
		certificateChain = chain;
		if (useRawPublicKey) {
			message = new CertificateMessage(chain[0].getPublicKey().getEncoded(), peerAddress);
		} else {
			message = new CertificateMessage(Arrays.asList(chain), peerAddress);
		}
	}

	private void givenARawPublicKeyCertificateMessage(PublicKey publicKey) {
		message = new CertificateMessage(publicKey.getEncoded(), peerAddress);
	}

	private void assertThatReassembledMessageEqualsOriginalMessage(HandshakeMessage result) {
		assertThat(result, is(instanceOf(CertificateMessage.class)));
		CertificateMessage reassembled = (CertificateMessage) result;
		assertThat(reassembled.getPublicKey(), is(certificateMessage.getPublicKey()));
		assertThat(reassembled.getMessageSeq(), is(certificateMessage.getMessageSeq()));
	}

	private void assertThatCertificateVerificationSucceeds() {
		try {
			handshakerWithAnchors.verifyCertificate(message);
			// all is well
		} catch (HandshakeException e) {
			failedHandshake(e);
		}
	}

	private void assertThatCertificateVerificationFails() {
		try {
			handshaker.verifyCertificate(message);
			fail("Verification of certificate should have failed");
		} catch (HandshakeException e) {
			// all is well
		}
	}

	private void assertThatCertificateValidationFailsForEmptyTrustAnchor() {
		try {
			handshaker.verifyCertificate(message);
			fail("Verification of certificate should have failed");
		} catch (HandshakeException e) {
			// all is well
		}
	}

	private Record createRecord(int epoch, long sequenceNo, int messageSeqNo) throws GeneralSecurityException {
		ClientHello clientHello = new ClientHello(new ProtocolVersion(), new SecureRandom(), session, null, null);
		clientHello.setMessageSeq(messageSeqNo);
		return new Record(ContentType.HANDSHAKE, epoch, sequenceNo, clientHello, session, true, 0);
	}
	
	private CertificateMessage createCertificateMessage(int seqNo) {
		CertificateMessage result = new CertificateMessage(Arrays.asList(certificateChain), session.getPeer());
		result.setMessageSeq(seqNo);
		return result;
	}

	private static Record getRecordForMessage(final int epoch, final int seqNo, final DTLSMessage msg, final InetSocketAddress peer) {
		byte[] dtlsRecord = DtlsTestTools.newDTLSRecord(msg.getContentType().getCode(), epoch,
				seqNo, msg.toByteArray());
		List<Record> list = Record.fromByteArray(dtlsRecord, peer, null);
		assertFalse("Should be able to deserialize DTLS Record from byte array", list.isEmpty());
		return list.get(0);
	}

	private class ChangeCipherSpecTestHandshaker extends Handshaker {

		private AtomicBoolean changeCipherSpecProcessed = new AtomicBoolean(false);
		private AtomicBoolean finishedProcessed = new AtomicBoolean(false);

		ChangeCipherSpecTestHandshaker(final DTLSSession session, final RecordLayer recordLayer,
				DtlsConnectorConfig config) {
			super(false, 0, session, recordLayer, null, config, 1500);
		}

		@Override
		public void startHandshake() throws HandshakeException {
		}

		@Override
		protected void doProcessMessage(final DTLSMessage message) throws GeneralSecurityException, HandshakeException {

			switch(message.getContentType()) {

			case CHANGE_CIPHER_SPEC:
				changeCipherSpecProcessed.set(true);
				setCurrentReadState();
				break;
			case HANDSHAKE:
				final HandshakeMessage handshakeMessage = (HandshakeMessage) message;
				if (handshakeMessage.getMessageType() == HandshakeType.FINISHED) {
					finishedProcessed.set(true);
				}
				break;
			default:
				break;
			}
		}
	}
}
