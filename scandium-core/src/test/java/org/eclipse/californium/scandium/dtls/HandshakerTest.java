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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.eclipse.californium.scandium.auth.RawPublicKeyIdentity;
import org.eclipse.californium.scandium.category.Medium;
import org.eclipse.californium.scandium.dtls.rpkstore.InMemoryRpkTrustStore;
import org.eclipse.californium.scandium.dtls.rpkstore.TrustedRpkStore;
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

	@Before
	public void setUp() throws Exception {
		for (int i = 0; i < receivedMessages.length; i++) {
			receivedMessages[i++] = 0;
		}

		session = new DTLSSession(endpoint, false);
		session.setReceiveRawPublicKey(false);
		certificateChain = DtlsTestTools.getServerCertificateChain();
		trustAnchor = DtlsTestTools.getTrustedCertificates();
		certificateMessage = createCertificateMessage(1);
		recordLayer = mock(RecordLayer.class);
		serverPublicKey = DtlsTestTools.getPublicKey();
		peerAddress = new InetSocketAddress(InetAddress.getLoopbackAddress(), 5684);
		rpkStore = new InMemoryRpkTrustStore(Collections.singleton(new RawPublicKeyIdentity(serverPublicKey)));
		handshaker = new Handshaker(false, session, recordLayer, null, null, 1500, rpkStore) {
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
		
		handshakerWithAnchors = new Handshaker(false, session, recordLayer, null, trustAnchor, 1500, rpkStore) {
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

		// GIVEN a handshaker not yet expecting the peer's ChangeCipherSpec message
		ChangeCipherSpecTestHandshaker handshaker = new ChangeCipherSpecTestHandshaker(session, recordLayer, rpkStore);

		// WHEN the peer sends its ChangeCipherSpec message
		InetSocketAddress senderAddress = new InetSocketAddress(5000);

		ChangeCipherSpecMessage ccs = new ChangeCipherSpecMessage(endpoint);
		Record ccsRecord = getRecordForMessage(0, 5, ccs, senderAddress);
		handshaker.processMessage(ccsRecord);

		// THEN the ChangeCipherSpec message is not processed until the missing message arrives
		assertFalse(handshaker.changeCipherSpecProcessed.get());
		handshaker.expectChangeCipherSpecMessage();
		PSKClientKeyExchange msg = new PSKClientKeyExchange("id", endpoint);
		msg.setMessageSeq(0);
		Record keyExchangeRecord = getRecordForMessage(0, 6, msg, senderAddress);
		handshaker.processMessage(keyExchangeRecord);
		assertTrue(handshaker.changeCipherSpecProcessed.get());
	}

	@Test
	public void testProcessMessageBuffersFinishedMessageUntilChangeCipherSpecIsReceived() throws Exception {

		final InetSocketAddress senderAddress = new InetSocketAddress(5000);

		// GIVEN a handshaker expecting the peer's ChangeCipherSpec message
		ChangeCipherSpecTestHandshaker handshaker = new ChangeCipherSpecTestHandshaker(session, recordLayer, rpkStore);
		handshaker.expectChangeCipherSpecMessage();

		// WHEN the peer's FINISHED message is received out-of-sequence before the ChangeCipherSpec message
		Finished finished = new Finished(new byte[]{0x00, 0x01}, true, new byte[]{0x00, 0x00}, endpoint);
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
		Record firstRecord = new Record(ContentType.HANDSHAKE, 0, 0, createCertificateMessage(nextSeqNo), session);
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
			Record record = new Record(ContentType.HANDSHAKE, 0, i++, fragment, session);
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
		List<FragmentedHandshakeMessage> fragments = new LinkedList<>();
		byte[] serializedMsg = message.fragmentToByteArray();
		int maxFragmentSize = 500;
		int fragmentOffset = 0;
		while (fragmentOffset < serializedMsg.length) {
			int fragmentLength = Math.min(maxFragmentSize, serializedMsg.length - fragmentOffset);
			byte[] fragment = new byte[fragmentLength];
			System.arraycopy(serializedMsg, fragmentOffset, fragment, 0, fragmentLength);
			FragmentedHandshakeMessage msg = new FragmentedHandshakeMessage(fragment, message.getMessageType(),
					fragmentOffset, serializedMsg.length, endpoint);
			msg.setMessageSeq(message.getMessageSeq());
			fragments.add(msg);
			fragmentOffset += fragmentLength;
		}
		handshakeMessageFragments = fragments.toArray(new FragmentedHandshakeMessage[] {});
	}

	private void givenACertificateMessage(X509Certificate[] chain, boolean useRawPublicKey)
			throws IOException, GeneralSecurityException {
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
			fail("Verification of certificate should have succeeded");
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
		return new Record(ContentType.HANDSHAKE, epoch, sequenceNo, clientHello, session);
	}
	
	private CertificateMessage createCertificateMessage(int seqNo) {
		CertificateMessage result = new CertificateMessage(certificateChain, session.getPeer());
		result.setMessageSeq(seqNo);
		return result;
	}

	private static Record getRecordForMessage(final int epoch, final int seqNo, final DTLSMessage msg, final InetSocketAddress peer) {
		byte[] dtlsRecord = DtlsTestTools.newDTLSRecord(msg.getContentType().getCode(), epoch,
				seqNo, msg.toByteArray());
		List<Record> list = Record.fromByteArray(dtlsRecord, peer);
		assertFalse("Should be able to deserialize DTLS Record from byte array", list.isEmpty());
		return list.get(0);
	}

	private class ChangeCipherSpecTestHandshaker extends Handshaker {

		private AtomicBoolean changeCipherSpecProcessed = new AtomicBoolean(false);
		private AtomicBoolean finishedProcessed = new AtomicBoolean(false);

		ChangeCipherSpecTestHandshaker(final DTLSSession session, final RecordLayer recordLayer,
				TrustedRpkStore rpkStore) {
			super(false, session, recordLayer, null, null, 1500, rpkStore);
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
