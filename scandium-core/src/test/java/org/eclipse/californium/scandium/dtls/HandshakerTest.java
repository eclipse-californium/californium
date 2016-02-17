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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.LinkedList;
import java.util.List;

import org.eclipse.californium.scandium.category.Medium;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Medium.class)
public class HandshakerTest {

	InetSocketAddress endpoint = InetSocketAddress.createUnresolved("localhost", 10000);
	Handshaker handshaker;
	final int[] receivedMessages = new int[10];
	DTLSSession session;
	Certificate[] certificateChain;
	CertificateMessage certificateMessage;
	FragmentedHandshakeMessage[] handshakeMessageFragments;

	@Before
	public void setUp() throws Exception {
		for (int i = 0; i < receivedMessages.length; i++) {
			receivedMessages[i++] = 0;
		}
		
		session = new DTLSSession(endpoint, false);
		session.setReceiveRawPublicKey(false);
		certificateChain = DtlsTestTools.getServerCertificateChain();
		certificateMessage = createCertificateMessage(1);
		RecordLayer recordLayer = new RecordLayer() {

			@Override
			public void sendRecord(Record record) {
			}

			@Override
			public void sendFlight(DTLSFlight flight) {
			}
		};
		handshaker = new Handshaker(false, session, recordLayer, null, null, 1500) {
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
	
	private void givenAFragmentedHandshakeMessage(HandshakeMessage message) {
		List<FragmentedHandshakeMessage> fragments = new LinkedList<>();
		byte[] serializedMsg = message.fragmentToByteArray();
		int maxFragmentSize = 500;
		int fragmentOffset = 0;
		while (fragmentOffset < serializedMsg.length) {
			int fragmentLength = Math.min(maxFragmentSize, serializedMsg.length - fragmentOffset);
			byte[] fragment = new byte[fragmentLength];
			System.arraycopy(serializedMsg, fragmentOffset, fragment, 0, fragmentLength);
			FragmentedHandshakeMessage msg = 
					new FragmentedHandshakeMessage(
							fragment,
							message.getMessageType(),
							fragmentOffset,
							serializedMsg.length,
							endpoint);
			msg.setMessageSeq(message.getMessageSeq());
			fragments.add(msg);
			fragmentOffset += fragmentLength;
		}
		handshakeMessageFragments = fragments.toArray(new FragmentedHandshakeMessage[]{});
	}

	private void assertThatReassembledMessageEqualsOriginalMessage(HandshakeMessage result) {
		assertThat(result, is(instanceOf(CertificateMessage.class)));
		CertificateMessage reassembled = (CertificateMessage) result;
		assertThat(reassembled.getPublicKey(), is(certificateMessage.getPublicKey()));
		assertThat(reassembled.getMessageSeq(), is(certificateMessage.getMessageSeq()));
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
}
