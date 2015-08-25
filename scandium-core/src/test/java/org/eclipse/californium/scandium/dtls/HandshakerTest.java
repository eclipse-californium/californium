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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - replace custom HMAC implementation
 *                                                    with standard algorithm
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add test case for verifying re-assembly
 *                                                    of fragmented messages
 *    Kai Hudalla (Bosch Software Innovations GmbH) - consolidate and fix record buffering and message re-assembly
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
		certificateChain = 
				DtlsTestTools.getCertificateChainFromStore(
						DtlsTestTools.KEY_STORE_LOCATION,
						DtlsTestTools.KEY_STORE_PASSWORD,
						"server");
		certificateMessage = createCertificateMessage(1);

		handshaker = new Handshaker(false, session, null, null, 1500) {
			@Override
			public DTLSFlight getStartHandshakeMessage() {
				return new DTLSFlight(session);
			}
			
			@Override
			protected DTLSFlight doProcessMessage(DTLSMessage message) throws GeneralSecurityException, HandshakeException {
				if (message instanceof HandshakeMessage) {
					receivedMessages[((HandshakeMessage) message).getMessageSeq()] += 1;
					incrementNextReceiveSeq();
				}
				return null;
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
							HandshakeType.CERTIFICATE,
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
		assertTrue(result instanceof CertificateMessage);
		CertificateMessage reassembled = (CertificateMessage) result;
		assertThat(reassembled.getPublicKey(), is(certificateMessage.getPublicKey()));
		assertThat(reassembled.getMessageSeq(), is(certificateMessage.getMessageSeq()));
	}
	
	@Test
	public void testDoPrfProducesDataOfCorrectLength() {
		byte[] secret = "secret".getBytes();
		byte[] seed = "seed".getBytes();
		byte[] data = Handshaker.doPRF(secret, Handshaker.MASTER_SECRET_LABEL, seed);
		assertThat(data.length, is(48));
		data = Handshaker.doPRF(secret, Handshaker.KEY_EXPANSION_LABEL, seed);
		assertThat(data.length, is(128));
		data = Handshaker.doPRF(secret, Handshaker.CLIENT_FINISHED_LABEL, seed);
		assertThat(data.length, is(12));
		data = Handshaker.doPRF(secret, Handshaker.SERVER_FINISHED_LABEL, seed);
		assertThat(data.length, is(12));
	}
	
	/**
	 * Verifies TLS1.2PRF-SHA256
	 * <a href="http://www.ietf.org/mail-archive/web/tls/current/msg03416.html">
	 * test vector</a>.
	 */
	@Test
	public void testExpansionProducesCorrectData() throws Exception {
		byte[] seed = new byte[]{
				(byte) 0xa0, (byte) 0xba, (byte) 0x9f, (byte) 0x93, (byte) 0x6c, (byte) 0xda,
				(byte) 0x31, (byte) 0x18, (byte) 0x27, (byte) 0xa6, (byte) 0xf7, (byte) 0x96,
				(byte) 0xff, (byte) 0xd5, (byte) 0x19, (byte) 0x8c};
		byte[] secret = new byte[] {
				(byte) 0x9b, (byte) 0xbe, (byte) 0x43, (byte) 0x6b, (byte) 0xa9, (byte) 0x40,
				(byte) 0xf0, (byte) 0x17, (byte) 0xb1, (byte) 0x76, (byte) 0x52, (byte) 0x84,
				(byte) 0x9a, (byte) 0x71, (byte) 0xdb, (byte) 0x35};
		byte[] label = "test label".getBytes();
		byte[] expectedOutput = new byte[]{
				(byte) 0xe3, (byte) 0xf2, (byte) 0x29, (byte) 0xba, (byte) 0x72, (byte) 0x7b,
				(byte) 0xe1, (byte) 0x7b, (byte) 0x8d, (byte) 0x12, (byte) 0x26, (byte) 0x20,
				(byte) 0x55, (byte) 0x7c, (byte) 0xd4, (byte) 0x53, (byte) 0xc2, (byte) 0xaa,
				(byte) 0xb2, (byte) 0x1d, (byte) 0x07, (byte) 0xc3, (byte) 0xd4, (byte) 0x95,
				(byte) 0x32, (byte) 0x9b, (byte) 0x52, (byte) 0xd4, (byte) 0xe6, (byte) 0x1e,
				(byte) 0xdb, (byte) 0x5a, (byte) 0x6b, (byte) 0x30, (byte) 0x17, (byte) 0x91,
				(byte) 0xe9, (byte) 0x0d, (byte) 0x35, (byte) 0xc9, (byte) 0xc9, (byte) 0xa4,
				(byte) 0x6b, (byte) 0x4e, (byte) 0x14, (byte) 0xba, (byte) 0xf9, (byte) 0xaf,
				(byte) 0x0f, (byte) 0xa0, (byte) 0x22, (byte) 0xf7, (byte) 0x07, (byte) 0x7d,
				(byte) 0xef, (byte) 0x17, (byte) 0xab, (byte) 0xfd, (byte) 0x37, (byte) 0x97,
				(byte) 0xc0, (byte) 0x56, (byte) 0x4b, (byte) 0xab, (byte) 0x4f, (byte) 0xbc,
				(byte) 0x91, (byte) 0x66, (byte) 0x6e, (byte) 0x9d, (byte) 0xef, (byte) 0x9b,
				(byte) 0x97, (byte) 0xfc, (byte) 0xe3, (byte) 0x4f, (byte) 0x79, (byte) 0x67,
				(byte) 0x89, (byte) 0xba, (byte) 0xa4, (byte) 0x80, (byte) 0x82, (byte) 0xd1,
				(byte) 0x22, (byte) 0xee, (byte) 0x42, (byte) 0xc5, (byte) 0xa7, (byte) 0x2e,
				(byte) 0x5a, (byte) 0x51, (byte) 0x10, (byte) 0xff, (byte) 0xf7, (byte) 0x01,
				(byte) 0x87, (byte) 0x34, (byte) 0x7b, (byte) 0x66};
		
		byte[] data = Handshaker.doPRF(secret, label, seed, expectedOutput.length);
		assertArrayEquals(expectedOutput, data);
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
