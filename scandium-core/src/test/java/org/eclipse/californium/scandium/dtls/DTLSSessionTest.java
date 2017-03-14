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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creator
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.scandium.auth.PreSharedKeyIdentity;
import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class DTLSSessionTest {

	static final int DEFAULT_MAX_FRAGMENT_LENGTH = 16384; //2^14 as defined in DTLS 1.2 spec
	static final InetSocketAddress PEER_ADDRESS = new InetSocketAddress(InetAddress.getLoopbackAddress(), 10000);
	private static final Random RANDOM = new Random();
	DTLSSession session;

	@Before
	public void setUp() throws Exception {
		session = newEstablishedServerSession(PEER_ADDRESS, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, false);
	}

	@Test
	public void testDefaultMaxFragmentLengthCompliesWithSpec() {
		// when instantiating a default server session
		session = new DTLSSession(PEER_ADDRESS, false);

		// then the max fragment size is as specified in DTLS spec
		assertThat(session.getMaxFragmentLength(), is(DEFAULT_MAX_FRAGMENT_LENGTH));
	}

	@Test
	public void testMaxFragmentLengthIsAdjustedToMtu() {
		// given an ethernet network interface
		int mtu = 1500;

		// when setting the session's maximumTransmissionUnit property
		session.setMaxTransmissionUnit(mtu);

		// then the maxFragmentLength is as adjusted so that a fragment
		// fits into a single unfragmented UDP datagram
		assertAnyFragmentFitsIntoUnfragmentedDatagram(mtu);
	}

	@Test
	public void testMaxFragmentLengthIsAdjustedToCipherSuite() {
		// given a handshake over an ethernet connection (MTU 1500 bytes)
		int mtu = 1500;
		session.setMaxTransmissionUnit(mtu);
		int initialMaxFragmentLength = session.getMaxFragmentLength();

		// when negotiating a cipher suite introducing ciphertext expansion
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256;
		DTLSConnectionState newWriteState =
				new DTLSConnectionState(cipherSuite, CompressionMethod.NULL, null, null, null);
		session.setWriteState(newWriteState);

		// then the maxFragmentLength is adjusted so that any fragment using
		// current write state fits into a single unfragmented UDP datagram
		assertAnyFragmentFitsIntoUnfragmentedDatagram(mtu);
		assertTrue(session.getMaxFragmentLength() < initialMaxFragmentLength);
	}

	private void assertAnyFragmentFitsIntoUnfragmentedDatagram(int mtu) {
		int datagramSize = session.getMaxFragmentLength()
				+ session.getWriteState().getMaxCiphertextExpansion()
				+ 12 // DTLS session headers
				+ 13 // DTLS record headers
				+ 8 // UDP headers
				+ 20; // IP headers
		assertTrue(datagramSize <= mtu);
		assertThat(session.getMaxDatagramSize(), is(datagramSize));
	}

	@Test
	public void testRecordFromPreviousEpochIsDiscarded() {
		session.setReadEpoch(1);
		assertFalse(session.isRecordProcessable(0, 15));
	}

	@Test
	public void testRecordFromFutureEpochIsDiscarded() {
		session.setReadEpoch(1);
		assertFalse(session.isRecordProcessable(2, 15));
	}

	@Test
	public void testRecordShiftsReceiveWindow() {
		int epoch = 0;
		session.setReadEpoch(epoch);
		session.markRecordAsRead(epoch, 0);
		session.markRecordAsRead(epoch, 2);
		assertFalse(session.isRecordProcessable(0, 0));
		assertTrue(session.isRecordProcessable(0, 1));
		assertFalse(session.isRecordProcessable(0, 2));
		assertTrue(session.isRecordProcessable(0, 64));

		// make a right shift by 1 position
		session.markRecordAsRead(epoch, 64);
		assertFalse(session.isRecordProcessable(0, 0));
		assertTrue(session.isRecordProcessable(0, 1));
		assertFalse(session.isRecordProcessable(0, 2));
		assertFalse(session.isRecordProcessable(0, 64));
	}

	@Test
	public void testEpochSwitchResetsReceiveWindow() {

		int epoch = session.getReadEpoch();
		session.markRecordAsRead(epoch, 0);
		session.markRecordAsRead(epoch, 2);
		assertFalse(session.isRecordProcessable(session.getReadEpoch(), 0));
		assertFalse(session.isRecordProcessable(session.getReadEpoch(), 2));

		session.setReadState(session.getReadState()); // dummy invocation to provoke epoch switch
		assertTrue(session.isRecordProcessable(session.getReadEpoch(), 0));
		assertTrue(session.isRecordProcessable(session.getReadEpoch(), 2));
	}

	@Test
	public void testConstructorEnforcesMaxSequenceNo() {
		session = new DTLSSession(PEER_ADDRESS, false, DtlsTestTools.MAX_SEQUENCE_NO); // should succeed
		try {
			session = new DTLSSession(PEER_ADDRESS, false, DtlsTestTools.MAX_SEQUENCE_NO + 1); // should fail
			fail("DTLSSession constructor should have refused initial sequence number > 2^48 - 1");
		} catch (IllegalArgumentException e) {
			// ok
		}
	}

	@Test(expected = IllegalStateException.class)
	public void testGetSequenceNumberEnforcesMaxSequenceNo() {
		session = new DTLSSession(PEER_ADDRESS, false, DtlsTestTools.MAX_SEQUENCE_NO);
		session.getSequenceNumber(); // should throw exception
	}

	@Test
	public void testSessionCanBeResumedFromSessionTicket() throws GeneralSecurityException {
		// GIVEN a session ticket for an established server session
		session = newEstablishedServerSession(PEER_ADDRESS, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, true);
		SessionTicket ticket = session.getSessionTicket();

		// WHEN creating a new session to be resumed from the ticket
		DTLSSession sessionToResume = new DTLSSession(session.getSessionIdentifier(), session.getPeer(), ticket, 1);

		// THEN the new session contains all relevant pending state to perform an abbreviated handshake
		assertThatSessionsHaveSameRelevantPropertiesForResumption(sessionToResume, session);
	}

	public static void assertThatSessionsHaveSameRelevantPropertiesForResumption(DTLSSession sessionToResume, DTLSSession establishedSession) {
		assertThat(sessionToResume.getSessionIdentifier(), is(establishedSession.getSessionIdentifier()));
		assertThat(sessionToResume.getCipherSuite(), is(establishedSession.getWriteState().getCipherSuite()));
		assertThat(sessionToResume.getCompressionMethod(), is(establishedSession.getWriteState().getCompressionMethod()));
		assertThat(sessionToResume.getMasterSecret(), is(establishedSession.getMasterSecret()));
		assertThat(sessionToResume.getPeerIdentity(), is(establishedSession.getPeerIdentity()));
	}

	public static DTLSSession newEstablishedServerSession(InetSocketAddress peerAddress, CipherSuite cipherSuite, boolean useRawPublicKeys) {
		DTLSSession session = new DTLSSession(peerAddress, false);
		DTLSConnectionState currentState = newConnectionState(cipherSuite);
		session.setSessionIdentifier(new SessionId());
		session.setReadState(currentState);
		session.setWriteState(currentState);
		session.setReceiveRawPublicKey(useRawPublicKeys);
		session.setSendRawPublicKey(useRawPublicKeys);
		session.setMasterSecret(getRandomBytes(48));
		session.setPeerIdentity(new PreSharedKeyIdentity("client_identity"));
		return session;
	}

	private static DTLSConnectionState newConnectionState(CipherSuite cipherSuite) {
		SecretKey macKey = null;
		if (cipherSuite.getMacKeyLength() > 0) {
			macKey = new SecretKeySpec(getRandomBytes(cipherSuite.getMacKeyLength()), "AES");
		}
		SecretKey encryptionKey = new SecretKeySpec(getRandomBytes(cipherSuite.getEncKeyLength()), "AES");
		IvParameterSpec iv = new IvParameterSpec(getRandomBytes(cipherSuite.getFixedIvLength()));
		return new DTLSConnectionState(cipherSuite, CompressionMethod.NULL, encryptionKey, iv, macKey);
	}

	private static byte[] getRandomBytes(int length) {
		byte[] result = new byte[length];
		RANDOM.nextBytes(result);
		return result;
	}

}
