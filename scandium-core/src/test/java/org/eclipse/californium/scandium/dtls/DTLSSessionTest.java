/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.elements.auth.PreSharedKeyIdentity;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.util.SecretIvParameterSpec;
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
		session = new DTLSSession(PEER_ADDRESS);

		// then the max fragment size is as specified in DTLS spec
		assertThat(session.getMaxFragmentLength(), is(DEFAULT_MAX_FRAGMENT_LENGTH));
	}

	@Test
	public void testRecordFromPreviousEpochIsDiscarded() {
		session.setReadEpoch(1);
		assertFalse(session.isRecordProcessable(0, 15, 0));
	}

	@Test
	public void testRecordFromFutureEpochIsDiscarded() {
		session.setReadEpoch(1);
		assertFalse(session.isRecordProcessable(2, 15, 0));
	}

	@Test
	public void testRecordShiftsReceiveWindow() {
		int epoch = 0;
		session.setReadEpoch(epoch);
		//session.markRecordAsRead(epoch, 0);
		session.markRecordAsRead(epoch, 2);
		assertTrue(session.isRecordProcessable(0, 0, 0));
		assertTrue(session.isRecordProcessable(0, 1, 0));
		assertFalse(session.isRecordProcessable(0, 2, 0));
		assertTrue(session.isRecordProcessable(0, 64, 0));

		// make a right shift by 1 position
		session.markRecordAsRead(epoch, 64);
		assertFalse(session.isRecordProcessable(0, 0, 0));
		assertTrue(session.isRecordProcessable(0, 1, 0));
		assertFalse(session.isRecordProcessable(0, 2, 0));
		assertFalse(session.isRecordProcessable(0, 64, 0));
	}

	@Test
	public void testRecordShiftsReceiveWindowUsingWindowFilter() {
		int epoch = 0;
		session.setReadEpoch(epoch);
		//session.markRecordAsRead(epoch, 0);
		session.markRecordAsRead(epoch, 2);
		assertTrue(session.isRecordProcessable(0, 0, -1));
		assertTrue(session.isRecordProcessable(0, 1, -1));
		assertFalse(session.isRecordProcessable(0, 2, -1));
		assertTrue(session.isRecordProcessable(0, 64, -1));
		assertTrue(session.isRecordProcessable(0, 100, -1));

		// make a right shift by 1 position
		session.markRecordAsRead(epoch, 64);
		assertTrue(session.isRecordProcessable(0, 0, -1));
		assertTrue(session.isRecordProcessable(0, 1, -1));
		assertFalse(session.isRecordProcessable(0, 2, -1));
		assertFalse(session.isRecordProcessable(0, 64, -1));
		assertTrue(session.isRecordProcessable(0, 100, -1));
	}

	@Test
	public void testRecordShiftsReceiveWindowUsingExtendedWindowFilter() {
		int epoch = 0;
		session.setReadEpoch(epoch);
		//session.markRecordAsRead(epoch, 0);
		session.markRecordAsRead(epoch, 2);
		assertTrue(session.isRecordProcessable(0, 0, 8));
		assertTrue(session.isRecordProcessable(0, 1, 8));
		assertFalse(session.isRecordProcessable(0, 2, 8));
		assertTrue(session.isRecordProcessable(0, 64, 8));
		assertTrue(session.isRecordProcessable(0, 100, 8));

		// make a right shift by 16 position
		session.markRecordAsRead(epoch, 80);
		assertFalse(session.isRecordProcessable(0, 0, 8));
		assertFalse(session.isRecordProcessable(0, 1, 8));
		assertFalse(session.isRecordProcessable(0, 2, 8));
		assertFalse(session.isRecordProcessable(0, 12, 0));
		assertTrue(session.isRecordProcessable(0, 12, 8));
		assertFalse(session.isRecordProcessable(0, 80, 8));
		assertTrue(session.isRecordProcessable(0, 100, 8));
	}

	@Test
	public void testEpochSwitchResetsReceiveWindow() {

		int epoch = session.getReadEpoch();
		session.markRecordAsRead(epoch, 0);
		session.markRecordAsRead(epoch, 2);
		assertFalse(session.isRecordProcessable(session.getReadEpoch(), 0, 0));
		assertFalse(session.isRecordProcessable(session.getReadEpoch(), 2, 0));

		session.setReadState(session.getReadState()); // dummy invocation to provoke epoch switch
		assertTrue(session.isRecordProcessable(session.getReadEpoch(), 0, 0));
		assertTrue(session.isRecordProcessable(session.getReadEpoch(), 2, 0));
	}

	@Test
	public void testHigherSequenceNumberIsNewer() {

		int epoch = session.getReadEpoch();
		session.markRecordAsRead(epoch, 0);
		assertTrue(session.markRecordAsRead(epoch, 2));
	}

	@Test
	public void testLowerSequenceNumberIsNotNewer() {

		int epoch = session.getReadEpoch();
		session.markRecordAsRead(epoch, 2);
		assertFalse(session.markRecordAsRead(epoch, 0));
	}

	@Test
	public void testSameSequenceNumberIsNotNewer() {

		int epoch = session.getReadEpoch();
		session.markRecordAsRead(epoch, 2);
		assertFalse(session.markRecordAsRead(epoch, 2));
	}

	@Test
	public void testHigherEpochIsNewer() {
		int epoch = session.getReadEpoch();
		session.markRecordAsRead(epoch, 2);
		assertTrue(session.markRecordAsRead(epoch + 1, 0));
	}

	@Test
	public void testLowerEpochIsNotNewer() {
		int epoch = session.getReadEpoch();
		session.markRecordAsRead(epoch, 0);
		assertFalse(session.markRecordAsRead(epoch - 1, 2));
	}

	@Test
	public void testConstructorEnforcesMaxSequenceNo() {
		session = new DTLSSession(PEER_ADDRESS, DtlsTestTools.MAX_SEQUENCE_NO); // should succeed
		try {
			session = new DTLSSession(PEER_ADDRESS, DtlsTestTools.MAX_SEQUENCE_NO + 1); // should fail
			fail("DTLSSession constructor should have refused initial sequence number > 2^48 - 1");
		} catch (IllegalArgumentException e) {
			// ok
		}
	}

	@Test(expected = IllegalStateException.class)
	public void testGetSequenceNumberEnforcesMaxSequenceNo() {
		session = new DTLSSession(PEER_ADDRESS, DtlsTestTools.MAX_SEQUENCE_NO);
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

	@Test
	public void testSessionWithServerNamesCanBeResumedFromSessionTicket() throws GeneralSecurityException {
		// GIVEN a session ticket for an established server session
		session = newEstablishedServerSession(PEER_ADDRESS, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, true);
		session.setHostName("test");
		SessionTicket ticket = session.getSessionTicket();

		// WHEN creating a new session to be resumed from the ticket
		DTLSSession sessionToResume = new DTLSSession(session.getSessionIdentifier(), session.getPeer(), ticket, 1);

		// THEN the new session contains all relevant pending state to perform an abbreviated handshake
		assertThatSessionsHaveSameRelevantPropertiesForResumption(sessionToResume, session);
	}

	@Test
	public void testSessionCanBeResumedFromSerializedSessionTicket() throws GeneralSecurityException {
		// GIVEN a session ticket for an established server session
		session = newEstablishedServerSession(PEER_ADDRESS, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, true);
		SessionTicket ticket = serialize(session.getSessionTicket());

		// WHEN creating a new session to be resumed from the ticket
		DTLSSession sessionToResume = new DTLSSession(session.getSessionIdentifier(), session.getPeer(), ticket, 1);

		// THEN the new session contains all relevant pending state to perform an abbreviated handshake
		assertThatSessionsHaveSameRelevantPropertiesForResumption(sessionToResume, session);
	}

	@Test
	public void testSessionWithServerNamesCanBeResumedFromSerializedSessionTicket() throws GeneralSecurityException {
		// GIVEN a session ticket for an established server session
		session = newEstablishedServerSession(PEER_ADDRESS, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, true);
		session.setHostName("test");
		SessionTicket ticket = serialize(session.getSessionTicket());

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
		assertThat(sessionToResume.getServerNames(), is(establishedSession.getServerNames()));
	}

	public static DTLSSession newEstablishedServerSession(InetSocketAddress peerAddress, CipherSuite cipherSuite, boolean useRawPublicKeys) {
		CertificateType type = useRawPublicKeys ? CertificateType.RAW_PUBLIC_KEY : CertificateType.X_509;
		DTLSSession session = new DTLSSession(peerAddress);
		DTLSConnectionState currentState = newConnectionState(cipherSuite);
		session.setSessionIdentifier(new SessionId());
		session.setReadState(currentState);
		session.setWriteState(currentState);
		session.setReceiveCertificateType(type);
		session.setSendCertificateType(type);
		session.setMasterSecret(new SecretKeySpec(getRandomBytes(48), "MAC"));
		session.setPeerIdentity(new PreSharedKeyIdentity("client_identity"));
		return session;
	}

	private static DTLSConnectionState newConnectionState(CipherSuite cipherSuite) {
		SecretKey macKey = null;
		if (cipherSuite.getMacKeyLength() > 0) {
			macKey = new SecretKeySpec(getRandomBytes(cipherSuite.getMacKeyLength()), "AES");
		}
		SecretKey encryptionKey = new SecretKeySpec(getRandomBytes(cipherSuite.getEncKeyLength()), "AES");
		SecretIvParameterSpec iv = new SecretIvParameterSpec(getRandomBytes(cipherSuite.getFixedIvLength()));
		return DTLSConnectionState.create(cipherSuite, CompressionMethod.NULL, encryptionKey, iv, macKey);
	}

	private static byte[] getRandomBytes(int length) {
		byte[] result = new byte[length];
		RANDOM.nextBytes(result);
		return result;
	}
	
	private static SessionTicket serialize(SessionTicket ticket) {
		DatagramWriter writer = new DatagramWriter(true);
		ticket.encode(writer);
		byte[] ticketBytes = writer.toByteArray();
		DatagramReader reader = new DatagramReader(ticketBytes);
		SessionTicket result = SessionTicket.decode(reader);
		Bytes.clear(ticketBytes);
		writer.close();
		return result;
	}

}
