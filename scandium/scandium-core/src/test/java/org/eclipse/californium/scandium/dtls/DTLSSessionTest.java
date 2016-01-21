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

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class DTLSSessionTest {

	static final int DEFAULT_MAX_FRAGMENT_LENGTH = 16384; //2^14 as defined in DTLS 1.2 spec
	InetSocketAddress peerAddress;
	DTLSSession session;

	@Before
	public void setUp() throws Exception {
		peerAddress = new InetSocketAddress(InetAddress.getLocalHost(), 0);
		session = new DTLSSession(peerAddress, false);
	}

	@Test
	public void testDefaultMaxFragmentLengthCompliesWithSpec() {
		// when instantiating a default server session
		session = new DTLSSession(peerAddress, false);

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
		session = new DTLSSession(peerAddress, false, DtlsTestTools.MAX_SEQUENCE_NO); // should succeed
		try {
			session = new DTLSSession(peerAddress, false, DtlsTestTools.MAX_SEQUENCE_NO + 1); // should fail
			fail("DTLSSession constructor should have refused initial sequence number > 2^48 - 1");
		} catch (IllegalArgumentException e) {
			// ok
		}
	}

	@Test(expected = IllegalStateException.class)
	public void testGetSequenceNumberEnforcesMaxSequenceNo() {
		session = new DTLSSession(peerAddress, false, DtlsTestTools.MAX_SEQUENCE_NO);
		session.getSequenceNumber(); // should throw exception
	}
}
