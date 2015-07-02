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

import java.net.InetSocketAddress;

import org.eclipse.californium.scandium.category.Small;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class DTLSSessionTest {

	InetSocketAddress peerAddress;
	DTLSSession session;
	
	@Before
	public void setUp() throws Exception {
		peerAddress = new InetSocketAddress(5000);
		session = new DTLSSession(peerAddress, false);
	}

	@Test
	public void testRecordFromPreviousEpochIsDiscarded() {
		session.setReadEpoch(1);
		Assert.assertFalse(session.isRecordProcessable(0, 15));
	}

	@Test
	public void testRecordFromFutureEpochIsDiscarded() {
		session.setReadEpoch(1);
		Assert.assertFalse(session.isRecordProcessable(2, 15));
	}

	@Test
	public void testRecordShiftsReceiveWindow() {
		int epoch = 0;
		session.setReadEpoch(epoch);
		session.markRecordAsRead(epoch, 0);
		session.markRecordAsRead(epoch, 2);
		Assert.assertFalse(session.isRecordProcessable(0, 0));
		Assert.assertTrue(session.isRecordProcessable(0, 1));
		Assert.assertFalse(session.isRecordProcessable(0, 2));
		Assert.assertTrue(session.isRecordProcessable(0, 64));

		// make a right shift by 1 position
		session.markRecordAsRead(epoch, 64);
		Assert.assertFalse(session.isRecordProcessable(0, 0));
		Assert.assertTrue(session.isRecordProcessable(0, 1));
		Assert.assertFalse(session.isRecordProcessable(0, 2));
		Assert.assertFalse(session.isRecordProcessable(0, 64));
	}
	
	@Test
	public void testEpochSwitchResetsReceiveWindow() {

		int epoch = session.getReadEpoch();
		session.markRecordAsRead(epoch, 0);
		session.markRecordAsRead(epoch, 2);
		Assert.assertFalse(session.isRecordProcessable(session.getReadEpoch(), 0));
		Assert.assertFalse(session.isRecordProcessable(session.getReadEpoch(), 2));
		
		session.setReadState(session.getReadState()); // dummy invocation to provoke epoch switch
		Assert.assertTrue(session.isRecordProcessable(session.getReadEpoch(), 0));
		Assert.assertTrue(session.isRecordProcessable(session.getReadEpoch(), 2));
		
	}
	
	@Test
	public void testConstructorEnforcesMaxSequenceNo() {
		session = new DTLSSession(peerAddress, false, DtlsTestTools.MAX_SEQUENCE_NO); // should succeed
		try {
			session = new DTLSSession(peerAddress, false, DtlsTestTools.MAX_SEQUENCE_NO + 1); // should fail
			Assert.fail("DTLSSession constructor should have refused initial sequence number > 2^48 - 1");
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
