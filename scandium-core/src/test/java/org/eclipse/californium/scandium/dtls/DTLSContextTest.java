/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - derived from DatagramReader
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.util.SecretIvParameterSpec;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class DTLSContextTest {

	static final int DEFAULT_MAX_FRAGMENT_LENGTH = 16384; //2^14 as defined in DTLS 1.2 spec
	private static final Random RANDOM = new Random();
	DTLSContext context;

	@Before
	public void setUp() throws Exception {
		context = newEstablishedServerDtlsContext(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CertificateType.X_509);
	}

	@Test (expected = IllegalArgumentException.class)
	public void testRecordFromPreviousEpochIsDiscarded() {
		context.setReadEpoch(1);
		context.isRecordProcessable(0, 15, 0);
	}

	@Test (expected = IllegalArgumentException.class)
	public void testRecordFromFutureEpochIsDiscarded() {
		context.setReadEpoch(1);
		context.isRecordProcessable(2, 15, 0);
	}

	@Test
	public void testRecordShiftsReceiveWindow() {
		int epoch = 0;
		context.setReadEpoch(epoch);
		//session.markRecordAsRead(epoch, 0);
		context.markRecordAsRead(epoch, 2);
		assertTrue(context.isRecordProcessable(0, 0, 0));
		assertTrue(context.isRecordProcessable(0, 1, 0));
		assertFalse(context.isRecordProcessable(0, 2, 0));
		assertTrue(context.isRecordProcessable(0, 64, 0));

		// make a right shift by 1 position
		context.markRecordAsRead(epoch, 64);
		assertFalse(context.isRecordProcessable(0, 0, 0));
		assertTrue(context.isRecordProcessable(0, 1, 0));
		assertFalse(context.isRecordProcessable(0, 2, 0));
		assertFalse(context.isRecordProcessable(0, 64, 0));

		DTLSContext context2 = reload(context);
		assertThat(context2, is(context));
	}

	@Test
	public void testRecordShiftsReceiveWindowUsingWindowFilter() {
		int epoch = 0;
		context.setReadEpoch(epoch);
		//session.markRecordAsRead(epoch, 0);
		context.markRecordAsRead(epoch, 2);
		assertTrue(context.isRecordProcessable(0, 0, -1));
		assertTrue(context.isRecordProcessable(0, 1, -1));
		assertFalse(context.isRecordProcessable(0, 2, -1));
		assertTrue(context.isRecordProcessable(0, 64, -1));
		assertTrue(context.isRecordProcessable(0, 100, -1));

		// make a right shift by 1 position
		context.markRecordAsRead(epoch, 64);
		assertTrue(context.isRecordProcessable(0, 0, -1));
		assertTrue(context.isRecordProcessable(0, 1, -1));
		assertFalse(context.isRecordProcessable(0, 2, -1));
		assertFalse(context.isRecordProcessable(0, 64, -1));
		assertTrue(context.isRecordProcessable(0, 100, -1));

		DTLSContext context2 = reload(context);
		assertThat(context2, is(context));
	}

	@Test
	public void testRecordShiftsReceiveWindowUsingExtendedWindowFilter() {
		int epoch = 0;
		context.setReadEpoch(epoch);
		//session.markRecordAsRead(epoch, 0);
		context.markRecordAsRead(epoch, 2);
		assertTrue(context.isRecordProcessable(0, 0, 8));
		assertTrue(context.isRecordProcessable(0, 1, 8));
		assertFalse(context.isRecordProcessable(0, 2, 8));
		assertTrue(context.isRecordProcessable(0, 64, 8));
		assertTrue(context.isRecordProcessable(0, 100, 8));

		// make a right shift by 16 position
		context.markRecordAsRead(epoch, 80);
		assertFalse(context.isRecordProcessable(0, 0, 8));
		assertFalse(context.isRecordProcessable(0, 1, 8));
		assertFalse(context.isRecordProcessable(0, 2, 8));
		assertFalse(context.isRecordProcessable(0, 12, 0));
		assertTrue(context.isRecordProcessable(0, 12, 8));
		assertFalse(context.isRecordProcessable(0, 80, 8));
		assertTrue(context.isRecordProcessable(0, 100, 8));

		DTLSContext context2 = reload(context);
		assertThat(context2, is(context));
	}

	@Test
	public void testEpochSwitchResetsReceiveWindow() {

		int epoch = context.getReadEpoch();
		context.markRecordAsRead(epoch, 0);
		context.markRecordAsRead(epoch, 2);
		assertFalse(context.isRecordProcessable(context.getReadEpoch(), 0, 0));
		assertFalse(context.isRecordProcessable(context.getReadEpoch(), 2, 0));

		context.incrementReadEpoch();
		assertTrue(context.isRecordProcessable(context.getReadEpoch(), 0, 0));
		assertTrue(context.isRecordProcessable(context.getReadEpoch(), 2, 0));

		DTLSContext context2 = reload(context);
		assertThat(context2, is(context));
	}

	@Test
	public void testHigherSequenceNumberIsNewer() {

		int epoch = context.getReadEpoch();
		context.markRecordAsRead(epoch, 0);
		assertTrue(context.markRecordAsRead(epoch, 2));
	}

	@Test
	public void testLowerSequenceNumberIsNotNewer() {

		int epoch = context.getReadEpoch();
		context.markRecordAsRead(epoch, 2);
		assertFalse(context.markRecordAsRead(epoch, 0));
	}

	@Test
	public void testSameSequenceNumberIsNotNewer() {

		int epoch = context.getReadEpoch();
		context.markRecordAsRead(epoch, 2);
		assertFalse(context.markRecordAsRead(epoch, 2));
	}

	@Test (expected = IllegalArgumentException.class)
	public void testHigherEpochFails() {
		int epoch = context.getReadEpoch();
		context.markRecordAsRead(epoch, 2);
		context.markRecordAsRead(epoch + 1, 0);
	}

	@Test (expected = IllegalArgumentException.class)
	public void testLowerEpochFails() {
		int epoch = context.getReadEpoch();
		context.markRecordAsRead(epoch, 0);
		context.markRecordAsRead(epoch - 1, 2);
	}

	@Test
	public void testConstructorEnforcesMaxSequenceNo() {
		context = new DTLSContext(new DTLSSession(), Record.MAX_SEQUENCE_NO); // should succeed
		try {
			context = new DTLSContext(new DTLSSession(), Record.MAX_SEQUENCE_NO + 1); // should fail
			fail("DTLSSession constructor should have refused initial sequence number > 2^48 - 1");
		} catch (IllegalArgumentException e) {
			// ok
		}
	}

	@Test(expected = IllegalStateException.class)
	public void testGetSequenceNumberEnforcesMaxSequenceNo() {
		context = new DTLSContext(new DTLSSession(), Record.MAX_SEQUENCE_NO);
		context.getNextSequenceNumber(); // should succeed
		context.getNextSequenceNumber(); // should throw exception
	}

	public static DTLSContext newEstablishedServerDtlsContext(CipherSuite cipherSuite, CertificateType type) {
		SecretKey macKey = null;
		if (cipherSuite.getMacKeyLength() > 0) {
			macKey = new SecretKeySpec(getRandomBytes(cipherSuite.getMacKeyLength()), "AES");
		}
		SecretKey encryptionKey = new SecretKeySpec(getRandomBytes(cipherSuite.getEncKeyLength()), "AES");
		SecretIvParameterSpec iv = new SecretIvParameterSpec(getRandomBytes(cipherSuite.getFixedIvLength()));

		DTLSSession session = DTLSSessionTest.newEstablishedServerSession(cipherSuite, type);
		DTLSContext context = new DTLSContext(session, 0);
		context.createReadState(encryptionKey, iv, macKey);
		context.createWriteState(encryptionKey, iv, macKey);
		return context;
	}

	private static DTLSContext reload(DTLSContext context) {
		DatagramWriter writer = new DatagramWriter();
		if (context.write(writer)) {
			DatagramReader reader = new DatagramReader(writer.toByteArray());
			return DTLSContext.fromReader(reader);
		}
		return null;
	}

	private static byte[] getRandomBytes(int length) {
		byte[] result = new byte[length];
		RANDOM.nextBytes(result);
		return result;
	}
	
}
