/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
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
 *    Tobias Andersson (RISE SICS)
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.eclipse.californium.cose.AlgorithmID;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * Test generation of values in an OSCORE Context.
 *
 */
public class OSCoreCtxTest {

	private final byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
			0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] context_id = { 0x37, (byte) 0xCB, (byte) 0xF3, 0x21, 0x00, 0x17, (byte) 0xA2, (byte) 0xD3 };
	private final byte[] rid = new byte[] { 0x01 };
	private final byte[] sid = new byte[0];
	private final byte[] sid2 = new byte[] { 0x00 };
	private final AlgorithmID cipher = AlgorithmID.AES_CCM_16_64_128;
	private final AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	@Rule
	public final ExpectedException exception = ExpectedException.none();

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testMinimal() throws OSException {
		new OSCoreCtx(master_secret, true);
		new OSCoreCtx(master_secret, false);
		new OSCoreCtx(master_secret, true, cipher, sid, rid, kdf, 32, null, null);
	}

	@Test
	public void testMinimalNull() throws OSException {
		exception.expect(NullPointerException.class);
		new OSCoreCtx(null, true);
	}

	@Test
	public void testInitVariables() throws OSException {
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, cipher, sid, rid, kdf, 32, null, null);

		assertEquals(this.cipher, ctx.getAlg());
		assertEquals(this.kdf, ctx.getKdf());
		assertEquals(13, ctx.getIVLength());
		assertTrue(Arrays.equals(this.master_secret, ctx.getMasterSecret()));
		assertEquals(-1, ctx.getReceiverSeq());
		assertTrue(Arrays.equals(this.rid, ctx.getRecipientId()));
		assertTrue(Arrays.equals(this.sid, ctx.getSenderId()));
		assertEquals(0, ctx.getSenderSeq());
	}
	
	/**
	 * Tests generation of sender key with salt, without salt and with context ID.
	 * Test vectors are from OSCORE draft. (Test Vector 1-3)
	 * 
	 * @throws OSException if sender key generation fails
	 */
	@Test
	public void testSenderKey() throws OSException {
		//Test without salt
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, cipher, sid2, rid, kdf, 32, null, null);

		byte[] predictedSenderKey = { 0x32, 0x1b, 0x26, (byte) 0x94, 0x32, 0x53, (byte) 0xc7, (byte) 0xff,
				(byte) 0xb6, 0x00, 0x3b, 0x0b, 0x64, (byte) 0xd7, 0x40, 0x41 };		

		assertArrayEquals(predictedSenderKey, ctx.getSenderKey());
		
		//Test with salt
		ctx = new OSCoreCtx(master_secret, true, cipher, sid, rid, kdf, 32, master_salt, null);

		byte[] predictedSenderKeySalt = { (byte) 0xf0, (byte) 0x91, 0x0e, (byte) 0xd7, 0x29, 0x5e, 0x6a, (byte) 0xd4,
				(byte) 0xb5, 0x4f, (byte) 0xc7, (byte) 0x93, 0x15, 0x43, 0x02, (byte) 0xff };
		
		assertArrayEquals(predictedSenderKeySalt, ctx.getSenderKey());
		
		//Test with context ID and salt
		ctx = new OSCoreCtx(master_secret, true, cipher, sid, rid, kdf, 32, master_salt, context_id);

		byte[] predictedSenderKeyContextID = { (byte) 0xaf, 0x2a, 0x13, 0x00, (byte) 0xa5, (byte) 0xe9, 0x57, (byte) 0x88,
				(byte) 0xb3, 0x56, 0x33, 0x6e, (byte) 0xee, (byte) 0xcd, 0x2b, (byte) 0x92 };
		
		assertArrayEquals(predictedSenderKeyContextID, ctx.getSenderKey());
	}

	/**
	 * Tests generation of recipient key with salt, without salt and with context ID.
	 * Test vectors are from OSCORE draft. (Test Vector 1-3)
	 *
	 * @throws OSException if recipient key generation fails
	 */
	@Test
	public void testRecipientKey() throws OSException {
		//Test without salt
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, cipher, sid2, rid, kdf, 32, null, null);

		byte[] predictedRecipientKey = { (byte) 0xe5, 0x7b, 0x56, 0x35, (byte) 0x81, 0x51, 0x77, (byte) 0xcd,
				0x67, (byte) 0x9a, (byte) 0xb4, (byte) 0xbc, (byte) 0xec, (byte) 0x9d, 0x7d, (byte) 0xda };		

		assertArrayEquals(predictedRecipientKey, ctx.getRecipientKey());
		
		//Test with salt
		ctx = new OSCoreCtx(master_secret, true, cipher, sid, rid, kdf, 32, master_salt, null);

		byte[] predictedRecipientKeySalt = { (byte) 0xff, (byte) 0xb1, 0x4e, 0x09, 0x3c, (byte) 0x94, (byte) 0xc9, (byte) 0xca,
				(byte) 0xc9, 0x47, 0x16, 0x48, (byte) 0xb4, (byte) 0xf9, (byte) 0x87, 0x10 };
		
		assertArrayEquals(predictedRecipientKeySalt, ctx.getRecipientKey());
		
		//Test with context ID and salt
		ctx = new OSCoreCtx(master_secret, true, cipher, sid, rid, kdf, 32, master_salt, context_id);

		byte[] predictedRecipientKeyContextID = { (byte) 0xe3, (byte) 0x9a, 0x0c, 0x7c, 0x77, (byte) 0xb4, 0x3f, 0x03,
				(byte) 0xb4, (byte) 0xb3, (byte) 0x9a, (byte) 0xb9, (byte) 0xa2, 0x68, 0x69, (byte) 0x9f };
		
		assertArrayEquals(predictedRecipientKeyContextID, ctx.getRecipientKey());
	}
	
	/**
	 * Tests generation of common IV with salt, without salt and with context ID.
	 * Test vectors are from OSCORE draft. (Test Vector 1-3)
	 * 
	 * @throws OSException if common IV generation fails
	 */
	@Test
	public void testCommonIV() throws OSException {
		//Test without salt
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, cipher, sid2, rid, kdf, 32, null, null);

		byte[] predictedCommonIV = { (byte) 0xbe, 0x35, (byte) 0xae, 0x29, 0x7d, 0x2d, (byte) 0xac, (byte) 0xe9,
				0x10, (byte) 0xc5, 0x2e, (byte) 0x99, (byte) 0xf9 };
		
		assertArrayEquals(predictedCommonIV, ctx.getCommonIV());
		
		//Test with salt
		ctx = new OSCoreCtx(master_secret, true, cipher, sid, rid, kdf, 32, master_salt, null);

		byte[] predictedCommonIVSalt = { 0x46, 0x22, (byte) 0xd4, (byte) 0xdd, 0x6d, (byte) 0x94, 0x41, 0x68,
				(byte) 0xee, (byte) 0xfb, 0x54, (byte) 0x98, 0x7c };
		
		assertArrayEquals(predictedCommonIVSalt, ctx.getCommonIV());
		
		//Test with context ID and salt
		ctx = new OSCoreCtx(master_secret, true, cipher, sid, rid, kdf, 32, master_salt, context_id);

		byte[] predictedCommonIVContextID = { 0x2c, (byte) 0xa5, (byte) 0x8f, (byte) 0xb8, 0x5f, (byte) 0xf1, (byte) 0xb8, 0x1c,
				0x0b, 0x71, (byte) 0x81, (byte) 0xb8, 0x5e };
		
		assertArrayEquals(predictedCommonIVContextID, ctx.getCommonIV());
	}
}
