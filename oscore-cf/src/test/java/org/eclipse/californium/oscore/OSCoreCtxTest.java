/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
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
 *    Tobias Andersson (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import static org.junit.Assert.*;

import java.util.Arrays;

import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import COSE.AlgorithmID;

public class OSCoreCtxTest {

	private final byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
			0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
			0x20, 0x21, 0x22, 0x23 };
	private final byte[] rid = new byte[] { 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 };
	private final byte[] sid = new byte[] { 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74 };
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
}
