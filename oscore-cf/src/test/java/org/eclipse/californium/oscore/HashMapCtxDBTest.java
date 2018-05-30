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

import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import COSE.AlgorithmID;

public class HashMapCtxDBTest {

	private final Token token = new Token(new byte[] { 0x09, 0x08, 0x07, 0x06 });
	private final Token modifiedToken = new Token(new byte[] { 0x08, 0x07, 0x06, 0x05 });
	private final String uri = "coap/hello/1";
	private final String modifiedUri = "coap://localhost";
	private final byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
			0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
			0x20, 0x21, 0x22, 0x23 };
	private final AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final byte[] rid = new byte[] { 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 };
	private final byte[] sid = new byte[] { 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74 };
	private final byte[] modifiedRid = new byte[] { 0x01, 0x65, 0x72, 0x76, 0x65, 0x72 };
	private final Integer seq = 42;

	@Rule
	public final ExpectedException exception = ExpectedException.none();

	@Before
	public void setUp() throws Exception {
		HashMapCtxDB db = HashMapCtxDB.getInstance();
		db.purge();
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testGetContextNull() throws OSException {
		HashMapCtxDB db = HashMapCtxDB.getInstance();

		assertNull(db.getContext(rid));
		assertNull(db.getContext(uri));
		assertNull(db.getContextByToken(token));
	}

	@Test
	public void testAddGetContextRid() throws OSException {
		HashMapCtxDB db = HashMapCtxDB.getInstance();
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, AlgorithmID.HKDF_HMAC_SHA_256, 32, null,
				null);
		db.addContext(ctx);

		assertEquals(ctx, db.getContext(rid));
		assertNull(db.getContext(modifiedRid));
		assertNull(db.getContext(uri));
		assertNull(db.getContextByToken(token));
	}

	@Test
	public void testAddGetContextUri() throws OSException {
		HashMapCtxDB db = HashMapCtxDB.getInstance();
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, AlgorithmID.HKDF_HMAC_SHA_256, 32, null,
				null);
		db.addContext(uri, ctx);

		assertEquals(ctx, db.getContext(rid));
		assertNull(db.getContext(modifiedRid));
		assertEquals(ctx, db.getContext(uri));
		assertNull(db.getContext(modifiedUri));
		assertNull(db.getContextByToken(token));
	}

	@Test
	public void testAddGetContextToken() throws OSException {
		HashMapCtxDB db = HashMapCtxDB.getInstance();
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, AlgorithmID.HKDF_HMAC_SHA_256, 32, null,
				null);
		db.addContext(token, ctx);

		assertEquals(ctx, db.getContext(rid));
		assertNull(db.getContext(modifiedRid));
		assertNull(db.getContext(uri));
		assertEquals(ctx, db.getContextByToken(token));
		assertNull(db.getContextByToken(modifiedToken));
	}

	@Test
	public void testNullSeqByToken() throws OSException {
		HashMapCtxDB db = HashMapCtxDB.getInstance();
		exception.expect(NullPointerException.class);

		db.addSeqByToken(token, null);
	}

	@Test
	public void testSeqByNullToken() throws OSException {
		HashMapCtxDB db = HashMapCtxDB.getInstance();
		exception.expect(NullPointerException.class);

		db.addSeqByToken(null, seq);
	}

	@Test
	public void testSeqBytToken() throws OSException {
		HashMapCtxDB db = HashMapCtxDB.getInstance();
		db.addSeqByToken(token, seq);

		assertEquals(seq, db.getSeqByToken(token));
		assertNull(db.getSeqByToken(modifiedToken));
	}

	@Test
	public void testRemoveSeqBytToken() throws OSException {
		HashMapCtxDB db = HashMapCtxDB.getInstance();
		db.addSeqByToken(token, seq);
		db.removeSeqByToken(token);

		assertNull(db.getSeqByToken(token));
		assertFalse(db.tokenExist(token));
	}

	@Test
	public void testUpdateNonExistentSeqByToken() {
		HashMapCtxDB db = HashMapCtxDB.getInstance();

		try {
			db.updateSeqByToken(null, seq);
			db.updateSeqByToken(token, 44);
		} catch (NullPointerException e) {
			assertEquals(ErrorDescriptions.TOKEN_NULL, e.getMessage());
		}

		try {
			db.updateSeqByToken(token, -5);
		} catch (Exception e) {
			assertEquals(ErrorDescriptions.SEQ_NBR_INVALID, e.getMessage());
		}

		assertFalse(db.tokenExist(token));
		assertNull(db.getSeqByToken(token));
	}

	@Test
	public void testTokenExists() throws OSException {
		HashMapCtxDB db = HashMapCtxDB.getInstance();
		db.addSeqByToken(token, seq);

		assertTrue(db.tokenExist(token));
		assertFalse(db.tokenExist(modifiedToken));
	}
}
