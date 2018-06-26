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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.OptionSet;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import COSE.AlgorithmID;

public class OSSerializerTest {

	private final static byte[] payload = new byte[] { 0x01, 0x02 };
	private final static int realCode = 1;

	// test vector OSCORE draft Appendix C.1.1
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] sid = new byte[0];
	private final static byte[] rid = new byte[] { 0x01 };
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	private final static OptionSet options = new OptionSet();
	private final static boolean newPartialIV = false;
	private final static int version = CoAP.VERSION;
	private final static int seq = 1;
	private final static byte[] partialIV = new byte[] { 0x01 };

	private static OSCoreCtx ctx = null;

	@Rule
	public final ExpectedException exception = ExpectedException.none();

	@Before
	public void setUp() throws Exception {
		ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null);
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testserializeConfidentialDataNullOptionSet() {
		exception.expect(NullPointerException.class);
		OSSerializer.serializeConfidentialData(null, payload, realCode);
	}

	@Test
	public void testserializeConfidentialDataNullPayload() {
		OSSerializer.serializeConfidentialData(new OptionSet(), null, realCode);
	}

	@Test
	public void testserializeConfidentialDataNotRealCode() {
		exception.expect(IllegalArgumentException.class);
		OSSerializer.serializeConfidentialData(options, payload, -1);
	}

	@Test
	public void testserializeSendResponseAADVersionInvalid() {
		exception.expect(IllegalArgumentException.class);
		OSSerializer.serializeSendResponseAAD(-1, ctx, options, newPartialIV);
	}

	@Test
	public void testserializeSendResponseAADCtxNull() {
		exception.expect(NullPointerException.class);
		OSSerializer.serializeSendResponseAAD(version, null, options, newPartialIV);
	}

	@Test
	public void testserializeSendResponseAADOptionsNull() {
		exception.expect(NullPointerException.class);
		OSSerializer.serializeSendResponseAAD(version, ctx, null, newPartialIV);
	}

	@Test
	public void testserializeReceiveResponseAADVersionInvalid() {
		exception.expect(IllegalArgumentException.class);
		OSSerializer.serializeReceiveResponseAAD(-1, seq, ctx, options);
	}

	@Test
	public void testserializeReceiveResponseAADSeqInvalid() {
		exception.expect(IllegalArgumentException.class);
		OSSerializer.serializeReceiveResponseAAD(version, -5, ctx, options);
	}

	@Test
	public void testserializeReceiveResponseAADCtxNull() {
		exception.expect(NullPointerException.class);
		OSSerializer.serializeReceiveResponseAAD(version, seq, null, options);
	}

	@Test
	public void testserializeReceiveResponseAADOptionsNull() {
		exception.expect(NullPointerException.class);
		OSSerializer.serializeReceiveResponseAAD(version, seq, ctx, null);
	}

	@Test
	public void testserializeSendRequestAADVersionInvalid() {
		exception.expect(IllegalArgumentException.class);
		OSSerializer.serializeSendRequestAAD(-1, ctx, options);
	}

	@Test
	public void testserializeSendRequestAADCtxNull() {
		exception.expect(NullPointerException.class);
		OSSerializer.serializeSendRequestAAD(version, null, options);
	}

	@Test
	public void testserializeSendRequestAADOptionsNull() {
		exception.expect(NullPointerException.class);
		OSSerializer.serializeSendRequestAAD(version, ctx, null);
	}

	@Test
	public void testserializeReceiveRequestAADVersionInvalid() {
		exception.expect(IllegalArgumentException.class);
		OSSerializer.serializeReceiveRequestAAD(-1, seq, ctx, options);
	}

	@Test
	public void testserializeReceiveRequestAADSeqInvalid() {
		exception.expect(IllegalArgumentException.class);
		OSSerializer.serializeReceiveRequestAAD(version, -5, ctx, options);
	}

	@Test
	public void testserializeReceiveRequestAADCtxNull() {
		exception.expect(NullPointerException.class);
		OSSerializer.serializeReceiveRequestAAD(version, seq, null, options);
	}

	@Test
	public void testserializeReceiveRequestAADOptionsNull() {
		exception.expect(NullPointerException.class);
		OSSerializer.serializeReceiveRequestAAD(version, seq, ctx, null);
	}

	@Test
	public void testnonceGenerationPartialIVNull() throws OSException {
		exception.expect(NullPointerException.class);
		OSSerializer.nonceGeneration(null, sid, ctx.getCommonIV(), ctx.getIVLength());
	}

	@Test
	public void testnonceGenerationSidNull() throws OSException {
		exception.expect(NullPointerException.class);
		OSSerializer.nonceGeneration(partialIV, null, ctx.getCommonIV(), ctx.getIVLength());
	}

	@Test
	public void testnonceGenerationCommonIVNull() throws OSException {
		exception.expect(NullPointerException.class);
		OSSerializer.nonceGeneration(partialIV, sid, null, ctx.getIVLength());
	}

	@Test
	public void testnonceGenerationNonceLengthInvalid() throws OSException {
		exception.expect(IllegalArgumentException.class);
		OSSerializer.nonceGeneration(partialIV, sid, ctx.getCommonIV(), -5);
	}

	@Test
	public void testLeftPadding() {
		byte[] paddMe = new byte[] { 0x01, 0x02 };
		byte[] expected = new byte[] { 0x00, 0x00, 0x01, 0x02 };
		int zeros = 2;

		byte[] updated = OSSerializer.leftPaddingZeroes(paddMe, zeros);

		assertTrue(Arrays.equals(expected, updated));
	}
}
