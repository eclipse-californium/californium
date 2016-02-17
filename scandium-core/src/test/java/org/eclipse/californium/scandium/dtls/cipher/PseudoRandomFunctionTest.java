/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - refactored some Handshaker tests into separate class
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction.Label;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class PseudoRandomFunctionTest {

	@Before
	public void setUp() throws Exception {
	}

	@Test
	public void testDoPrfProducesDataOfCorrectLength() {
		byte[] secret = "secret".getBytes();
		byte[] seed = "seed".getBytes();
		byte[] data = PseudoRandomFunction.doPRF(secret, Label.MASTER_SECRET_LABEL, seed);
		assertThat(data.length, is(48));
		data = PseudoRandomFunction.doPRF(secret, Label.KEY_EXPANSION_LABEL, seed);
		assertThat(data.length, is(128));
		data = PseudoRandomFunction.doPRF(secret, Label.CLIENT_FINISHED_LABEL, seed);
		assertThat(data.length, is(12));
		data = PseudoRandomFunction.doPRF(secret, Label.SERVER_FINISHED_LABEL, seed);
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
		byte[] label = "test label".getBytes(StandardCharsets.UTF_8);
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

		byte[] data = PseudoRandomFunction.doPRF(secret, label, seed, expectedOutput.length);
		assertArrayEquals(expectedOutput, data);
	}
}
