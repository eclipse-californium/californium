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

import org.eclipse.californium.oscore.ByteId;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class ByteIdTest {

	private final byte[] iv1 = new byte[] { 0x01, 0x02 };
	private final byte[] iv2 = new byte[] { 0x01, 0x02 };
	private final byte[] iv3 = new byte[] { 0x02, 0x01 };
	private final byte[] iv4 = new byte[] { 0x00, 0x01, 0x02 };

	@Rule
	public final ExpectedException exception = ExpectedException.none();

	@Test
	public void testConstructor() {
		exception.expect(NullPointerException.class);
		new ByteId(null);
	}

	@Test
	public void testEquals() {
		ByteId bId1 = new ByteId(iv1);
		ByteId bId2 = new ByteId(iv2);

		int b1 = bId1.hashCode();
		int b2 = bId2.hashCode();

		boolean result = Arrays.equals(iv1, iv2);
		boolean result2 = bId1.equals(bId2);

		assertTrue(result);
		assertTrue(result2);
		assertEquals(b1, b2);
	}

	@Test
	public void testNonEqual() {
		ByteId bId1 = new ByteId(iv1);
		ByteId bId2 = new ByteId(iv3);

		int b1 = bId1.hashCode();
		int b2 = bId2.hashCode();

		boolean result = Arrays.equals(iv1, iv3);

		assertFalse(result);
		assertNotEquals(b1, b2);
	}
}
