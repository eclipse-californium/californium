/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class DatagramWriterTest {

	@Rule
	public ExpectedException exception = ExpectedException.none();

	DatagramWriter writer;

	@Before
	public void setUp() throws Exception {
		writer = new DatagramWriter(32);
	}

	@Test
	public void testWrite() {
		writer.write(0x123456, 24);
		byte[] data = writer.toByteArray();
		assertEquals("123456", hex(data));
	}

	@Test
	public void testWriteOdd() {
		writer.write(0x8, 4);
		writer.write(0x123456, 22);
		byte[] data = writer.toByteArray();
		assertEquals("848D1580", hex(data));
	}

	@Test
	public void testWriteTooLarge() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("Truncating");
		writer.write(0x123456, 16);
	}

	@Test
	public void testWriteTooLargeNegativeValue() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("Truncating");
		writer.write(-1, 16);
	}

	@Test
	public void testWriteTooManyBits() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("Number of bits ");
		writer.write(1, 33);
	}

	@Test
	public void testWriteFull() {
		writer.write(-1, 32);
		byte[] data = writer.toByteArray();
		assertEquals("FFFFFFFF", hex(data));
	}

	@Test
	public void testWriteLong() {
		writer.writeLong(0x123456abcdL, 48);
		byte[] data = writer.toByteArray();
		assertEquals("00123456ABCD", hex(data));
	}

	@Test
	public void testWriteLongOdd() {
		writer.write(0x8, 4);
		writer.writeLong(0x123456abcdL, 48);
		byte[] data = writer.toByteArray();
		assertEquals("800123456ABCD0", hex(data));
	}

	@Test
	public void testWriteLongTooLarge() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("Truncating");
		writer.writeLong(0x123456abcdL, 36);
	}

	@Test
	public void testWriteLongTooLargeNegativeValue() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("Truncating");
		writer.writeLong(-1L, 36);
	}

	@Test
	public void testWriteLongTooManyBits() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("Number of bits ");
		writer.writeLong(1L, 65);
	}

	@Test
	public void testWriteFullLong() {
		writer.writeLong(-1L, 64);
		byte[] data = writer.toByteArray();
		assertEquals("FFFFFFFFFFFFFFFF", hex(data));
	}

	@Test
	public void testWriteByte() {
		writer.writeByte((byte) 0x7a);
		byte[] data = writer.toByteArray();
		assertEquals("7A", hex(data));
	}

	@Test
	public void testWriteByteOdd() {
		writer.write(0x8, 6);
		writer.writeByte((byte) 0x7a);
		byte[] data = writer.toByteArray();
		assertEquals("21E8", hex(data));
	}

	@Test
	public void testWriteByteOddNegativeValue() {
		writer.write(0x8, 6);
		writer.writeByte((byte) -1);
		byte[] data = writer.toByteArray();
		assertEquals("23FC", hex(data));
	}

	@Test
	public void testWriteBytes() {
		byte[] data = bin("ab12def671223344556677890a");
		writer.writeBytes(data);
		byte[] wdata = writer.toByteArray();
		assertEquals(hex(data), hex(wdata));
	}

	@Test
	public void testWriteBytesOdd() {
		writer.write(0x6, 4);
		byte[] data = bin("ab12def671223344556677890a");
		writer.writeBytes(data);
		byte[] wdata = writer.toByteArray();
		assertEquals("6" + hex(data) + "0", hex(wdata));
	}

	@Test
	public void testWriteDatagramWriter() {
		writer.writeBytes(bin("1234"));
		DatagramWriter writer2 = new DatagramWriter(16);
		writer2.writeBytes(bin("5678"));
		writer.write(writer2);
		byte[] data = writer.toByteArray();
		assertEquals("12345678", hex(data));
	}

	private static byte[] bin(String hex) {
		return StringUtil.hex2ByteArray(hex);
	}

	private static String hex(byte[] data) {
		return StringUtil.byteArray2Hex(data);
	}
}
