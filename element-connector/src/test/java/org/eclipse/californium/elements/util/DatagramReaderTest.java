/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import org.junit.Before;
import org.junit.Test;

public class DatagramReaderTest {

	DatagramReader reader;

	@Before
	public void setUp() throws Exception {
	}

	@Test
	public void testBitsLeftWorksForEmptyBuffer() {
		givenABuffer(Bytes.EMPTY);
		assertThat(reader.bitsLeft(), is(0));
	}

	@Test
	public void testBitsLeftWorksForByteWiseReading() {
		givenABuffer(new byte[] { 0x01, 0x02, 0x03 });
		assertThat(reader.bitsLeft(), is(24));

		reader.readBytes(1);
		assertThat(reader.bitsLeft(), is(16));

		reader.readBytes(1);
		assertThat(reader.bitsLeft(), is(8));
		reader.readBytes(1);
		assertThat(reader.bitsLeft(), is(0));
	}

	@Test
	public void testBitsLeftWorksForBitWiseReading() {
		givenABuffer(new byte[] { 0x01, 0x02, 0x03 });

		reader.read(6);
		assertThat(reader.bitsLeft(), is(18));

		reader.readBytes(1);
		assertThat(reader.bitsLeft(), is(10));

		reader.read(10);
		assertThat(reader.bitsLeft(), is(0));
	}

	@Test
	public void testMarkAndResetBits() {
		givenABuffer(new byte[] { 0x01, 0x02, 0x03 });

		int value = reader.read(6);
		assertThat(value, is(0));
		assertThat(reader.bitsLeft(), is(18));

		reader.mark();

		value = reader.readBytes(1)[0] & 0xff;
		assertThat(value, is(0x40));
		assertThat(reader.bitsLeft(), is(10));

		reader.reset();
		assertThat(reader.bitsLeft(), is(18));

		value = reader.readBytes(1)[0] & 0xff;
		assertThat(value, is(0x40));
		assertThat(reader.bitsLeft(), is(10));
	}

	@Test
	public void testMarkAndResetBytes() {
		givenABuffer(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 });

		int value = reader.read(Byte.SIZE);
		assertThat(value, is(1));

		value = reader.read(Byte.SIZE);
		assertThat(value, is(2));

		reader.mark();

		value = reader.read(Byte.SIZE);
		assertThat(value, is(3));

		value = reader.read(Byte.SIZE);
		assertThat(value, is(4));

		reader.reset();
		byte[] bytes = reader.readBytes(4);
		assertThat(bytes, is(new byte[] { 0x03, 0x04, 0x05, 0x06 }));
	}

	@Test
	public void testSkipBytes() {
		givenABuffer(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 });

		assertThat(reader.skip(8), is(8L));

		int value = reader.read(Byte.SIZE);
		assertThat(value, is(2));

		assertThat(reader.skip(12), is(12L));

		value = reader.read(Byte.SIZE);
		assertThat(value, is(0x40));

		assertThat(reader.skip(24), is(12L));

	}

	@Test (expected = IllegalArgumentException.class)
	public void testReadBytesExceedsAvailableBytes() {
		givenABuffer(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 });

		reader.readBytes(7);
	}

	@Test (expected = IllegalArgumentException.class)
	public void testReadExceedsAvailableBytes() {
		givenABuffer(new byte[] { 0x01, 0x02 });

		reader.read(24);
	}

	@Test (expected = IllegalArgumentException.class)
	public void testReadLongExceedsAvailableBytes() {
		givenABuffer(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 });

		reader.readLong(48);
	}

	@Test 
	public void testReadLong() {
		givenABuffer(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 });

		long value = reader.readLong(24);
		assertEquals(0x010203, value);
		value = reader.readLong(40);
		assertEquals(0x0405060708L, value);
	}

	@Test 
	public void testReadInt() {
		givenABuffer(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 });

		int value = reader.read(24);
		assertEquals(0x010203, value);
		value = reader.read(16);
		assertEquals(0x0405, value);
	}

	@Test (expected = IllegalArgumentException.class)
	public void testReadNextByteExceedsAvailableBytes() {
		givenABuffer(new byte[] { 0x01, 0x02 });

		reader.readNextByte();
		reader.readNextByte();
		reader.readNextByte();
	}

	@Test 
	public void testCreateRangeReader() {
		givenABuffer(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 });

		assertThat(reader.readNextByte(), is((byte)0x01));
		DatagramReader rangeReader = reader.createRangeReader(4);
		assertThat(reader.readNextByte(), is((byte)0x06));
		assertThat(reader.bytesAvailable(), is(false));
		assertThat(rangeReader.readNextByte(), is((byte)0x02));
		assertThat(rangeReader.readNextByte(), is((byte)0x03));
		assertThat(rangeReader.readNextByte(), is((byte)0x04));
		assertThat(rangeReader.readNextByte(), is((byte)0x05));
		assertThat(rangeReader.bytesAvailable(), is(false));
	}

	@Test (expected = IllegalArgumentException.class)
	public void testCreateRangeReaderExceedsAvailableBytes() {
		givenABuffer(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 });

		assertThat(reader.readNextByte(), is((byte)0x01));
		reader.createRangeReader(6);
	}

	@Test (expected = IllegalArgumentException.class)
	public void testRangeReaderExceedsAvailableBytes() {
		givenABuffer(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 });

		assertThat(reader.readNextByte(), is((byte)0x01));
		DatagramReader rangeReader = reader.createRangeReader(4);
		assertThat(reader.readNextByte(), is((byte)0x06));
		assertThat(reader.bytesAvailable(), is(false));
		assertThat(rangeReader.readNextByte(), is((byte)0x02));
		rangeReader.readBytes(4);
	}

	@Test 
	public void testCreateRangeDatagramReader() {
		byte[] data = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
		DatagramReader reader = new DatagramReader(data, 2, 3);

		assertThat(reader.readNextByte(), is((byte)0x03));
		assertThat(reader.bytesAvailable(2), is(true));
		assertThat(reader.bytesAvailable(3), is(false));
	}

	@Test (expected = IllegalArgumentException.class)
	public void testCreateRangeDatagramReaderOffestOutOfRange() {
		byte[] data = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
		DatagramReader reader = new DatagramReader(data, 8, 3);

		assertThat(reader.bytesAvailable(1), is(false));
		// fails with IllegalArgumentException
		reader.readNextByte();
	}

	private void givenABuffer(byte[] buffer) {
		reader = new DatagramReader(buffer);
	}
}
