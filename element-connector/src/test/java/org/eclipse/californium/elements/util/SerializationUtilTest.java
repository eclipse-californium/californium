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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.eclipse.californium.elements.util.TestConditionTools.inRange;

import java.net.InetSocketAddress;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.Definition;
import org.eclipse.californium.elements.Definitions;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext.Attributes;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.rule.TestTimeRule;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class SerializationUtilTest {

	private static final long MILLISECOND_IN_NANOS = TimeUnit.MILLISECONDS.toNanos(1);

	@Rule
	public TestTimeRule time = new TestTimeRule();

	DatagramWriter writer;
	DatagramReader reader;

	@Before
	public void setUp() throws Exception {
		writer = new DatagramWriter();
	}

	@Test
	public void testStrings() {
		String write = "Hallo!";
		SerializationUtil.write(writer, write, Byte.SIZE);
		swap();
		String read = SerializationUtil.readString(reader, Byte.SIZE);
		assertEquals(write, read);
	}

	@Test
	public void testNullStrings() {
		String write = null;
		SerializationUtil.write(writer, write, Byte.SIZE);
		swap();
		String read = SerializationUtil.readString(reader, Byte.SIZE);
		assertEquals(write, read);
	}

	@Test
	public void testEmptyStrings() {
		String write = "";
		SerializationUtil.write(writer, write, Byte.SIZE);
		swap();
		String read = SerializationUtil.readString(reader, Byte.SIZE);
		assertEquals(write, read);
	}

	@Test
	public void testAddressIpv4() {
		InetSocketAddress write = new InetSocketAddress("192.168.1.5", 5683);
		SerializationUtil.write(writer, write);
		swap();
		InetSocketAddress read = SerializationUtil.readAddress(reader);
		assertEquals(write, read);
	}

	@Test
	public void testAddressUnresolved() {
		InetSocketAddress write = new InetSocketAddress("non-existing.host", 11111);
		SerializationUtil.write(writer, write);
		swap();
		InetSocketAddress read = SerializationUtil.readAddress(reader);
		assertEquals(write, read);
	}

	@Test
	public void testAddressIpv6() {
		InetSocketAddress write = new InetSocketAddress("[2001::1]", 5684);
		SerializationUtil.write(writer, write);
		swap();
		InetSocketAddress read = SerializationUtil.readAddress(reader);
		assertEquals(write, read);
	}

	@Test
	public void testEndpointContextAttributes() {
		Definitions<Definition<?>> test = MapBasedEndpointContext.ATTRIBUTE_DEFINITIONS;
		Definition<String> K1 = new Definition<>("K1", String.class, test);
		Definition<Integer> K2 = new Definition<>("K2", Integer.class, test);
		Definition<Long> K3 = new Definition<>("K3", Long.class, test);
		Definition<Bytes> K4 = new Definition<>("K4", Bytes.class, test);
		Definition<Boolean> K5 = new Definition<>("K5", Boolean.class, test);
		Definition<InetSocketAddress> K6 = new Definition<>("K6", InetSocketAddress.class, test);

		InetSocketAddress dummy = new InetSocketAddress(0);
		InetSocketAddress address = new InetSocketAddress("192.168.0.1", 5683);

		Attributes writeAttributes = new Attributes();
		writeAttributes.add(K1, "String");
		writeAttributes.add(K2, 10);
		writeAttributes.add(K3, 1000L);
		writeAttributes.add(K4, new Bytes("bytes".getBytes()));
		writeAttributes.add(K5, true);
		writeAttributes.add(K6, address);
		MapBasedEndpointContext context = new MapBasedEndpointContext(dummy, null, writeAttributes);
		Map<Definition<?>, Object> write = context.entries();
		SerializationUtil.write(writer, write);
		swap();
		Attributes readAttributes = SerializationUtil.readEndpointContexAttributes(reader, test);
		context = new MapBasedEndpointContext(dummy, null, readAttributes);
		Map<Definition<?>, Object> read = context.entries();
		assertEquals(write, read);
		assertEquals(writeAttributes, readAttributes);
	}

	@Test
	public void testNanotimeSynchronizationMark() {
		long timePassed = ClockUtil.nanoRealtime();
		SerializationUtil.writeNanotimeSynchronizationMark(writer);
		timePassed = ClockUtil.nanoRealtime() - timePassed;
		swap();
		timePassed -= ClockUtil.nanoRealtime();
		long delta = SerializationUtil.readNanotimeSynchronizationMark(reader);
		timePassed += ClockUtil.nanoRealtime();
		assertThat(delta, is(inRange(-MILLISECOND_IN_NANOS, timePassed + MILLISECOND_IN_NANOS)));
	}

	@Test
	public void testNanotimeSynchronizationMarkWithTimeshift() {
		long timePassed = ClockUtil.nanoRealtime();
		SerializationUtil.writeNanotimeSynchronizationMark(writer);
		timePassed = ClockUtil.nanoRealtime() - timePassed;
		time.addTestTimeShift(10, TimeUnit.MILLISECONDS);
		swap();
		timePassed -= ClockUtil.nanoRealtime();
		long delta = SerializationUtil.readNanotimeSynchronizationMark(reader);
		timePassed += ClockUtil.nanoRealtime();
		assertThat(delta, is(inRange(9 * MILLISECOND_IN_NANOS, timePassed + 11 * MILLISECOND_IN_NANOS)));
	}

	@Test
	public void testSkipItems() {
		int pos = SerializationUtil.writeStartItem(writer, 10, Short.SIZE);
		writer.writeVarBytes("hello".getBytes(), Byte.SIZE);
		SerializationUtil.writeFinishedItem(writer, pos, Short.SIZE);
		pos = SerializationUtil.writeStartItem(writer, 10, Short.SIZE);
		writer.writeVarBytes(",".getBytes(), Byte.SIZE);
		SerializationUtil.writeFinishedItem(writer, pos, Short.SIZE);
		pos = SerializationUtil.writeStartItem(writer, 10, Short.SIZE);
		writer.writeVarBytes("world!".getBytes(), Byte.SIZE);
		SerializationUtil.writeFinishedItem(writer, pos, Short.SIZE);
		SerializationUtil.writeNoItem(writer);
		pos = SerializationUtil.writeStartItem(writer, 10, Short.SIZE);
		writer.writeVarBytes("Next!".getBytes(), Byte.SIZE);
		SerializationUtil.writeFinishedItem(writer, pos, Short.SIZE);
		SerializationUtil.writeNoItem(writer);
		swap();
		int len = SerializationUtil.readStartItem(reader, 10, Short.SIZE);
		byte[] data = reader.readVarBytes(Byte.SIZE);
		assertThat(data, is("hello".getBytes()));
		assertThat(len, is(data.length + 1)); // size of var-bytes
		int count = SerializationUtil.skipItems(reader, Short.SIZE);
		assertThat(count, is(2));
		len = SerializationUtil.readStartItem(reader, 10, Short.SIZE);
		data = reader.readVarBytes(Byte.SIZE);
		assertThat(data, is("Next!".getBytes()));
	}

	@Test (expected = IllegalArgumentException.class)
	public void testSkipBitsEndOfStream() {
		int pos = SerializationUtil.writeStartItem(writer, 10, Short.SIZE);
		writer.writeVarBytes("hello".getBytes(), Byte.SIZE);
		SerializationUtil.writeFinishedItem(writer, pos, Short.SIZE);
		swap();
		SerializationUtil.skipBits(reader, 1024);
	}

	private void swap() {
		reader = new DatagramReader(writer.toByteArray());
	}

}
