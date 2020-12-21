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

import java.net.InetSocketAddress;
import java.util.Map;

import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext.Attributes;
import org.junit.Before;
import org.junit.Test;

public class SerializationUtilTest {

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
		Attributes writeAttributes = new Attributes();
		writeAttributes.add("K1", "String");
		writeAttributes.add("K2", 10);
		writeAttributes.add("K3", 1000L);
		writeAttributes.add("K4", new Bytes("bytes".getBytes()));
		InetSocketAddress dummy = new InetSocketAddress(0);
		MapBasedEndpointContext context = new MapBasedEndpointContext(dummy, null, writeAttributes);
		Map<String, Object> write = context.entries();
		SerializationUtil.write(writer, write);
		swap();
		Attributes readAttributes = SerializationUtil.readEndpointContexAttributes(reader);
		context = new MapBasedEndpointContext(dummy, null, readAttributes);
		Map<String, Object> read = context.entries();
		assertEquals(write, read);
		assertEquals(writeAttributes, readAttributes);
	}

	private void swap() {
		reader = new DatagramReader(writer.toByteArray());
	}

}
