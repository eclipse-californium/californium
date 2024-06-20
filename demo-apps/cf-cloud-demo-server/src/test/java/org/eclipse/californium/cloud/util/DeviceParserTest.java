/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.cloud.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;

import org.eclipse.californium.cloud.util.DeviceParser.Device;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.rule.ThreadsRule;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

/**
 * 
 * @since 3.13
 */
public final class DeviceParserTest {

	@Rule
	public ThreadsRule cleanup = new ThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private DeviceParser parser;
	private DeviceParser parserAppend;

	@Before
	public void setup() throws IOException {
		String init = "test=tester\n.psk='test','secret'\ntest2=tester\n"
				+ ".rpk=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEo0msWyi2DwpS39sf8Wnv6lk+wune"
				+ "tleRJfIxxG8KFOoqrhK7Acweg+1BQo+ApFFabYNZfzu/tUIC2laB398n5g==\n" + ".prov=1\n";

		parser = new DeviceParser(true, false);
		parserAppend = new DeviceParser(true, true);
		Reader data = new StringReader(init);
		parser.load(data);
		data.close();
		data = new StringReader(init);
		parserAppend.load(data);
		data.close();
	}

	@Test
	public void testAppendDevice() throws IOException {
		String append = "test=tester\n.psk='test2','secret'\n";
		Reader data = new StringReader(append);
		int count = parserAppend.load(data);
		data.close();
		assertThat(count, is(1));
		Device device = parserAppend.get("test");
		assertThat(device, is(notNullValue()));
		assertThat(device.pskIdentity, is("test2"));
	}

	@Test
	public void testAppendDeviceRefused() throws IOException {
		String append = "test=tester\n.psk='test2','secret'\n";
		Reader data = new StringReader(append);
		int count = parser.load(data);
		data.close();
		assertThat(count, is(0));
		Device device = parser.get("test");
		assertThat(device, is(notNullValue()));
		assertThat(device.pskIdentity, is("test"));
	}

	@Test
	public void testAppendProvisionerRefused() throws IOException {
		String append = "test3=tester\n.psk='test3','secret'\n.prov=1\n";
		Reader data = new StringReader(append);
		try {
			parserAppend.load(data);
			fail("IllegalArgumentException expected for .prov=1");
		} catch (IllegalArgumentException ex) {
			Device device = parserAppend.get("test3");
			assertThat(device, is(nullValue()));
		} finally {
			data.close();
		}
	}

	@Test
	public void testReplacedProvisionerRefused() throws IOException {
		String append = "test2=tester\n.psk='test3','secret'\n";
		Reader data = new StringReader(append);
		int count = parserAppend.load(data);
		data.close();
		assertThat(count, is(0));
		Device device = parserAppend.get("test2");
		assertThat(device, is(notNullValue()));
		assertThat(device.publicKey, is(notNullValue()));
	}

}
