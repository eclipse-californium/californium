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
import java.util.Arrays;
import java.util.regex.Pattern;

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

	private static final String CUSTOM_FIELD = ".fresp";

	private DeviceParser parser;
	private DeviceParser parserAppend;

	@Before
	public void setup() throws IOException {
		String init = "test=tester\n.label='extra'\n.psk='test','secret'\ntest2=tester\n"
				+ ".rpk=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEo0msWyi2DwpS39sf8Wnv6lk+wune"
				+ "tleRJfIxxG8KFOoqrhK7Acweg+1BQo+ApFFabYNZfzu/tUIC2laB398n5g==\n" + ".type=prov\n";

		parser = new DeviceParser(true, false, null);
		parserAppend = new DeviceParser(true, true, Arrays.asList(CUSTOM_FIELD));
		Reader data = new StringReader(init);
		parser.load(data);
		data.close();
		data = new StringReader(init);
		parserAppend.load(data);
		data.close();
	}

	@Test
	public void testAppendDevice() throws IOException {
		String append = "test=tester\n.label='added'\n.psk='test2','secret'\n";
		Reader data = new StringReader(append);
		int count = parserAppend.load(data);
		data.close();
		assertThat(count, is(1));
		Device device = parserAppend.get("test");
		assertThat(device, is(notNullValue()));
		assertThat(device.pskIdentity, is("test2"));
		assertThat(device.label, is("added"));
	}

	@Test
	public void testAppendDeviceKeepingLabel() throws IOException {
		String append = "test=tester\n.psk='test2','secret'\n";
		Reader data = new StringReader(append);
		int count = parserAppend.load(data);
		data.close();
		assertThat(count, is(1));
		Device device = parserAppend.get("test");
		assertThat(device, is(notNullValue()));
		assertThat(device.pskIdentity, is("test2"));
		assertThat(device.label, is("extra"));
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
		String append = "test3=tester\n.psk='test3','secret'\n.type=prov\n";
		Reader data = new StringReader(append);
		try {
			parserAppend.load(data);
			fail("IllegalArgumentException expected for .type=prov");
		} catch (IllegalArgumentException ex) {
			Device device = parserAppend.get("test3");
			assertThat(device, is(nullValue()));
		} finally {
			data.close();
		}
	}

	@Test
	public void testAppendCARefused() throws IOException {
		String append = "test3=tester\n.psk='test3','secret'\n.type=ca\n";
		Reader data = new StringReader(append);
		try {
			parserAppend.load(data);
			fail("IllegalArgumentException expected for .type=ca");
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

	@Test
	public void testResponseFilter() throws IOException {
		String filter = "ack";
		String append = "test3=tester\n.psk='test3','secret'\n" + CUSTOM_FIELD + "=" + filter + "\n";
		Reader data = new StringReader(append);
		int count = parserAppend.load(data);
		data.close();
		assertThat(count, is(1));
		Device device = parserAppend.get("test3");
		assertThat(device, is(notNullValue()));
		String value = device.customFields.get(CUSTOM_FIELD);
		assertThat(value, is(filter));
		assertThat(Pattern.matches(value, "test"), is(false));
		assertThat(Pattern.matches(value, "ack"), is(true));
		assertThat(Pattern.matches(value, "tack"), is(false));
		assertThat(Pattern.matches(value, "ackn"), is(false));
	}

	@Test
	public void testResponseFilter2() throws IOException {
		String filter = ".*\"status\":\\s*true,.*";
		String append = "test3=tester\n.psk='test3','secret'\n" + CUSTOM_FIELD + "=" + filter + "\n";
		Reader data = new StringReader(append);
		int count = parserAppend.load(data);
		data.close();
		assertThat(count, is(1));
		Device device = parserAppend.get("test3");
		assertThat(device, is(notNullValue()));
		String value = device.customFields.get(CUSTOM_FIELD);
		assertThat(value, is(filter));
		assertThat(Pattern.matches(value, "{\"status\":true,\"result\":\"3 Data Added\"}"), is(true));
	}

}
