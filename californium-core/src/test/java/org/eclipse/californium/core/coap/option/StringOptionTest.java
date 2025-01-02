/********************************************************************************
 * Copyright (c) 2025 Contributors to the Eclipse Foundation
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
package org.eclipse.californium.core.coap.option;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramReader;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Tests the functionality of the class StringOption.
 * 
 * @since 4.0
 */
@Category(Small.class)
public class StringOptionTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final StringOption.Definition CUSTOM = new StringOption.Definition(0xff1c, "Custom", false, 1, 6);

	@Test
	public void testCreate() {
		String value = "test";
		byte[] bytes = value.getBytes();
		DatagramReader reader = new DatagramReader(bytes);

		StringOption test = CUSTOM.create(value);
		assertThat(test, is(notNullValue()));
		assertThat(test.getValue(), is(bytes));

		test = CUSTOM.create(reader, 4);
		assertThat(test, is(notNullValue()));
		assertThat(test.getValue(), is(bytes));
		assertThat(test.getStringValue(), is(value));
	}

	@Test(expected = NullPointerException.class)
	public void testCreateWithoutReader() {
		CUSTOM.create(null, 0);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateWithReaderTooLarge() {
		DatagramReader reader = new DatagramReader("0123456789".getBytes());
		CUSTOM.create(reader, 7);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateTooLarge() {
		CUSTOM.create("0123456789");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateWithReaderEmpty() {
		DatagramReader reader = new DatagramReader("test".getBytes());
		CUSTOM.create(reader, 0);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateEmpty() {
		CUSTOM.create("");
	}

	@Test(expected = NullPointerException.class)
	public void testCreateNullValue() {
		CUSTOM.create((String) null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateEmptyByte() {
		CUSTOM.create(Bytes.EMPTY);
	}

	@Test(expected = NullPointerException.class)
	public void testCreateNullBytes() {
		CUSTOM.create((byte[]) null);
	}

}
