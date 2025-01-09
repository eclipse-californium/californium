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
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.StringUtil;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Tests the functionality of the class IntegerOption.
 * 
 * @since 4.0
 */
@Category(Small.class)
public class IntegerOptionTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final IntegerOption.Definition CUSTOM = new IntegerOption.Definition(0xff1c, "Custom", false, 1, 2);

	private static final IntegerOption.RangeDefinition CUSTOM_RANGE = new IntegerOption.RangeDefinition(0xff2c, "Range",
			false, 10, 1000);

	private static final IntegerOption.Definition CUSTOM_LARGE = new IntegerOption.Definition(0xff3c, "Custom Large", false);

	@Test
	public void testCreate() {
		DatagramReader reader = new DatagramReader(StringUtil.hex2ByteArray("0104"));
		IntegerOption test = CUSTOM.create(12);
		assertThat(test, is(notNullValue()));

		test = CUSTOM.create(reader, 2);
		assertThat(test, is(notNullValue()));
		assertThat(test.getIntegerValue(), is(0x104));
	}

	@Test(expected = NullPointerException.class)
	public void testCreateWithoutReader() {
		CUSTOM.create(null, 0);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateWithBytesTooLarge() {
		DatagramReader reader = new DatagramReader("test".getBytes());
		CUSTOM.create(reader, 4);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateTooLarge() {
		CUSTOM.create(0x10000);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateEmpty() {
		DatagramReader reader = new DatagramReader("test".getBytes());
		CUSTOM.create(reader, 0);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateZero() {
		CUSTOM.create(0);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateTooLongLong() {
		DatagramReader reader = new DatagramReader("0123456789".getBytes());
		CUSTOM_LARGE.create(reader, 9);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateTooLongInteger() {
		DatagramReader reader = new DatagramReader("0123456789".getBytes());
		IntegerOption.Definition.getIntegerValue(reader, 5);
	}

	@Test
	public void testCreateRange() {
		DatagramReader reader = new DatagramReader(StringUtil.hex2ByteArray("0104"));
		IntegerOption test = CUSTOM_RANGE.create(10);
		assertThat(test, is(notNullValue()));
		test = CUSTOM_RANGE.create(1000);
		assertThat(test, is(notNullValue()));

		test = CUSTOM_RANGE.create(reader, 2);
		assertThat(test, is(notNullValue()));
		assertThat(test.getIntegerValue(), is(0x104));
	}

	@Test(expected = NullPointerException.class)
	public void testCreateRangeWithoutReader() {
		CUSTOM_RANGE.create(null, 0);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateRangeWithBytesTooLarge() {
		DatagramReader reader = new DatagramReader("test".getBytes());
		CUSTOM_RANGE.create(reader, 4);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateRangeTooLarge() {
		CUSTOM_RANGE.create(1001);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateRangeEmpty() {
		DatagramReader reader = new DatagramReader("test".getBytes());
		CUSTOM_RANGE.create(reader, 0);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateRangeTooSmall() {
		CUSTOM_RANGE.create(9);
	}

}
