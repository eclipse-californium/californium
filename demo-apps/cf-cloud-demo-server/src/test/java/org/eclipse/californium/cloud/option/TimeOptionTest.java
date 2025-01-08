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
package org.eclipse.californium.cloud.option;

import static org.eclipse.californium.elements.matcher.InRange.inRange;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import org.eclipse.californium.cloud.option.TimeOption.Definition;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.DatagramReader;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Tests the functionality of the class TransmissionCountOption.
 * 
 * @since 4.0
 */
@Category(Small.class)
public class TimeOptionTest {

	public static final Definition DEFINITION = TimeOption.DEFINITION;

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	@Test
	public void testCreate() {
		byte[] bytes = { 0x04, 0x1, 0x2 };
		DatagramReader reader = new DatagramReader(bytes);

		long time1 = System.currentTimeMillis();
		TimeOption test = DEFINITION.create();
		long time2 = System.currentTimeMillis();
		assertThat(test, is(notNullValue()));
		assertThat(test.getLongValue(), is(inRange(time1, time2 + 1)));

		test = DEFINITION.create(2);
		assertThat(test, is(notNullValue()));
		assertThat(test.getLongValue(), is(2L));

		test = DEFINITION.create(reader, 3);
		assertThat(test, is(notNullValue()));
		assertThat(test.getLongValue(), is(0x40102L));
	}

	@Test(expected = NullPointerException.class)
	public void testCreateWithoutReader() {
		DEFINITION.create(null, 0);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateWithReaderTooLarge() {
		DatagramReader reader = new DatagramReader("0123456789".getBytes());
		DEFINITION.create(reader, 9);
	}

	@Test
	public void testCreateWithReaderEmpty() {
		DatagramReader reader = new DatagramReader("test".getBytes());
		TimeOption test = DEFINITION.create(reader, 0);
		assertThat(test, is(notNullValue()));
		assertThat(test.getLongValue(), is(0L));
	}

	@Test
	public void testCreateEmpty() {
		TimeOption test = DEFINITION.create(0);
		assertThat(test.getLongValue(), is(0L));
	}

	@Test
	public void testGetMessageTimeWithoutTimeOption() {
		Request request = Request.newGet();
		request.setMID(1);

		// current time, if time option is missing
		long time1 = System.currentTimeMillis();
		TimeOption time = TimeOption.getMessageTime(request);
		long time2 = System.currentTimeMillis();
		assertThat(time, is(notNullValue()));
		assertThat(time.getLongValue(), is(inRange(time1, time2 + 1)));

		// no time option, no adjust
		TimeOption adjust = time.adjust();
		assertThat(adjust, is(nullValue()));
	}

	@Test
	public void testGetMessageTimeWithInitialTimeOption() {
		Request request = Request.newGet();
		request.setMID(1);
		TimeOption time = DEFINITION.create(0);
		request.getOptions().addOtherOption(time);

		long time1 = System.currentTimeMillis();
		time = TimeOption.getMessageTime(request);
		assertThat(time, is(notNullValue()));
		TimeOption adjust = time.adjust();
		long time2 = System.currentTimeMillis();
		assertThat(time.getLongValue(), is(inRange(time1, time2 + 1)));
		assertThat(adjust, is(notNullValue()));
		assertThat(adjust.getLongValue(), is(inRange(time1, time2 + 1)));
	}

	@Test
	public void testGetMessageTimeWithCurrentTimeOption() {
		Request request = Request.newGet();
		request.setMID(1);
		// time option with current time
		long time1 = System.currentTimeMillis();
		TimeOption time = DEFINITION.create(time1);
		request.getOptions().addOtherOption(time);
		time = TimeOption.getMessageTime(request);
		long time2 = System.currentTimeMillis();
		assertThat(time, is(notNullValue()));
		assertThat(time.getLongValue(), is(time1));
		TimeOption adjust = time.adjust();
		if ((time2 - time1) < TimeOption.MAX_MILLISECONDS_DELTA) {
			assertThat(adjust, is(nullValue()));
		}
	}

	@Test
	public void testGetMessageTimeWithDelayedTimeOption() {
		Request request = Request.newGet();
		request.setMID(1);

		// time option with offset
		long time1 = System.currentTimeMillis();
		long offset = time1 - TimeOption.MAX_MILLISECONDS_DELTA * 2;
		TimeOption time = DEFINITION.create(offset);
		request.getOptions().addOtherOption(time);
		time = TimeOption.getMessageTime(request);
		assertThat(time, is(notNullValue()));
		TimeOption adjust = time.adjust();
		long time2 = System.currentTimeMillis();
		assertThat(time.getLongValue(), is(offset));
		assertThat(adjust, is(notNullValue()));
		assertThat(adjust.getLongValue(), is(inRange(time1, time2 + 1)));
	}

	@Test(expected = NullPointerException.class)
	public void testGetMessageTimeFailsWithNull() {
		TimeOption.getMessageTime(null);
	}
}
