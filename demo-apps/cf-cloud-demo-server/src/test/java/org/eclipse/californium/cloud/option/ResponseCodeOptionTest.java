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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
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
public class ResponseCodeOptionTest {

	public static final ResponseCodeOption.Definition DEFINITION = ServerCustomOptions.READ_RESPONSE;

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	@Test
	public void testCreate() {
		byte[] bytes = { (byte) ResponseCode.CHANGED.value };
		DatagramReader reader = new DatagramReader(bytes);

		ResponseCodeOption test = DEFINITION.create(ResponseCode.CONTENT.value);
		assertThat(test, is(notNullValue()));
		assertThat(test.getResponseCode(), is(ResponseCode.CONTENT));

		test = DEFINITION.create(ResponseCode.VALID);
		assertThat(test, is(notNullValue()));
		assertThat(test.getResponseCode(), is(ResponseCode.VALID));

		test = DEFINITION.create(reader, 1);
		assertThat(test, is(notNullValue()));
		assertThat(test.getResponseCode(), is(ResponseCode.CHANGED));
	}

	@Test(expected = NullPointerException.class)
	public void testCreateWithoutReader() {
		DEFINITION.create(null, 0);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateWithReaderTooLarge() {
		DatagramReader reader = new DatagramReader("0123456789".getBytes());
		DEFINITION.create(reader, 2);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateWithReaderEmpty() {
		DatagramReader reader = new DatagramReader("test".getBytes());
		DEFINITION.create(reader, 0);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateEmpty() {
		DEFINITION.create(0);
	}

	@Test(expected = NullPointerException.class)
	public void testGetMessageTimeFailsWithNull() {
		DEFINITION.create(null);
	}
}
