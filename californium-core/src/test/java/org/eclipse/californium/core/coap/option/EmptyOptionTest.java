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
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Tests the functionality of the class EmptyOption.
 * 
 * @since 4.0
 */
@Category(Small.class)
public class EmptyOptionTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final EmptyOption.Definition CUSTOM = new EmptyOption.Definition(0xff1c, "Custom");

	@Test
	public void testCreate() {
		DatagramReader reader = new DatagramReader("test".getBytes());
		EmptyOption test = CUSTOM.create();
		assertThat(test, is(notNullValue()));

		test = CUSTOM.create(reader, 0);
		assertThat(test, is(notNullValue()));
	}

	@Test(expected = NullPointerException.class)
	public void testCreateWithoutReader() {
		CUSTOM.create(null, 0);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateWithBytes() {
		DatagramReader reader = new DatagramReader("test".getBytes());
		CUSTOM.create(reader, 1);
	}

}
