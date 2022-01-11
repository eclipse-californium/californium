/*******************************************************************************
 * Copyright (c) 2022 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.ExpectedExceptionWrapper;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * Tests for {@link UriQueryParameter}.
 * 
 * @since 3.2
 */
public final class UriQueryParameterTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();
	@Rule
	public ExpectedException exception = ExpectedExceptionWrapper.none();

	private UriQueryParameter helper;

	@Before
	public void setup() {
		helper = new UriQueryParameter(Arrays.asList("test", "testint=12", "text=hallo"));
	}

	@Test
	public void testHasParameter() {
		assertThat(helper.hasParameter("test"), is(true));
		assertThat(helper.hasParameter("testint"), is(true));
		assertThat(helper.hasParameter("test2"), is(false));
		assertThat(helper.hasParameter("te"), is(false));
	}

	@Test
	public void testGetArgument() {
		assertThat(helper.getArgument("testint"), is("12"));
		assertThat(helper.getArgument("text"), is("hallo"));
	}

	@Test
	public void testGetArgumentWithDefault() {
		assertThat(helper.getArgument("text", "default"), is("hallo"));
		assertThat(helper.getArgument("te", "default"), is("default"));
	}

	@Test
	public void testGetArgumentFailsUnavailableParameter() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("Missing parameter");
		helper.getArgument("te");
	}

	@Test
	public void testGetArgumentFailsMissingArgument() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("Missing argument");
		helper.getArgument("test");
	}

	@Test
	public void testGetArgumentAsInteger() {
		assertThat(helper.getArgumentAsInteger("testint"), is(12));
	}

	@Test
	public void testGetArgumentAsIntegerDefault() {
		assertThat(helper.getArgumentAsInteger("testint", 100), is(12));
		assertThat(helper.getArgumentAsInteger("test", 100), is(100));
		assertThat(helper.getArgumentAsInteger("te", 100), is(100));
	}

	@Test
	public void testGetArgumentAsIntegerFailsNoNumber() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("no number");
		helper.getArgumentAsInteger("text");
	}

	@Test
	public void testGetArgumentAsIntegerWithMinimum() {
		assertThat(helper.getArgumentAsInteger("testint", 100, 10), is(12));
		assertThat(helper.getArgumentAsInteger("test", 100, 10), is(100));
		assertThat(helper.getArgumentAsInteger("te", 100, 10), is(100));
	}

	@Test
	public void testGetArgumentAsIntegerWithMinimumFails() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("less than");
		helper.getArgumentAsInteger("testint", 100, 20);
	}

	@Test
	public void testGetArgumentAsIntegerWithMinimumFailsDefault() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("less than");
		helper.getArgumentAsInteger("te", 10, 20);
	}

	@Test
	public void testGetArgumentAsLong() {
		assertThat(helper.getArgumentAsLong("testint"), is(12L));
	}

	@Test
	public void testGetArgumentAsLongDefault() {
		assertThat(helper.getArgumentAsLong("testint", 100), is(12L));
		assertThat(helper.getArgumentAsLong("test", 100), is(100L));
		assertThat(helper.getArgumentAsLong("te", 100), is(100L));
	}

	@Test
	public void testGetArgumentAsLongFailsNoNumber() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("no number");
		helper.getArgumentAsLong("text");
	}

	@Test
	public void testGetArgumentAsLongWithMinimum() {
		assertThat(helper.getArgumentAsLong("testint", 100, 10), is(12L));
		assertThat(helper.getArgumentAsLong("test", 100, 10), is(100L));
		assertThat(helper.getArgumentAsLong("te", 100, 10), is(100L));
	}

	@Test
	public void testGetArgumentAsLongWithMinimumFails() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("less than");
		helper.getArgumentAsLong("testint", 100, 20);
	}

	@Test
	public void testGetArgumentAsLongWithMinimumFailsDefault() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("less than");
		helper.getArgumentAsLong("te", 10, 20);
	}

	@Test
	public void testParameterSupported() {
		new UriQueryParameter(Arrays.asList("test", "testint=12", "text=hallo"),
				Arrays.asList("test", "testint", "text", "extra"));
	}

	@Test
	public void testExtraParameterFails() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("is not supported");
		new UriQueryParameter(Arrays.asList("test", "testint=12", "text=hallo"),
				Arrays.asList("test", "testint"));
	}

	@Test
	public void testExtraParameterAddedToUnsupported() {
		List<String> unsupported = new ArrayList<>();
		new UriQueryParameter(Arrays.asList("test", "testint=12", "text=hallo"), Arrays.asList("test", "testint"),
				unsupported);
		assertThat(unsupported.size(), is(1));
		assertThat(unsupported, hasItem("text=hallo"));
	}

}
