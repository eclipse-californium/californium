/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import java.util.List;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.option.IntegerOption;
import org.eclipse.californium.core.coap.option.MapBasedOptionRegistry;
import org.eclipse.californium.core.coap.option.NoResponseOption;
import org.eclipse.californium.core.coap.option.OpaqueOption;
import org.eclipse.californium.core.coap.option.OptionRegistry;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.core.coap.option.StringOption;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.Bytes;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * This test tests the class Option. We test that the conversion of String,
 * integer and long values to byte arrays work properly.
 */
@Category(Small.class)
public class OptionTest {

	private static final int CUSTOM_OPTION_1 = 0xff1c;
	private static final int CUSTOM_OPTION_2 = 0xff9c;
	private static final int CUSTOM_OPTION_3 = 0xff1d;
	private static final StringOption.Definition CUSTOM_1 = new StringOption.Definition(CUSTOM_OPTION_1, "custom1",
			true, 0, 64);
	private static final StringOption.Definition CUSTOM_2 = new StringOption.Definition(CUSTOM_OPTION_2, "custom2",
			false, 0, 64);
	private static final StringOption.Definition CUSTOM_3 = new StringOption.Definition(CUSTOM_OPTION_3, "custom3",
			true, 0, 64);
	private static final OpaqueOption.Definition OPAQUE = new OpaqueOption.Definition(OptionNumberRegistry.RESERVED_0,
			"Reserved 0");
	private static final IntegerOption.Definition INTEGER = new IntegerOption.Definition(0xff7c, "custom3", false, 0,
			4);
	private static final IntegerOption.Definition LONG = new IntegerOption.Definition(0xff8c, "custom4", false, 0, 8);

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	@Test
	public void testIsCritical() {
		assertTrue(OptionNumberRegistry.isCritical(OptionNumberRegistry.IF_MATCH));
		assertTrue(OptionNumberRegistry.isCritical(OptionNumberRegistry.URI_HOST));
		assertFalse(OptionNumberRegistry.isCritical(OptionNumberRegistry.ETAG));
		assertTrue(OptionNumberRegistry.isCritical(OptionNumberRegistry.IF_NONE_MATCH));
		assertFalse(OptionNumberRegistry.isCritical(OptionNumberRegistry.OBSERVE));
		assertTrue(OptionNumberRegistry.isCritical(OptionNumberRegistry.URI_PORT));
		assertFalse(OptionNumberRegistry.isCritical(OptionNumberRegistry.LOCATION_PATH));
		assertTrue(OptionNumberRegistry.isCritical(OptionNumberRegistry.URI_PATH));
		assertFalse(OptionNumberRegistry.isCritical(OptionNumberRegistry.CONTENT_FORMAT));
		assertFalse(OptionNumberRegistry.isCritical(OptionNumberRegistry.MAX_AGE));
		assertTrue(OptionNumberRegistry.isCritical(OptionNumberRegistry.URI_QUERY));
		assertTrue(OptionNumberRegistry.isCritical(OptionNumberRegistry.ACCEPT));
		assertFalse(OptionNumberRegistry.isCritical(OptionNumberRegistry.LOCATION_QUERY));
		assertTrue(OptionNumberRegistry.isCritical(OptionNumberRegistry.BLOCK2));
		assertTrue(OptionNumberRegistry.isCritical(OptionNumberRegistry.BLOCK1));
		assertFalse(OptionNumberRegistry.isCritical(OptionNumberRegistry.SIZE2));
		assertTrue(OptionNumberRegistry.isCritical(OptionNumberRegistry.PROXY_URI));
		assertTrue(OptionNumberRegistry.isCritical(OptionNumberRegistry.PROXY_SCHEME));
		assertFalse(OptionNumberRegistry.isCritical(OptionNumberRegistry.SIZE1));
		assertTrue(OptionNumberRegistry.isCritical(OptionNumberRegistry.OSCORE));
		assertFalse(OptionNumberRegistry.isCritical(OptionNumberRegistry.NO_RESPONSE));
	}

	@Test
	public void testIsElective() {
		assertFalse(OptionNumberRegistry.isElective(OptionNumberRegistry.IF_MATCH));
		assertFalse(OptionNumberRegistry.isElective(OptionNumberRegistry.URI_HOST));
		assertTrue(OptionNumberRegistry.isElective(OptionNumberRegistry.ETAG));
		assertFalse(OptionNumberRegistry.isElective(OptionNumberRegistry.IF_NONE_MATCH));
		assertTrue(OptionNumberRegistry.isElective(OptionNumberRegistry.OBSERVE));
		assertFalse(OptionNumberRegistry.isElective(OptionNumberRegistry.URI_PORT));
		assertTrue(OptionNumberRegistry.isElective(OptionNumberRegistry.LOCATION_PATH));
		assertFalse(OptionNumberRegistry.isElective(OptionNumberRegistry.URI_PATH));
		assertTrue(OptionNumberRegistry.isElective(OptionNumberRegistry.CONTENT_FORMAT));
		assertTrue(OptionNumberRegistry.isElective(OptionNumberRegistry.MAX_AGE));
		assertFalse(OptionNumberRegistry.isElective(OptionNumberRegistry.URI_QUERY));
		assertFalse(OptionNumberRegistry.isElective(OptionNumberRegistry.ACCEPT));
		assertTrue(OptionNumberRegistry.isElective(OptionNumberRegistry.LOCATION_QUERY));
		assertFalse(OptionNumberRegistry.isElective(OptionNumberRegistry.BLOCK2));
		assertFalse(OptionNumberRegistry.isElective(OptionNumberRegistry.BLOCK1));
		assertTrue(OptionNumberRegistry.isElective(OptionNumberRegistry.SIZE2));
		assertFalse(OptionNumberRegistry.isElective(OptionNumberRegistry.PROXY_URI));
		assertFalse(OptionNumberRegistry.isElective(OptionNumberRegistry.PROXY_SCHEME));
		assertTrue(OptionNumberRegistry.isElective(OptionNumberRegistry.SIZE1));
		assertFalse(OptionNumberRegistry.isElective(OptionNumberRegistry.OSCORE));
		assertTrue(OptionNumberRegistry.isElective(OptionNumberRegistry.NO_RESPONSE));
	}

	@Test
	public void testIsSafe() {
		assertTrue(OptionNumberRegistry.isSafe(OptionNumberRegistry.IF_MATCH));
		assertFalse(OptionNumberRegistry.isSafe(OptionNumberRegistry.URI_HOST));
		assertTrue(OptionNumberRegistry.isSafe(OptionNumberRegistry.ETAG));
		assertTrue(OptionNumberRegistry.isSafe(OptionNumberRegistry.IF_NONE_MATCH));
		assertFalse(OptionNumberRegistry.isSafe(OptionNumberRegistry.OBSERVE));
		assertFalse(OptionNumberRegistry.isSafe(OptionNumberRegistry.URI_PORT));
		assertTrue(OptionNumberRegistry.isSafe(OptionNumberRegistry.LOCATION_PATH));
		assertFalse(OptionNumberRegistry.isSafe(OptionNumberRegistry.URI_PATH));
		assertTrue(OptionNumberRegistry.isSafe(OptionNumberRegistry.CONTENT_FORMAT));
		assertFalse(OptionNumberRegistry.isSafe(OptionNumberRegistry.MAX_AGE));
		assertFalse(OptionNumberRegistry.isSafe(OptionNumberRegistry.URI_QUERY));
		assertTrue(OptionNumberRegistry.isSafe(OptionNumberRegistry.ACCEPT));
		assertTrue(OptionNumberRegistry.isSafe(OptionNumberRegistry.LOCATION_QUERY));
		assertFalse(OptionNumberRegistry.isSafe(OptionNumberRegistry.BLOCK2));
		assertFalse(OptionNumberRegistry.isSafe(OptionNumberRegistry.BLOCK1));
		assertTrue(OptionNumberRegistry.isSafe(OptionNumberRegistry.SIZE2));
		assertFalse(OptionNumberRegistry.isSafe(OptionNumberRegistry.PROXY_URI));
		assertFalse(OptionNumberRegistry.isSafe(OptionNumberRegistry.PROXY_SCHEME));
		assertTrue(OptionNumberRegistry.isSafe(OptionNumberRegistry.SIZE1));
		assertTrue(OptionNumberRegistry.isSafe(OptionNumberRegistry.OSCORE));
		assertFalse(OptionNumberRegistry.isSafe(OptionNumberRegistry.NO_RESPONSE));
	}

	@Test
	public void testIsUnsafe() {
		assertFalse(OptionNumberRegistry.isUnsafe(OptionNumberRegistry.IF_MATCH));
		assertTrue(OptionNumberRegistry.isUnsafe(OptionNumberRegistry.URI_HOST));
		assertFalse(OptionNumberRegistry.isUnsafe(OptionNumberRegistry.ETAG));
		assertFalse(OptionNumberRegistry.isUnsafe(OptionNumberRegistry.IF_NONE_MATCH));
		assertTrue(OptionNumberRegistry.isUnsafe(OptionNumberRegistry.OBSERVE));
		assertTrue(OptionNumberRegistry.isUnsafe(OptionNumberRegistry.URI_PORT));
		assertFalse(OptionNumberRegistry.isUnsafe(OptionNumberRegistry.LOCATION_PATH));
		assertTrue(OptionNumberRegistry.isUnsafe(OptionNumberRegistry.URI_PATH));
		assertFalse(OptionNumberRegistry.isUnsafe(OptionNumberRegistry.CONTENT_FORMAT));
		assertTrue(OptionNumberRegistry.isUnsafe(OptionNumberRegistry.MAX_AGE));
		assertTrue(OptionNumberRegistry.isUnsafe(OptionNumberRegistry.URI_QUERY));
		assertFalse(OptionNumberRegistry.isUnsafe(OptionNumberRegistry.ACCEPT));
		assertFalse(OptionNumberRegistry.isUnsafe(OptionNumberRegistry.LOCATION_QUERY));
		assertTrue(OptionNumberRegistry.isUnsafe(OptionNumberRegistry.BLOCK2));
		assertTrue(OptionNumberRegistry.isUnsafe(OptionNumberRegistry.BLOCK1));
		assertFalse(OptionNumberRegistry.isUnsafe(OptionNumberRegistry.SIZE2));
		assertTrue(OptionNumberRegistry.isUnsafe(OptionNumberRegistry.PROXY_URI));
		assertTrue(OptionNumberRegistry.isUnsafe(OptionNumberRegistry.PROXY_SCHEME));
		assertFalse(OptionNumberRegistry.isUnsafe(OptionNumberRegistry.SIZE1));
		assertFalse(OptionNumberRegistry.isUnsafe(OptionNumberRegistry.OSCORE));
		assertTrue(OptionNumberRegistry.isUnsafe(OptionNumberRegistry.NO_RESPONSE));
	}

	@Test
	public void testIsCacheKey() {
		assertTrue(OptionNumberRegistry.isCacheKey(OptionNumberRegistry.IF_MATCH));
		assertTrue(OptionNumberRegistry.isCacheKey(OptionNumberRegistry.URI_HOST));
		assertTrue(OptionNumberRegistry.isCacheKey(OptionNumberRegistry.ETAG));
		assertTrue(OptionNumberRegistry.isCacheKey(OptionNumberRegistry.IF_NONE_MATCH));
		assertTrue(OptionNumberRegistry.isCacheKey(OptionNumberRegistry.OBSERVE));
		assertTrue(OptionNumberRegistry.isCacheKey(OptionNumberRegistry.URI_PORT));
		assertTrue(OptionNumberRegistry.isCacheKey(OptionNumberRegistry.LOCATION_PATH));
		assertTrue(OptionNumberRegistry.isCacheKey(OptionNumberRegistry.URI_PATH));
		assertTrue(OptionNumberRegistry.isCacheKey(OptionNumberRegistry.CONTENT_FORMAT));
		assertTrue(OptionNumberRegistry.isCacheKey(OptionNumberRegistry.MAX_AGE));
		assertTrue(OptionNumberRegistry.isCacheKey(OptionNumberRegistry.URI_QUERY));
		assertTrue(OptionNumberRegistry.isCacheKey(OptionNumberRegistry.ACCEPT));
		assertTrue(OptionNumberRegistry.isCacheKey(OptionNumberRegistry.LOCATION_QUERY));
		assertTrue(OptionNumberRegistry.isCacheKey(OptionNumberRegistry.BLOCK2));
		assertTrue(OptionNumberRegistry.isCacheKey(OptionNumberRegistry.BLOCK1));
		assertFalse(OptionNumberRegistry.isCacheKey(OptionNumberRegistry.SIZE2));
		assertTrue(OptionNumberRegistry.isCacheKey(OptionNumberRegistry.PROXY_URI));
		assertTrue(OptionNumberRegistry.isCacheKey(OptionNumberRegistry.PROXY_SCHEME));
		assertFalse(OptionNumberRegistry.isCacheKey(OptionNumberRegistry.SIZE1));
		assertTrue(OptionNumberRegistry.isCacheKey(OptionNumberRegistry.OSCORE));
		assertTrue(OptionNumberRegistry.isCacheKey(OptionNumberRegistry.NO_RESPONSE));
	}

	@Test
	public void testIsNonCacheable() {
		assertFalse(OptionNumberRegistry.isNoCacheKey(OptionNumberRegistry.IF_MATCH));
		assertFalse(OptionNumberRegistry.isNoCacheKey(OptionNumberRegistry.URI_HOST));
		assertFalse(OptionNumberRegistry.isNoCacheKey(OptionNumberRegistry.ETAG));
		assertFalse(OptionNumberRegistry.isNoCacheKey(OptionNumberRegistry.IF_NONE_MATCH));
		assertFalse(OptionNumberRegistry.isNoCacheKey(OptionNumberRegistry.OBSERVE));
		assertFalse(OptionNumberRegistry.isNoCacheKey(OptionNumberRegistry.URI_PORT));
		assertFalse(OptionNumberRegistry.isNoCacheKey(OptionNumberRegistry.LOCATION_PATH));
		assertFalse(OptionNumberRegistry.isNoCacheKey(OptionNumberRegistry.URI_PATH));
		assertFalse(OptionNumberRegistry.isNoCacheKey(OptionNumberRegistry.CONTENT_FORMAT));
		assertFalse(OptionNumberRegistry.isNoCacheKey(OptionNumberRegistry.MAX_AGE));
		assertFalse(OptionNumberRegistry.isNoCacheKey(OptionNumberRegistry.URI_QUERY));
		assertFalse(OptionNumberRegistry.isNoCacheKey(OptionNumberRegistry.ACCEPT));
		assertFalse(OptionNumberRegistry.isNoCacheKey(OptionNumberRegistry.LOCATION_QUERY));
		assertFalse(OptionNumberRegistry.isNoCacheKey(OptionNumberRegistry.BLOCK2));
		assertFalse(OptionNumberRegistry.isNoCacheKey(OptionNumberRegistry.BLOCK1));
		assertTrue(OptionNumberRegistry.isNoCacheKey(OptionNumberRegistry.SIZE2));
		assertFalse(OptionNumberRegistry.isNoCacheKey(OptionNumberRegistry.PROXY_URI));
		assertFalse(OptionNumberRegistry.isNoCacheKey(OptionNumberRegistry.PROXY_SCHEME));
		assertTrue(OptionNumberRegistry.isNoCacheKey(OptionNumberRegistry.SIZE1));
		assertFalse(OptionNumberRegistry.isNoCacheKey(OptionNumberRegistry.OSCORE));
		assertFalse(OptionNumberRegistry.isNoCacheKey(OptionNumberRegistry.NO_RESPONSE));
	}

	@Test
	public void testIsSingleValue() {
		assertFalse(StandardOptionRegistry.IF_MATCH.isSingleValue());
		assertTrue(StandardOptionRegistry.URI_HOST.isSingleValue());
		assertFalse(StandardOptionRegistry.ETAG.isSingleValue());
		assertTrue(StandardOptionRegistry.IF_NONE_MATCH.isSingleValue());
		assertTrue(StandardOptionRegistry.OBSERVE.isSingleValue());
		assertTrue(StandardOptionRegistry.URI_PORT.isSingleValue());
		assertFalse(StandardOptionRegistry.LOCATION_PATH.isSingleValue());
		assertFalse(StandardOptionRegistry.URI_PATH.isSingleValue());
		assertTrue(StandardOptionRegistry.CONTENT_FORMAT.isSingleValue());
		assertTrue(StandardOptionRegistry.MAX_AGE.isSingleValue());
		assertFalse(StandardOptionRegistry.URI_QUERY.isSingleValue());
		assertTrue(StandardOptionRegistry.ACCEPT.isSingleValue());
		assertFalse(StandardOptionRegistry.LOCATION_QUERY.isSingleValue());
		assertTrue(StandardOptionRegistry.BLOCK2.isSingleValue());
		assertTrue(StandardOptionRegistry.BLOCK1.isSingleValue());
		assertTrue(StandardOptionRegistry.SIZE2.isSingleValue());
		assertTrue(StandardOptionRegistry.PROXY_URI.isSingleValue());
		assertTrue(StandardOptionRegistry.PROXY_SCHEME.isSingleValue());
		assertTrue(StandardOptionRegistry.SIZE1.isSingleValue());
	}

	@Test
	public void testIsUriOption() {
		assertFalse(OptionNumberRegistry.isUriOption(OptionNumberRegistry.IF_MATCH));
		assertTrue(OptionNumberRegistry.isUriOption(OptionNumberRegistry.URI_HOST));
		assertFalse(OptionNumberRegistry.isUriOption(OptionNumberRegistry.ETAG));
		assertFalse(OptionNumberRegistry.isUriOption(OptionNumberRegistry.IF_NONE_MATCH));
		assertFalse(OptionNumberRegistry.isUriOption(OptionNumberRegistry.OBSERVE));
		assertTrue(OptionNumberRegistry.isUriOption(OptionNumberRegistry.URI_PORT));
		assertFalse(OptionNumberRegistry.isUriOption(OptionNumberRegistry.LOCATION_PATH));
		assertTrue(OptionNumberRegistry.isUriOption(OptionNumberRegistry.URI_PATH));
		assertFalse(OptionNumberRegistry.isUriOption(OptionNumberRegistry.CONTENT_FORMAT));
		assertFalse(OptionNumberRegistry.isUriOption(OptionNumberRegistry.MAX_AGE));
		assertTrue(OptionNumberRegistry.isUriOption(OptionNumberRegistry.URI_QUERY));
		assertFalse(OptionNumberRegistry.isUriOption(OptionNumberRegistry.ACCEPT));
		assertFalse(OptionNumberRegistry.isUriOption(OptionNumberRegistry.LOCATION_QUERY));
		assertFalse(OptionNumberRegistry.isUriOption(OptionNumberRegistry.BLOCK2));
		assertFalse(OptionNumberRegistry.isUriOption(OptionNumberRegistry.BLOCK1));
		assertFalse(OptionNumberRegistry.isUriOption(OptionNumberRegistry.SIZE2));
		assertFalse(OptionNumberRegistry.isUriOption(OptionNumberRegistry.PROXY_URI));
		assertFalse(OptionNumberRegistry.isUriOption(OptionNumberRegistry.PROXY_SCHEME));
		assertFalse(OptionNumberRegistry.isUriOption(OptionNumberRegistry.SIZE1));
		assertFalse(OptionNumberRegistry.isUriOption(OptionNumberRegistry.OSCORE));
		assertFalse(OptionNumberRegistry.isUriOption(OptionNumberRegistry.NO_RESPONSE));
	}

	@Test
	public void testSetValue() {
		OpaqueOption option = OPAQUE.create(new byte[4]);
		assertArrayEquals(new byte[4], option.getValue());

		option = OPAQUE.create(new byte[] { 69, -104, 35, 55, -104, 116, 35, -104 });
		assertArrayEquals(new byte[] { 69, -104, 35, 55, -104, 116, 35, -104 }, option.getValue());
	}

	@Test
	public void testSetStringValue() {
		StringOption option = CUSTOM_1.create("");

		assertArrayEquals(Bytes.EMPTY, option.getValue());

		option = CUSTOM_1.create("Californium");
		assertArrayEquals("Californium".getBytes(), option.getValue());
	}

	@Test
	public void testSetIntegerValue() {
		IntegerOption option = INTEGER.create(0);

		assertArrayEquals(Bytes.EMPTY, option.encode());
		assertEquals(0, option.getIntegerValue());

		option = INTEGER.create(11);
		assertArrayEquals(new byte[] { 11 }, option.encode());
		assertEquals(11, option.getIntegerValue());

		option = INTEGER.create(255);
		assertArrayEquals(new byte[] { (byte) 255 }, option.encode());
		assertEquals(255, option.getIntegerValue());

		option = INTEGER.create(256);
		assertArrayEquals(new byte[] { 1, 0 }, option.encode());
		assertEquals(256, option.getIntegerValue());

		option = INTEGER.create(18273);
		assertArrayEquals(new byte[] { 71, 97 }, option.encode());
		assertEquals(18273, option.getIntegerValue());

		option = INTEGER.create(1 << 16);
		assertArrayEquals(new byte[] { 1, 0, 0 }, option.encode());
		assertEquals(1 << 16, option.getIntegerValue());

		option = INTEGER.create(23984773);
		assertArrayEquals(new byte[] { 1, 109, (byte) 250, (byte) 133 }, option.encode());
		assertEquals(23984773, option.getIntegerValue());

		// 0xFFFFFFFF requires L, otherwise it gets converted into a -1L
		option = INTEGER.create(0xFFFFFFFFL);
		assertArrayEquals(new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF }, option.encode());
		assertEquals(0xFFFFFFFF, option.getIntegerValue());
	}

	@Test
	public void testSetLongValue() {
		IntegerOption option = LONG.create(0);

		assertArrayEquals(Bytes.EMPTY, option.encode());
		assertEquals(0, option.getLongValue());

		option = LONG.create(11);
		assertArrayEquals(new byte[] { 11 }, option.encode());
		assertEquals(11, option.getLongValue());

		option = LONG.create(255);
		assertArrayEquals(new byte[] { (byte) 255 }, option.encode());
		assertEquals(255, option.getLongValue());

		option = LONG.create(256);
		assertArrayEquals(new byte[] { 1, 0 }, option.encode());
		assertEquals(256, option.getLongValue());

		option = LONG.create(18273);
		assertArrayEquals(new byte[] { 71, 97 }, option.encode());
		assertEquals(18273, option.getLongValue());

		option = LONG.create(1 << 16);
		assertArrayEquals(new byte[] { 1, 0, 0 }, option.encode());
		assertEquals(1 << 16, option.getLongValue());

		option = LONG.create(23984773);
		assertArrayEquals(new byte[] { 1, 109, (byte) 250, (byte) 133 }, option.encode());
		assertEquals(23984773, option.getLongValue());

		option = LONG.create(0xFFFFFFFFL);
		assertArrayEquals(new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF }, option.encode());
		assertEquals(0xFFFFFFFFL, option.getLongValue());

		option = LONG.create(0x9823749837239845L);
		assertArrayEquals(new byte[] { -104, 35, 116, -104, 55, 35, -104, 69 }, option.encode());
		assertEquals(0x9823749837239845L, option.getLongValue());

		option = LONG.create(0xFFFFFFFFFFFFFFFFL);
		assertArrayEquals(new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF }, option.encode());
		assertEquals(0xFFFFFFFFFFFFFFFFL, option.getLongValue());
	}

	@Test
	public void testUriOptions() {
		OptionSet options = new OptionSet();

		options.setUriPath("/foo/bar");
		assertEquals("Uri-Path", "foo/bar", options.getUriPathString());

		options.setUriPath("foo/bar");
		assertEquals("Uri-Path", "foo/bar", options.getUriPathString());

		options.setUriPath("//foo/bar");
		assertEquals("Uri-Path", "/foo/bar", options.getUriPathString());

		options.setUriPath("/foo//bar");
		assertEquals("Uri-Path", "foo//bar", options.getUriPathString());

		options.clearUriPath();
		options.addUriPath("foo");
		options.addUriPath("bar");
		assertEquals("Uri-Path", "foo/bar", options.getUriPathString());

		options.clearUriPath();
		options.addUriPath("foo");
		options.addUriPath("");
		options.addUriPath("bar");
		assertEquals("Uri-Path", "foo//bar", options.getUriPathString());
	}

	@Test
	public void testLocationOptions() {
		OptionSet options = new OptionSet();

		options.setLocationPath("/foo/bar");
		assertEquals("Uri-Path", "foo/bar", options.getLocationPathString());

		options.setLocationPath("foo/bar");
		assertEquals("Uri-Path", "foo/bar", options.getLocationPathString());

		options.setLocationPath("//foo/bar");
		assertEquals("Uri-Path", "/foo/bar", options.getLocationPathString());

		options.setLocationPath("/foo//bar");
		assertEquals("Uri-Path", "foo//bar", options.getLocationPathString());

		options.clearLocationPath();
		options.addLocationPath("foo");
		options.addLocationPath("bar");
		assertEquals("Uri-Path", "foo/bar", options.getLocationPathString());

		options.clearLocationPath();
		options.addLocationPath("foo");
		options.addLocationPath("");
		options.addLocationPath("bar");
		assertEquals("Uri-Path", "foo//bar", options.getLocationPathString());
	}

	@Test
	public void testNoResponseOptions() {
		OptionSet options = new OptionSet();

		assertFalse(options.hasNoResponse());

		options.setNoResponse(0);
		assertTrue(options.hasNoResponse());

		NoResponseOption noResponse = options.getNoResponse();
		assertNotNull(noResponse);

		assertEquals(0, noResponse.getMask());

		noResponse = new NoResponseOption(NoResponseOption.SUPPRESS_CLIENT_ERROR);
		options.setNoResponse(noResponse);
		noResponse = options.getNoResponse();
		assertNotNull(noResponse);

		assertFalse(noResponse.suppress(ResponseCode.CONTENT));
		assertTrue(noResponse.suppress(ResponseCode.BAD_REQUEST));
		assertFalse(noResponse.suppress(ResponseCode.SERVICE_UNAVAILABLE));
	}

	@Test
	public void testToString() {
		OptionSet options = new OptionSet();
		options.addETag(new byte[] { 1, 2, 3 });
		options.addETag(new byte[] { (byte) 0xBE, (byte) 0xEF });
		options.addLocationPath("abc");
		options.setUriPath("/this/is/a/test");

		assertEquals(
				"{\"ETag\":[0x010203,0xBEEF], \"Location-Path\":\"abc\", \"Uri-Path\":[\"this\",\"is\",\"a\",\"test\"]}",
				options.toString());

		options.setMaxAge(77);

		assertEquals(
				"{\"ETag\":[0x010203,0xBEEF], \"Location-Path\":\"abc\", \"Uri-Path\":[\"this\",\"is\",\"a\",\"test\"], \"Max-Age\":77}",
				options.toString());

		options = new OptionSet();
		options.setBlock1(1, true, 4);
		assertEquals("{\"Block1\":(szx=1/32, m=true, num=4)}", options.toString());

		options = new OptionSet();
		options.setAccept(MediaTypeRegistry.APPLICATION_VND_OMA_LWM2M_JSON);
		assertEquals("{\"Accept\":\"application/vnd.oma.lwm2m+json\"}", options.toString());

		options = new OptionSet();
		options.setNoResponse(NoResponseOption.SUPPRESS_SERVER_ERROR | NoResponseOption.SUPPRESS_CLIENT_ERROR);
		assertEquals("{\"No-Response\":\"NO CLIENT_ERROR,SERVER_ERROR\"}", options.toString());
	}

	@Test
	public void testOthersCustomOptionRegistry() {
		OptionRegistry registry = MapBasedOptionRegistry.builder()
				.add(StandardOptionRegistry.getDefaultOptionRegistry()).add(CUSTOM_1, CUSTOM_2, CUSTOM_3).build();
		StandardOptionRegistry.setDefaultOptionRegistry(registry);
		testOthers();
	}

	public void testOthers() {

		OptionSet options = new OptionSet();
		Option other1 = CUSTOM_1.create("other1");
		options.addOtherOption(other1);
		Option other2_1 = CUSTOM_2.create("other2-1");
		options.addOtherOption(other2_1);
		Option other2_2 = CUSTOM_2.create("other2-2");
		options.addOtherOption(other2_2);
		Option other3 = CUSTOM_3.create("other3");
		options.addOtherOption(other3);

		Option port = StandardOptionRegistry.URI_PORT.create(5684);
		options.addOption(port);

		Option no = StandardOptionRegistry.OBSERVE.create(0);

		List<Option> list = options.asSortedList();
		assertThat(list.size(), is(5));
		assertThat(list, hasItem(other1));
		assertThat(list, hasItem(other2_1));
		assertThat(list, hasItem(other2_2));
		assertThat(list, hasItem(port));
		assertThat(list, not(hasItem(no)));

		list = options.getOthers();
		assertThat(list.size(), is(4));
		assertThat(list, hasItem(other1));
		assertThat(list, hasItem(other2_1));
		assertThat(list, hasItem(other2_2));
		assertThat(list, not(hasItem(port)));
		assertThat(list, not(hasItem(no)));

		// add second elective single value option => ignore
		Option other1a = CUSTOM_1.create("other1a");
		options.addOtherOption(other1a);
		list = options.asSortedList();
		assertThat(list.size(), is(5));
		// since 4.0 comply with RFC7252 5.4.1, 4.5.5
		assertThat(list, hasItem(other1));
		assertThat(list, not(hasItem(other1a)));

		// clear and add new elective single value option
		options.clearOtherOption(CUSTOM_1);
		options.addOtherOption(other1a);
		list = options.asSortedList();
		assertThat(list.size(), is(5));
		assertThat(list, not(hasItem(other1)));
		assertThat(list, hasItem(other1a));

		// add second critical single value option => exception
		Option other3a = CUSTOM_3.create("other3a");
		try {
			options.addOtherOption(other3a);
			fail("add second critical single value option didn't fail.");
		} catch (IllegalArgumentException ex) {
			assertThat(ex.getMessage(), containsString(CUSTOM_3.toString()));
			assertThat(list, is(options.asSortedList()));
		}

		list = options.getOthers(CUSTOM_1);
		assertThat(list.size(), is(1));
		assertThat(list, hasItem(other1a));
		assertThat(list, not(hasItem(other2_1)));
		assertThat(list, not(hasItem(other2_2)));
		assertThat(list, not(hasItem(port)));
		assertThat(list, not(hasItem(no)));

		assertThat(options.getOtherOption(CUSTOM_1), is(other1a));
		assertThat(options.getOtherOption(CUSTOM_2), is(other2_1));

		options.addOtherOption(other2_1);
		options.clearOtherOption(other2_1);

		list = options.getOthers();
		assertThat(list.size(), is(3));
		assertThat(list, hasItem(other1a));
		assertThat(list, not(hasItem(other2_1)));
		assertThat(list, hasItem(other2_2));

		options.addOtherOption(other2_1);
		options.clearOtherOption(other2_1.getDefinition());

		list = options.getOthers();
		assertThat(list.size(), is(2));
		assertThat(list, hasItem(other1a));
		assertThat(list, not(hasItem(other2_1)));
		assertThat(list, not(hasItem(other2_2)));
	}

	@Test
	public void testUriHostOption() {
		OptionSet options = new OptionSet();
		options.setUriHost("host1");
		assertThat(options.getUriHost(), is("host1"));
		options.setUriHost("host2");
		assertThat(options.getUriHost(), is("host2"));
		try {
			options.addOption(StandardOptionRegistry.URI_HOST.create("host3"));
			fail("add second critical single value option didn't fail.");
		} catch (IllegalArgumentException ex) {
			assertThat(ex.getMessage(), containsString(StandardOptionRegistry.URI_HOST.toString()));
			assertThat(options.getUriHost(), is("host2"));
		}
	}

	@Test
	public void testUriPortOption() {
		OptionSet options = new OptionSet();
		options.setUriPort(5683);
		assertThat(options.getUriPort(), is(5683));
		options.setUriPort(5684);
		assertThat(options.getUriPort(), is(5684));
		try {
			options.addOption(StandardOptionRegistry.URI_PORT.create(5685));
			fail("add second critical single value option didn't fail.");
		} catch (IllegalArgumentException ex) {
			assertThat(ex.getMessage(), containsString(StandardOptionRegistry.URI_PORT.toString()));
			assertThat(options.getUriPort(), is(5684));
		}
	}

	@Test
	public void testProxyUriOption() {
		OptionSet options = new OptionSet();
		options.setProxyUri("http://host1");
		assertThat(options.getProxyUri(), is("http://host1"));
		options.setProxyUri("http://host2");
		assertThat(options.getProxyUri(), is("http://host2"));
		try {
			options.addOption(StandardOptionRegistry.PROXY_URI.create("http://host3"));
			fail("add second critical single value option didn't fail.");
		} catch (IllegalArgumentException ex) {
			assertThat(ex.getMessage(), containsString(StandardOptionRegistry.PROXY_URI.toString()));
			assertThat(options.getProxyUri(), is("http://host2"));
		}
	}

	@Test
	public void testProxySchemeOption() {
		OptionSet options = new OptionSet();
		options.setProxyScheme("http");
		assertThat(options.getProxyScheme(), is("http"));
		options.setProxyScheme("https");
		assertThat(options.getProxyScheme(), is("https"));
		try {
			options.addOption(StandardOptionRegistry.PROXY_SCHEME.create("http3"));
			fail("add second critical single value option didn't fail.");
		} catch (IllegalArgumentException ex) {
			assertThat(ex.getMessage(), containsString(StandardOptionRegistry.PROXY_SCHEME.toString()));
			assertThat(options.getProxyScheme(), is("https"));
		}
	}

	@Test
	public void testMaxAgeOption() {
		OptionSet options = new OptionSet();
		options.setMaxAge(120);
		assertThat(options.getMaxAge(), is(120L));
		options.setMaxAge(150);
		assertThat(options.getMaxAge(), is(150L));
		// non-repeatable, elective => ignore
		options.addOption(StandardOptionRegistry.MAX_AGE.create(200));
		assertThat(options.getMaxAge(), is(150L));
	}

	@After
	public void tearDown() {
		StandardOptionRegistry.setDefaultOptionRegistry(null);
	}
}
