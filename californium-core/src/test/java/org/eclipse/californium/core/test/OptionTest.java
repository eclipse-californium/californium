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

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.List;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.OptionNumberRegistry.CustomOptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionNumberRegistry.OptionFormat;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.NoResponseOption;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.option.MapBasedOptionRegistry;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.core.coap.option.StringOptionDefinition;
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
@SuppressWarnings("deprecation")
public class OptionTest {
	private static final int CUSTOM_OPTION_1 = 0xff1c;
	private static final int CUSTOM_OPTION_2 = 0xff9c;

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
		assertFalse(OptionNumberRegistry.isSingleValue(OptionNumberRegistry.IF_MATCH));
		assertTrue(OptionNumberRegistry.isSingleValue(OptionNumberRegistry.URI_HOST));
		assertFalse(OptionNumberRegistry.isSingleValue(OptionNumberRegistry.ETAG));
		assertTrue(OptionNumberRegistry.isSingleValue(OptionNumberRegistry.IF_NONE_MATCH));
		assertTrue(OptionNumberRegistry.isSingleValue(OptionNumberRegistry.OBSERVE));
		assertTrue(OptionNumberRegistry.isSingleValue(OptionNumberRegistry.URI_PORT));
		assertFalse(OptionNumberRegistry.isSingleValue(OptionNumberRegistry.LOCATION_PATH));
		assertFalse(OptionNumberRegistry.isSingleValue(OptionNumberRegistry.URI_PATH));
		assertTrue(OptionNumberRegistry.isSingleValue(OptionNumberRegistry.CONTENT_FORMAT));
		assertTrue(OptionNumberRegistry.isSingleValue(OptionNumberRegistry.MAX_AGE));
		assertFalse(OptionNumberRegistry.isSingleValue(OptionNumberRegistry.URI_QUERY));
		assertTrue(OptionNumberRegistry.isSingleValue(OptionNumberRegistry.ACCEPT));
		assertFalse(OptionNumberRegistry.isSingleValue(OptionNumberRegistry.LOCATION_QUERY));
		assertTrue(OptionNumberRegistry.isSingleValue(OptionNumberRegistry.BLOCK2));
		assertTrue(OptionNumberRegistry.isSingleValue(OptionNumberRegistry.BLOCK1));
		assertTrue(OptionNumberRegistry.isSingleValue(OptionNumberRegistry.SIZE2));
		assertTrue(OptionNumberRegistry.isSingleValue(OptionNumberRegistry.PROXY_URI));
		assertTrue(OptionNumberRegistry.isSingleValue(OptionNumberRegistry.PROXY_SCHEME));
		assertTrue(OptionNumberRegistry.isSingleValue(OptionNumberRegistry.SIZE1));
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
		Option option = new Option();

		option.setValue(new byte[4]);
		assertArrayEquals(option.getValue(), new byte[4]);

		option.setValue(new byte[] { 69, -104, 35, 55, -104, 116, 35, -104 });
		assertArrayEquals(option.getValue(), new byte[] { 69, -104, 35, 55, -104, 116, 35, -104 });
	}

	@Test
	public void testSetStringValue() {
		Option option = new Option();

		option.setStringValue("");
		assertArrayEquals(option.getValue(), Bytes.EMPTY);

		option.setStringValue("Californium");
		assertArrayEquals(option.getValue(), "Californium".getBytes());
	}

	@Test
	public void testSetIntegerValue() {
		Option option = new Option();

		option.setIntegerValue(0);
		assertArrayEquals(option.getValue(), Bytes.EMPTY);
		assertEquals(0, option.getIntegerValue());

		option.setIntegerValue(11);
		assertArrayEquals(option.getValue(), new byte[] { 11 });
		assertEquals(11, option.getIntegerValue());

		option.setIntegerValue(255);
		assertArrayEquals(option.getValue(), new byte[] { (byte) 255 });
		assertEquals(255, option.getIntegerValue());

		option.setIntegerValue(256);
		assertArrayEquals(option.getValue(), new byte[] { 1, 0 });
		assertEquals(256, option.getIntegerValue());

		option.setIntegerValue(18273);
		assertArrayEquals(option.getValue(), new byte[] { 71, 97 });
		assertEquals(18273, option.getIntegerValue());

		option.setIntegerValue(1 << 16);
		assertArrayEquals(option.getValue(), new byte[] { 1, 0, 0 });
		assertEquals(1 << 16, option.getIntegerValue());

		option.setIntegerValue(23984773);
		assertArrayEquals(option.getValue(), new byte[] { 1, 109, (byte) 250, (byte) 133 });
		assertEquals(23984773, option.getIntegerValue());

		option.setIntegerValue(0xFFFFFFFF);
		assertArrayEquals(option.getValue(), new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF });
		assertEquals(0xFFFFFFFF, option.getIntegerValue());
	}

	@Test
	public void testSetLongValue() {
		Option option = new Option();

		option.setLongValue(0);
		assertArrayEquals(option.getValue(), Bytes.EMPTY);
		assertEquals(0, option.getLongValue());

		option.setLongValue(11);
		assertArrayEquals(option.getValue(), new byte[] { 11 });
		assertEquals(11, option.getLongValue());

		option.setLongValue(255);
		assertArrayEquals(option.getValue(), new byte[] { (byte) 255 });
		assertEquals(255, option.getLongValue());

		option.setLongValue(256);
		assertArrayEquals(option.getValue(), new byte[] { 1, 0 });
		assertEquals(256, option.getLongValue());

		option.setLongValue(18273);
		assertArrayEquals(option.getValue(), new byte[] { 71, 97 });
		assertEquals(18273, option.getLongValue());

		option.setLongValue(1 << 16);
		assertArrayEquals(option.getValue(), new byte[] { 1, 0, 0 });
		assertEquals(1 << 16, option.getLongValue());

		option.setLongValue(23984773);
		assertArrayEquals(option.getValue(), new byte[] { 1, 109, (byte) 250, (byte) 133 });
		assertEquals(23984773, option.getLongValue());

		option.setLongValue(0xFFFFFFFFL);
		assertArrayEquals(option.getValue(), new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF });
		assertEquals(0xFFFFFFFFL, option.getLongValue());

		option.setLongValue(0x9823749837239845L);
		assertArrayEquals(option.getValue(), new byte[] { -104, 35, 116, -104, 55, 35, -104, 69 });
		assertEquals(0x9823749837239845L, option.getLongValue());

		option.setLongValue(0xFFFFFFFFFFFFFFFFL);
		assertArrayEquals(option.getValue(), new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF });
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
	public void testArbitraryOptions() {
		OptionSet options = new OptionSet();
		options.addETag(new byte[] { 1, 2, 3 });
		options.addLocationPath("abc");
		options.addOption(new Option(7, 1));
		options.addOption(new Option(43));
		options.addOption(new Option(33));
		options.addOption(new Option(17, 1));

		// Check that options are in the set
		assertTrue(options.hasOption(OptionNumberRegistry.ETAG));
		assertTrue(options.hasOption(OptionNumberRegistry.LOCATION_PATH));
		assertTrue(options.hasOption(7));
		assertTrue(options.hasOption(17));
		assertTrue(options.hasOption(33));
		assertTrue(options.hasOption(43));

		// Check that others are not
		assertFalse(options.hasOption(19));
		assertFalse(options.hasOption(53));

		// Check that we can remove options
		options.clearETags();
		assertFalse(options.hasOption(OptionNumberRegistry.ETAG));
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
		assertEquals("{\"Block1\":\"(szx=1/32, m=true, num=4)\"}", options.toString());

		options = new OptionSet();
		options.setAccept(MediaTypeRegistry.APPLICATION_VND_OMA_LWM2M_JSON);
		assertEquals("{\"Accept\":\"application/vnd.oma.lwm2m+json\"}", options.toString());

		options = new OptionSet();
		options.setNoResponse(NoResponseOption.SUPPRESS_SERVER_ERROR | NoResponseOption.SUPPRESS_CLIENT_ERROR);
		assertEquals("{\"No-Response\":\"NO CLIENT_ERROR,SERVER_ERROR\"}", options.toString());
	}

	@Test
	public void testOthersCustomOptionNumberRegistry() {
		final int[] CRITICAL_CUSTOM_OPTIONS = { CUSTOM_OPTION_1, CUSTOM_OPTION_2 };
		final CustomOptionNumberRegistry CUSTOM = new CustomOptionNumberRegistry() {
			
			@Override
			public String toString(int optionNumber) {
				switch (optionNumber) {
				case CUSTOM_OPTION_1 :
					return "custom1";
				case CUSTOM_OPTION_2 :
					return "custom2";
				}
				return null;
			}
			
			@Override
			public int toNumber(String name) {
				if ("custom1".equals(name)) {
					return CUSTOM_OPTION_1;
				} else if ("custom2".equals(name)) {
					return CUSTOM_OPTION_2;
				}
				return OptionNumberRegistry.UNKNOWN;
			}
			
			@Override
			public boolean isSingleValue(int optionNumber) {
				return optionNumber != CUSTOM_OPTION_2;
			}
			
			@Override
			public OptionFormat getFormatByNr(int optionNumber) {
				switch (optionNumber) {
				case CUSTOM_OPTION_1 :
				case CUSTOM_OPTION_2 :
					return OptionFormat.STRING;
				}
				return null;
			}
			
			@Override
			public int[] getCriticalCustomOptions() {
				return CRITICAL_CUSTOM_OPTIONS;
			}
			
			@Override
			public int[] getValueLengths(int optionNumber) {
				switch (optionNumber) {
				case CUSTOM_OPTION_1 :
				case CUSTOM_OPTION_2 :
					return new int[] {0, 64};
				}
				return null;
			}
			
			@Override
			public void assertValue(int optionNumber, long value) {
			}
		};

		OptionNumberRegistry.setCustomOptionNumberRegistry(CUSTOM);
		testOthers();
	}

	@Test
	public void testOthersCustomOptionRegistry() {
		StringOptionDefinition CUSTOM_1 = new StringOptionDefinition(CUSTOM_OPTION_1, "custom1", true, 0, 64);
		StringOptionDefinition CUSTOM_2 = new StringOptionDefinition(CUSTOM_OPTION_2, "custom2", false, 0, 64);
		MapBasedOptionRegistry registry = new MapBasedOptionRegistry(StandardOptionRegistry.getDefaultOptionRegistry(),
				CUSTOM_1, CUSTOM_2);
		StandardOptionRegistry.setDefaultOptionRegistry(registry);
		testOthers();
	}

	public void testOthers() {

		OptionSet options = new OptionSet();
		Option other1 = new Option(CUSTOM_OPTION_1, "other1");
		options.addOtherOption(other1);
		Option other2 = new Option(CUSTOM_OPTION_2, "other2");
		options.addOtherOption(other2);
		Option other3 = new Option(CUSTOM_OPTION_2, "other3");
		options.addOtherOption(other3);
		Option port = new Option(OptionNumberRegistry.URI_PORT, 5684);
		options.addOption(port);

		Option no = new Option(OptionNumberRegistry.OBSERVE, 0);

		List<Option> list = options.asSortedList();
		assertThat(list.size(), is(4));
		assertThat(list, hasItem(other1));
		assertThat(list, hasItem(other2));
		assertThat(list, hasItem(other3));
		assertThat(list, hasItem(port));
		assertThat(list, not(hasItem(no)));

		list = options.getOthers();
		assertThat(list.size(), is(3));
		assertThat(list, hasItem(other1));
		assertThat(list, hasItem(other2));
		assertThat(list, hasItem(other3));
		assertThat(list, not(hasItem(port)));
		assertThat(list, not(hasItem(no)));

		list = options.getOthers(CUSTOM_OPTION_1);
		assertThat(list.size(), is(1));
		assertThat(list, hasItem(other1));
		assertThat(list, not(hasItem(other2)));
		assertThat(list, not(hasItem(other3)));
		assertThat(list, not(hasItem(port)));
		assertThat(list, not(hasItem(no)));

		assertThat(options.getOtherOption(CUSTOM_OPTION_1), is(other1));
		assertThat(options.getOtherOption(CUSTOM_OPTION_2), is(other2));

		options.addOtherOption(other2);
		options.clearOtherOption(other2);

		list = options.getOthers();
		assertThat(list.size(), is(2));
		assertThat(list, hasItem(other1));
		assertThat(list, not(hasItem(other2)));
		assertThat(list, hasItem(other3));

		options.addOtherOption(other2);
		options.clearOtherOption(other2.getNumber());

		list = options.getOthers();
		assertThat(list.size(), is(1));
		assertThat(list, hasItem(other1));
		assertThat(list, not(hasItem(other2)));
		assertThat(list, not(hasItem(other3)));
	}

	@After
	public void tearDown() {
		OptionNumberRegistry.setCustomOptionNumberRegistry(null);
		StandardOptionRegistry.setDefaultOptionRegistry(null);
	}

}
