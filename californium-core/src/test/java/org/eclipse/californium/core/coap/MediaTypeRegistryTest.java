/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertArrayEquals;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.*;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Tests to validate the MediaTypeRegistry.
 */
@Category(Small.class)
public class MediaTypeRegistryTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	@Test
	public void testParse() {
		assertThat(MediaTypeRegistry.parse("plain/text"), is(UNDEFINED));
		assertThat(MediaTypeRegistry.parse("text/plain"), is(TEXT_PLAIN));
		assertThat(MediaTypeRegistry.parse("application/json"), is(APPLICATION_JSON));
	}

	@Test
	public void testParseWildcard() {
		int[] mediaTypes = MediaTypeRegistry.parseWildcard("text/plain");
		assertArrayEquals(new int[] { TEXT_PLAIN }, mediaTypes);
		mediaTypes = MediaTypeRegistry.parseWildcard("*/*");
		assertThat(mediaTypes.length, is(MediaTypeRegistry.getAllMediaTypes().size()));
		mediaTypes = MediaTypeRegistry.parseWildcard("text/*");
		assertArrayEquals(new int[] { TEXT_PLAIN, TEXT_CSS }, mediaTypes);
		mediaTypes = MediaTypeRegistry.parseWildcard("application/*");
		assertThat(mediaTypes.length, is(47));
		mediaTypes = MediaTypeRegistry.parseWildcard("image/*");
		assertArrayEquals(new int[] { IMAGE_GIF, IMAGE_JPEG, IMAGE_PNG, IMAGE_SVG_XML }, mediaTypes);
		mediaTypes = MediaTypeRegistry.parseWildcard("plain/*");
		assertThat(mediaTypes.length, is(0));
		mediaTypes = MediaTypeRegistry.parseWildcard("*/plain");
		assertThat(mediaTypes.length, is(0));
	}

	@Test(expected = NullPointerException.class)
	public void testParseWildcardNull() {
		MediaTypeRegistry.parseWildcard(null);
	}

	@Test
	public void testParseWithParameter() {
		int[] mediaTypes = MediaTypeRegistry.parseWithParameter("text/plain");
		assertArrayEquals(new int[] { TEXT_PLAIN }, mediaTypes);
		mediaTypes = MediaTypeRegistry.parseWithParameter("text/plain; charset=utf-8");
		assertArrayEquals(new int[] { TEXT_PLAIN }, mediaTypes);
		mediaTypes = MediaTypeRegistry.parseWithParameter("text/plain; charset=us-ascii");
		assertArrayEquals(new int[] { TEXT_PLAIN }, mediaTypes);
		mediaTypes = MediaTypeRegistry.parseWithParameter("application/cose; cose-type=\"cose-mac\"");
		assertArrayEquals(new int[] { APPLICATION_COSE_MAC }, mediaTypes);
		mediaTypes = MediaTypeRegistry.parseWithParameter("application/cose; cose-type=\"cose-sign\"");
		assertArrayEquals(new int[] { APPLICATION_COSE_SIGN }, mediaTypes);
		mediaTypes = MediaTypeRegistry.parseWithParameter("application/cose; cose-type=\"unknown\"");
		assertArrayEquals(new int[] {}, mediaTypes);
		mediaTypes = MediaTypeRegistry.parseWithParameter("application/cose");
		assertArrayEquals(new int[] { APPLICATION_COSE_ENCRYPT0, APPLICATION_COSE_MAC0, APPLICATION_COSE_SIGN1,
				APPLICATION_COSE_ENCRYPT, APPLICATION_COSE_MAC, APPLICATION_COSE_SIGN }, mediaTypes);
	}

	@Test(expected = NullPointerException.class)
	public void testParseWithParameterNull() {
		MediaTypeRegistry.parseWithParameter(null);
	}
}
