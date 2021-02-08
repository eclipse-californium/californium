/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotEquals;

import org.junit.Test;

/**
 * Unit tests for {@link Bytes}.
 * 
 * @since 3.0
 */
public class BytesTest {

	private static class TestBytes extends Bytes {

		private TestBytes(byte[] data, int maxLength, boolean copy, boolean useClassInEquals) {
			super(data, maxLength, copy, useClassInEquals);
		}
	}

	@Test
	public void testBytesEquals() {
		byte[] data = { 0, 1, 2, 3 };
		Bytes basic = new Bytes(data);
		Bytes test = new TestBytes(data, 32, true, false);
		assertThat(basic, is(test));
		assertThat(test, is(basic));
	}

	@Test
	public void testBytesNotEquals() {
		byte[] data = { 0, 1, 2, 3 };
		Bytes basic = new Bytes(data);
		Bytes test = new TestBytes(data, 32, true, true);
		assertThat(basic, not(is(test)));
		assertThat(test, not(is(basic)));
	}

	@Test
	public void testBytesNotCloned() {
		byte[] data = { 0, 1, 2, 3 };
		Bytes basic = new Bytes(data);
		// Note: manipulation is not intended and only done for this test!
		data[0]++;
		assertArrayEquals(data, basic.getBytes());
	}

	@Test
	public void testBytesCloned() {
		byte[] data = { 0, 1, 2, 3 };
		Bytes basic = new Bytes(data, 32, true);
		// Note: manipulation is not intended and only done for this test!
		data[0]++;
		assertNotEquals(data[0], basic.getBytes()[0]);
	}

}
