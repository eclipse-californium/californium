/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Test;

public class StringUtilTest {
	@Test
	public void testHex2ByteArray() {
		String line = "4130010A";
		byte[] result = StringUtil.hex2ByteArray(line);

		assertThat(result, is(new byte[] { 0x41, 0x30, 0x01, 0x0a }));
	}

	@Test
	public void testHex2CharArray() {
		String line = "4130010A";
		char[] result = StringUtil.hex2CharArray(line);

		assertThat(result, is(new char[] { 'A', '0', 0x01, '\n' }));
	}

	@Test
	public void testHex2CharArrayWithNull() {
		String line = null;
		char[] result = StringUtil.hex2CharArray(line);

		assertThat(result, is((char[]) null));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testHex2CharArrayIllegalArgumentLength() {
		String line = "4130010A0";
		StringUtil.hex2CharArray(line);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testHex2CharArrayIllegalArgumentContent() {
		String line = "4130010A0Z";
		StringUtil.hex2CharArray(line);
	}

}
