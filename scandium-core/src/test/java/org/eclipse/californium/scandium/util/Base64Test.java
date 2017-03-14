/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - Initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.util;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.eclipse.californium.scandium.category.Small;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

/**
 * Some test verifying correctness of Rob Harder's {@code Base64} encoder/decoder.
 *
 */
@Category(Small.class)
@RunWith(Parameterized.class)
public class Base64Test {

	@Parameter
	public byte[] input;

	@Parameters
	public static List<byte[]> params() {
		return Arrays.asList(
				new byte[]{0x01, 0x02, 0x03},
				new byte[]{0x01, 0x02, 0x03, 0x04},
				new byte[]{0x01, 0x02, 0x03, 0x04, 0x05});
	}

	/**
	 * Verifies that a String representing an encoded byte array does not contain trailing
	 * 0x00 bytes when using the {@code NO_PADDING} option.
	 * 
	 * @throws IOException if the test fails.
	 */
	@Test
	public void testEncodeBytesRecognizesNoPaddingOption() throws IOException {

		String result = Base64.encodeBytes(input, Base64.ENCODE | Base64.URL_SAFE);
		int excessBytes = input.length % 3;
		int expectedLength = (1 + (excessBytes > 0 ? 1 : 0)) * 4;
		assertThat(result.length(), is(expectedLength));
		if (input.length % 3 > 0) {
			assertTrue(result.endsWith("="));
		}
		result = Base64.encodeBytes(input, Base64.ENCODE | Base64.URL_SAFE | Base64.NO_PADDING);
		assertFalse(result.endsWith("="));
		expectedLength = 4 + (excessBytes > 0 ? excessBytes + 1 : 0);
		assertThat(result.length(), is(expectedLength));
	}

}
