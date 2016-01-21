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

import static org.junit.Assert.*;

import java.io.IOException;

import org.eclipse.californium.scandium.category.Small;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class Base64Test {

	@Before
	public void setUp() throws Exception {
	}

	@Test
	public void testEncodeBytesRecognizesNoPaddingOption() throws IOException {
		byte[] input = new byte[]{0x00, 0x00, 0x00, 0x00};
		String result = Base64.encodeBytes(input, Base64.ENCODE | Base64.URL_SAFE);
		assertTrue(result.endsWith("="));
		result = Base64.encodeBytes(input, Base64.ENCODE | Base64.URL_SAFE | Base64.NO_PADDING);
		assertFalse(result.endsWith("="));
	}


}
