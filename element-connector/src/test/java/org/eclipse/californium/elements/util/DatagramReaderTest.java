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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Before;
import org.junit.Test;

public class DatagramReaderTest {

	DatagramReader reader;

	@Before
	public void setUp() throws Exception {
	}

	@Test
	public void testBitsLeftWorksForEmptyBuffer() {
		givenABuffer(new byte[]{});
		assertThat(reader.bitsLeft(), is(0));
	}

	@Test
	public void testBitsLeftWorksForByteWiseReading() {
		givenABuffer(new byte[]{0x01, 0x02, 0x03});
		assertThat(reader.bitsLeft(), is(24));

		reader.readBytes(1);
		assertThat(reader.bitsLeft(), is(16));

		reader.readBytes(1);
		assertThat(reader.bitsLeft(), is(8));
		reader.readBytes(1);
		assertThat(reader.bitsLeft(), is(0));
	}

	@Test
	public void testBitsLeftWorksForBitWiseReading() {
		givenABuffer(new byte[]{0x01, 0x02, 0x03});

		reader.read(6);
		assertThat(reader.bitsLeft(), is(18));

		reader.readBytes(1);
		assertThat(reader.bitsLeft(), is(10));

		reader.read(10);
		assertThat(reader.bitsLeft(), is(0));
	}

	private void givenABuffer(byte[] buffer) {
		reader = new DatagramReader(buffer);
	}
}
