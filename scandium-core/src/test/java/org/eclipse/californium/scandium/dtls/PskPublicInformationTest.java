/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 *******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.eclipse.californium.elements.util.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.scandium.category.Small;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.ExpectedException;

@Category(Small.class)
public class PskPublicInformationTest {

	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Test
	public void testCompliantPublicInformation() {
		PskPublicInformation information = new PskPublicInformation("test");
		assertTrue("is compliant", information.isCompliantEncoding());
	}

	@Test
	public void testPublicInformationEquals() {
		PskPublicInformation information1 = new PskPublicInformation("test1");
		PskPublicInformation information2 = new PskPublicInformation("test1");
		assertEquals(information1, information2);
		PskPublicInformation information3 = new PskPublicInformation("test2");
		assertFalse(information1.equals(information3));
	}

	@Test
	public void testPublicInformationNormalize() {
		PskPublicInformation information = new PskPublicInformation("none", "compliant".getBytes(UTF_8));
		assertFalse(information.isCompliantEncoding());
		information.normalize("compliant");
		assertTrue(information.isCompliantEncoding());
	}

	@Test
	public void testPublicInformationNormalizeNull() {
		PskPublicInformation information = new PskPublicInformation("none", "compliant".getBytes(UTF_8));
		assertFalse(information.isCompliantEncoding());
		exception.expect(NullPointerException.class);
		exception.expectMessage("public information must not be null");
		information.normalize(null);
	}

	@Test
	public void testPublicInformationNormalizeEmpty() {
		PskPublicInformation information = new PskPublicInformation("none", "compliant".getBytes(UTF_8));
		assertFalse(information.isCompliantEncoding());
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("public information must not be empty");
		information.normalize("");
	}

	@Test
	public void testPublicInformationNull() {
		exception.expect(NullPointerException.class);
		exception.expectMessage("bytes must not be null");
		new PskPublicInformation((String) null);
	}

	@Test
	public void testPublicInformationFromByteArrayNull() {
		PskPublicInformation information = PskPublicInformation.fromByteArray(null);
		assertEquals(PskPublicInformation.EMPTY, information);
	}

	@Test
	public void testPublicInformationFromByteArrayEmpty() {
		PskPublicInformation information = PskPublicInformation.fromByteArray(Bytes.EMPTY);
		assertEquals(PskPublicInformation.EMPTY, information);
	}

	@Test
	public void testPublicInformationFromByteArray() {
		PskPublicInformation information1 = PskPublicInformation.fromByteArray("test".getBytes(UTF_8));
		PskPublicInformation information2 = new PskPublicInformation("test");
		assertEquals(information1, information2);
	}

}
