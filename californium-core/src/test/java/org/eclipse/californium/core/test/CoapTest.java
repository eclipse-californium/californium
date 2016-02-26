/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.junit.Assert.assertEquals;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * Tests that the mapping from a value to an enum is correct.
 */
@Category(Small.class)
public class CoapTest {
	
	@Test
	public void testType() {
		for (Type type:Type.values()) {
			assertEquals(type, Type.valueOf(type.value));
		}
	}
	
	@Test
	public void testCode() {
		for (Code code:Code.values()) {
			assertEquals(code, Code.valueOf(code.value));
		}
	}
	
	@Test
	public void testResponseCode() {
		for (ResponseCode code:ResponseCode.values()) {
			assertEquals(code, ResponseCode.valueOf(code.value));
		}
	}
}
