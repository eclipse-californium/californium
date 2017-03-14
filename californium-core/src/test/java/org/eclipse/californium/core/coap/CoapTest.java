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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add more tests
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.CodeClass;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.CoAP.MessageFormat;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

/**
 * Tests that the mapping from a value to an enum is correct.
 */
@Category(Small.class)
public class CoapTest {

	@Test
	public void testType() {
		for (Type type : Type.values()) {
			assertEquals(type, Type.valueOf(type.value));
		}
	}

	@Test
	public void testCodeClass() {
		for (CodeClass codeClass : CodeClass.values()) {
			assertEquals(codeClass, CodeClass.valueOf(codeClass.value));
		}
	}

	@Test
	public void testCode() {
		for (Code code : Code.values()) {
			assertEquals(code, Code.valueOf(code.value));
			assertTrue(MessageFormat.REQUEST_CODE_LOWER_BOUND <= code.value);
			assertTrue(code.value <= MessageFormat.REQUEST_CODE_UPPER_BOUND);
		}
	}

	@Test
	public void testResponseCode() {
		for (ResponseCode code : ResponseCode.values()) {
			assertEquals(code, ResponseCode.valueOf(code.value));
			assertTrue(MessageFormat.RESPONSE_CODE_LOWER_BOUND <= code.value);
			assertTrue(code.value <= MessageFormat.RESPONSE_CODE_UPPER_BOUND);
		}
	}

	@Test
	public void testGetCodeClass() {
		for (Code code : Code.values()) {
			assertThat(CoAP.getCodeClass(code.value), is(CodeClass.REQUEST.value));
		}
		// success
		assertThat(CoAP.getCodeClass(ResponseCode.CREATED.value), is(CodeClass.SUCCESS_RESPONSE.value));
		assertThat(CoAP.getCodeClass(ResponseCode.CHANGED.value), is(CodeClass.SUCCESS_RESPONSE.value));
		assertThat(CoAP.getCodeClass(ResponseCode.CONTINUE.value), is(CodeClass.SUCCESS_RESPONSE.value));
		// errors
		assertThat(CoAP.getCodeClass(ResponseCode.BAD_REQUEST.value), is(CodeClass.ERROR_RESPONSE.value));
		assertThat(CoAP.getCodeClass(ResponseCode.UNSUPPORTED_CONTENT_FORMAT.value), is(CodeClass.ERROR_RESPONSE.value));
		// server errors
		assertThat(CoAP.getCodeClass(ResponseCode.INTERNAL_SERVER_ERROR.value),
				is(CodeClass.SERVER_ERROR_RESPONSE.value));
		assertThat(CoAP.getCodeClass(ResponseCode.NOT_IMPLEMENTED.value), is(CodeClass.SERVER_ERROR_RESPONSE.value));
		assertThat(CoAP.getCodeClass(ResponseCode.SERVICE_UNAVAILABLE.value), is(CodeClass.SERVER_ERROR_RESPONSE.value));
	}

	@Test
	public void testGetCodeDetail() {
		// Requests
		assertThat(CoAP.getCodeDetail(Code.GET.value), is(1));
		assertThat(CoAP.getCodeDetail(Code.DELETE.value), is(4));
		// success
		assertThat(CoAP.getCodeDetail(ResponseCode.CREATED.value), is(1));
		assertThat(CoAP.getCodeDetail(ResponseCode.CHANGED.value), is(4));
		assertThat(CoAP.getCodeDetail(ResponseCode.CONTINUE.value), is(31));
		// errors
		assertThat(CoAP.getCodeDetail(ResponseCode.BAD_REQUEST.value), is(0));
		assertThat(CoAP.getCodeDetail(ResponseCode.UNSUPPORTED_CONTENT_FORMAT.value), is(15));
		// server errors
		assertThat(CoAP.getCodeDetail(ResponseCode.INTERNAL_SERVER_ERROR.value), is(0));
		assertThat(CoAP.getCodeDetail(ResponseCode.NOT_IMPLEMENTED.value), is(1));
		assertThat(CoAP.getCodeDetail(ResponseCode.SERVICE_UNAVAILABLE.value), is(3));
	}

	@Test
	public void testFormatCode() {
		// Requests
		assertThat(CoAP.formatCode(Code.GET.value), is("0.01"));
		assertThat(CoAP.formatCode(Code.POST.value), is("0.02"));
		// success
		assertThat(CoAP.formatCode(ResponseCode.CREATED.value), is("2.01"));
		assertThat(CoAP.formatCode(ResponseCode.CHANGED.value), is("2.04"));
		assertThat(CoAP.formatCode(ResponseCode.CONTENT.value), is("2.05"));
		// errors
		assertThat(CoAP.formatCode(ResponseCode.BAD_REQUEST.value), is("4.00"));
		assertThat(CoAP.formatCode(ResponseCode.REQUEST_ENTITY_INCOMPLETE.value), is("4.08"));
		assertThat(CoAP.formatCode(ResponseCode.REQUEST_ENTITY_TOO_LARGE.value), is("4.13"));
		assertThat(CoAP.formatCode(ResponseCode.UNSUPPORTED_CONTENT_FORMAT.value), is("4.15"));
		// server errors
		assertThat(CoAP.formatCode(ResponseCode.INTERNAL_SERVER_ERROR.value), is("5.00"));
		assertThat(CoAP.formatCode(ResponseCode.NOT_IMPLEMENTED.value), is("5.01"));
		assertThat(CoAP.formatCode(ResponseCode.SERVICE_UNAVAILABLE.value), is("5.03"));
	}

	@Test
	public void testIsRequest() {
		assertFalse(CoAP.isRequest(MessageFormat.EMPTY_CODE));
		assertTrue(CoAP.isRequest(Code.GET.value));
		assertFalse(CoAP.isRequest(ResponseCode.CHANGED.value));
	}

	@Test
	public void testIsResponse() {
		assertFalse(CoAP.isResponse(MessageFormat.EMPTY_CODE));
		assertFalse(CoAP.isResponse(Code.GET.value));
		assertTrue(CoAP.isResponse(ResponseCode.CHANGED.value));
	}

	@Test
	public void testIsEmptyMessage() {
		assertTrue(CoAP.isEmptyMessage(MessageFormat.EMPTY_CODE));
		assertFalse(CoAP.isEmptyMessage(Code.GET.value));
		assertFalse(CoAP.isEmptyMessage(ResponseCode.CHANGED.value));
	}

	@Test
	public void testIsTcPScheme() {
		assertTrue(CoAP.isTcpScheme(CoAP.COAP_SECURE_TCP_URI_SCHEME));
		assertTrue(CoAP.isTcpScheme(CoAP.COAP_TCP_URI_SCHEME));
		assertFalse(CoAP.isTcpScheme(CoAP.COAP_URI_SCHEME));
		assertFalse(CoAP.isTcpScheme(CoAP.COAP_SECURE_URI_SCHEME));
		assertFalse(CoAP.isTcpScheme("http:"));
	}

	@Test
	public void testIsSecureScheme() {
		assertTrue(CoAP.isSecureScheme(CoAP.COAP_SECURE_TCP_URI_SCHEME));
		assertTrue(CoAP.isSecureScheme(CoAP.COAP_SECURE_URI_SCHEME));
		assertFalse(CoAP.isSecureScheme(CoAP.COAP_URI_SCHEME));
		assertFalse(CoAP.isSecureScheme(CoAP.COAP_TCP_URI_SCHEME));
		assertFalse(CoAP.isSecureScheme("https:"));
	}

	@Test
	public void testIsSupportedScheme() {
		assertTrue(CoAP.isSupportedScheme(CoAP.COAP_SECURE_TCP_URI_SCHEME));
		assertTrue(CoAP.isSupportedScheme(CoAP.COAP_SECURE_URI_SCHEME));
		assertTrue(CoAP.isSupportedScheme(CoAP.COAP_TCP_URI_SCHEME));
		assertTrue(CoAP.isSupportedScheme(CoAP.COAP_URI_SCHEME));
		assertFalse(CoAP.isSupportedScheme("https:"));
	}

	@Test
	public void testGetDefaultPort() {
		assertThat(CoAP.getDefaultPort(CoAP.COAP_SECURE_TCP_URI_SCHEME), is(CoAP.DEFAULT_COAP_SECURE_PORT));
		assertThat(CoAP.getDefaultPort(CoAP.COAP_SECURE_URI_SCHEME), is(CoAP.DEFAULT_COAP_SECURE_PORT));
		assertThat(CoAP.getDefaultPort(CoAP.COAP_TCP_URI_SCHEME), is(CoAP.DEFAULT_COAP_PORT));
		assertThat(CoAP.getDefaultPort(CoAP.COAP_URI_SCHEME), is(CoAP.DEFAULT_COAP_PORT));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testGetDefaultPortError() {
		CoAP.getDefaultPort("http:");
	}

}
