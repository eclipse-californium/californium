/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Bosch Software Innovations GmbH - add test cases
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.junit.Assert.*;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.MessageFormatException;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.serialization.DataParser;
import org.eclipse.californium.core.network.serialization.DataSerializer;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * This test tests the serialization of messages to byte arrays and the parsing
 * back to messages.
 */
@Category(Small.class)
public class ParserTest {

	@Test
	public void testRequestParsing() {
		Request request = new Request(Code.POST);
		request.setType(Type.NON);
		request.setMID(7);
		request.setToken(new byte[] { 11, 82, -91, 77, 3 });
		request.getOptions().addIfMatch(new byte[] { 34, -17 }).addIfMatch(new byte[] { 88, 12, -2, -99, 5 })
				.setContentFormat(40).setAccept(40);

		byte[] bytes = DataSerializer.serializeRequest(request);

		DataParser parser = new DataParser(bytes);
		assertTrue(parser.isRequest());

		Request result = parser.parseRequest();
		assertEquals(request.getMID(), result.getMID());
		assertArrayEquals(request.getToken(), result.getToken());
		assertEquals(request.getOptions().asSortedList(), result.getOptions().asSortedList());
	}

	@Test
	public void testRequestParsingDetectsWrongCodeClass() {
		// GIVEN a message with a class code of 1, i.e. not a request
		byte[] malformedRequest = new byte[] {
				0b01000000, // ver 1, CON, token length: 0
				0b00100001, // code: 1.01 -> class 1 is reserved
				0x00, 0x10 // message ID
		};
		DataParser parser = new DataParser(malformedRequest);

		// WHEN parsing the request
		try {
			parser.parseRequest();
			fail("Parser should have detected that message is not a request");
		} catch (MessageFormatException e) {
			// THEN an exception is thrown by the parser
		}
	}

	@Test
	public void testResponseParsingDetectsWrongCodeClass() {
		// GIVEN a message with a class code of 0, i.e. not a response but a request
		byte[] malformedRequest = new byte[] {
				0b01000000, // ver 1, CON, token length: 0
				0b00000001, // code: 0.01 (GET request)
				0x00, 0x10 // message ID
		};
		DataParser parser = new DataParser(malformedRequest);

		// WHEN parsing the request
		try {
			parser.parseResponse();
			fail("Parser should have detected that message is not a response");
		} catch (MessageFormatException e) {
			// THEN an exception is thrown by the parser
		}
	}

	@Test
	public void testEmptyMessageParsingDetectsWrongCode() {
		// GIVEN a message with a code of 2.04, i.e. a CHANGED response
		byte[] notAnEmptyMessage = new byte[] {
				0b01000000, // ver 1, CON, token length: 0
				0b01000010, // code: 2.04 (CHANGED response)
				0x00, 0x10 // message ID
		};
		DataParser parser = new DataParser(notAnEmptyMessage);

		// WHEN parsing the message as an empty message
		try {
			parser.parseEmptyMessage();
			fail("Parser should have detected that message is not a CoAP empty message");
		} catch (MessageFormatException e) {
			// THEN an exception is thrown by the parser
		}
	}

	@Test
	public void testRequestParsingDetectsMissingPayloadInRequest() {
		// GIVEN a request with a payload delimiter but empty payload
		byte[] malformedGetRequest = new byte[] {
				0b01000000, // ver 1, CON, token length: 0
				0b00000001, // code: 0.01 (GET request)
				0x00, 0x10, // message ID
				(byte) 0xFF // payload marker
		};
		DataParser parser = new DataParser(malformedGetRequest);
		assertTrue(parser.isRequest());

		// WHEN parsing the request
		try {
			parser.parseRequest();
			fail("Parser should have detected missing payload");
		} catch (MessageFormatException e) {
			// THEN an exception is thrown by the parser
		}
	}

	@Test
	public void testRequestParsingDetectsMissingPayloadInResponse() {
		// GIVEN a request with a payload delimiter but empty payload
		byte[] malformedResponse = new byte[] {
				0b01000000, // ver 1, CON, token length: 0
				0b01000101, // code: 2.05 (CONTENT response)
				0x00, 0x10, // message ID
				(byte) 0xFF // payload marker
		};
		DataParser parser = new DataParser(malformedResponse);
		assertTrue(parser.isResponse());

		// WHEN parsing the response
		try {
			parser.parseResponse();
			fail("Parser should have detected missing payload");
		} catch (MessageFormatException e) {
			// THEN an exception is thrown by the parser
		}
	}

	@Test
	public void testResponseParsing() {
		Response response = new Response(ResponseCode.CONTENT);
		response.setType(Type.NON);
		response.setMID(9);
		response.setToken(new byte[] { 22, -1, 0, 78, 100, 22 });
		response.getOptions().addETag(new byte[] { 1, 0, 0, 0, 0, 1 })
				.addLocationPath("/one/two/three/four/five/six/seven/eight/nine/ten")
				.addOption(new Option(57453, "Arbitrary".hashCode())).addOption(new Option(19205, "Arbitrary1"))
				.addOption(new Option(19205, "Arbitrary2")).addOption(new Option(19205, "Arbitrary3"));

		byte[] bytes = DataSerializer.serializeResponse(response);

		DataParser parser = new DataParser(bytes);
		assertTrue(parser.isResponse());

		Response result = parser.parseResponse();
		assertEquals(response.getMID(), result.getMID());
		assertArrayEquals(response.getToken(), result.getToken());
		assertEquals(response.getOptions().asSortedList(), result.getOptions().asSortedList());
	}

	@Test
	public void testUTF8Encoding() {
		Response response = new Response(ResponseCode.CONTENT);
		response.setType(Type.NON);
		response.setMID(9);
		response.setToken(new byte[] {});
		response.getOptions().addLocationPath("ᚠᛇᚻ᛫ᛒᛦᚦ᛫ᚠᚱᚩᚠᚢᚱ᛫ᚠᛁᚱᚪ᛫ᚷᛖᚻᚹᛦᛚᚳᚢᛗ").addLocationPath("γλώσσα")
				.addLocationPath("пустынных").addLocationQuery("ვეპხის=யாமறிந்த").addLocationQuery("⠊⠀⠉⠁⠝=⠑⠁⠞⠀⠛⠇⠁⠎⠎");
		response.setPayload("⠊⠀⠉⠁⠝⠀⠑⠁⠞⠀⠛⠇⠁⠎⠎⠀⠁⠝⠙⠀⠊⠞⠀⠙⠕⠑⠎⠝⠞⠀⠓⠥⠗⠞⠀⠍⠑");

		byte[] bytes = DataSerializer.serializeResponse(response);

		DataParser parser = new DataParser(bytes);
		assertTrue(parser.isResponse());

		Response result = parser.parseResponse();
		assertEquals("ᚠᛇᚻ᛫ᛒᛦᚦ᛫ᚠᚱᚩᚠᚢᚱ᛫ᚠᛁᚱᚪ᛫ᚷᛖᚻᚹᛦᛚᚳᚢᛗ/γλώσσα/пустынных", response.getOptions().getLocationPathString());
		assertEquals("ვეპხის=யாமறிந்த&⠊⠀⠉⠁⠝=⠑⠁⠞⠀⠛⠇⠁⠎⠎", response.getOptions().getLocationQueryString());
		assertEquals("⠊⠀⠉⠁⠝⠀⠑⠁⠞⠀⠛⠇⠁⠎⠎⠀⠁⠝⠙⠀⠊⠞⠀⠙⠕⠑⠎⠝⠞⠀⠓⠥⠗⠞⠀⠍⠑", result.getPayloadString());
	}
}
