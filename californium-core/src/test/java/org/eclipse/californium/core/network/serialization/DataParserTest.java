/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * <p>
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.html.
 * <p>
 * Contributors:
 * Matthias Kovatsch - creator and main architect
 * Martin Lanter - architect and re-implementation
 * Dominique Im Obersteg - parsers and initial implementation
 * Daniel Pauli - parsers and initial implementation
 * Kai Hudalla - logging
 * Bosch Software Innovations GmbH - add test cases
 * Achim Kraus (Bosch Software Innovations GmbH) - add test for CoAP specific 
 *                                                 exception information
 ******************************************************************************/
package org.eclipse.californium.core.network.serialization;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.CoAPMessageFormatException;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageFormatException;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.elements.RawData;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 * This test tests the serialization of messages to byte arrays and the parsing
 * back to messages.
 */
@Category(Small.class) @RunWith(Parameterized.class) public class DataParserTest {

	private final DataSerializer serializer;
	private final DataParser parser;
	private final int expectedMid;

	public DataParserTest(DataSerializer serializer, DataParser parser, int expectedMid) {
		this.serializer = serializer;
		this.parser = parser;
		this.expectedMid = expectedMid;
	}

	@Parameterized.Parameters public static List<Object[]> parameters() {
		List<Object[]> parameters = new ArrayList<>();
		parameters.add(new Object[] { new UdpDataSerializer(), new UdpDataParser(), 7 });
		parameters.add(new Object[] { new TcpDataSerializer(), new TcpDataParser(), Message.NONE });
		return parameters;
	}

	@Test public void testRequestParsing() {
		Request request = new Request(Code.POST);
		request.setType(Type.NON);
		request.setMID(expectedMid);
		request.setToken(new byte[] { 11, 82, -91, 77, 3 });
		request.getOptions().addIfMatch(new byte[] { 34, -17 }).addIfMatch(new byte[] { 88, 12, -2, -99, 5 })
				.setContentFormat(40).setAccept(40);

		RawData rawData = serializer.serializeRequest(request);
//		MessageHeader header = parser.parseHeader(rawData);
//		assertTrue(CoAP.isRequest(header.getCode()));
//
//		Request result = parser.parseRequest(rawData);
		Request result = (Request) parser.parseMessage(rawData);
		assertEquals(request.getMID(), result.getMID());
		assertArrayEquals(request.getToken(), result.getToken());
		assertEquals(request.getOptions().asSortedList(), result.getOptions().asSortedList());
	}

	@Test public void testParseMessageDetectsIllegalCodeClass() {
		// GIVEN a message with a class code of 1, i.e. not a request
		byte[] malformedRequest = new byte[] { 0b01000000, // ver 1, CON, token length: 0
				0b00100001, // code: 1.01 -> class 1 is reserved
				0x00, 0x10 // message ID
		};

		RawData rawData = new RawData(malformedRequest, new InetSocketAddress(0));

		// WHEN parsing the request
		try {
			parser.parseMessage(rawData);
			fail("Parser should have detected that message is not a request");
		} catch (CoAPMessageFormatException e) {
			assertEquals(0b00100001, e.getCode());
			assertEquals(true, e.isConfirmable());
			// THEN an exception is thrown by the parser
		}
	}

	@Test public void testParseMessageDetectsIllegalCode() {
		// GIVEN a message with a class code of 0.07, i.e. not a request
		byte[] malformedRequest = new byte[] { 0b01000000, // ver 1, CON, token length: 0
				0b00000111, // code: 0.07 -> class 1 is reserved
				0x00, 0x10 // message ID
		};

		RawData rawData = new RawData(malformedRequest, new InetSocketAddress(0));

		// WHEN parsing the request
		try {
			parser.parseMessage(rawData);
			fail("Parser should have detected that message is not a request");
		} catch (CoAPMessageFormatException e) {
			assertEquals(0b00000111, e.getCode());
			assertEquals(true, e.isConfirmable());
			// THEN an exception is thrown by the parser
		}
	}

	@Test public void testParseMessageDetectsMalformedOption() {
		// GIVEN a request with an option value shorter than specified
		byte[] malformedGetRequest = new byte[] { 0b01000000, // ver 1, CON, token length: 0
				0b00000001, // code: 0.01 (GET request)
				0x00, 0x10, // message ID
				0x24, // option number 2, length: 4
				0x01, 0x02, 0x03 // token value is one byte short
		};

		RawData rawData = new RawData(malformedGetRequest, new InetSocketAddress(0));

		// WHEN parsing the request
		try {
			parser.parseMessage(rawData);
			fail("Parser should have detected malformed options");
		} catch (CoAPMessageFormatException e) {
			// THEN an exception is thrown by the parser
			assertEquals(0b00000001, e.getCode());
			assertEquals(true, e.isConfirmable());
		}
	}

	@Test public void testParseMessageDetectsMissingPayload() {
		// GIVEN a request with a payload delimiter but empty payload
		byte[] malformedGetRequest = new byte[] { 0b01000000, // ver 1, CON, token length: 0
				0b00000001, // code: 0.01 (GET request)
				0x00, 0x10, // message ID
				(byte) 0xFF // payload marker
		};
		RawData rawData = new RawData(malformedGetRequest, new InetSocketAddress(0));

		// WHEN parsing the request
		try {
			parser.parseMessage(rawData);
			fail("Parser should have detected missing payload");
		} catch (CoAPMessageFormatException e) {
			// THEN an exception is thrown by the parser
			assertEquals(0b00000001, e.getCode());
			assertEquals(true, e.isConfirmable());
		}
	}

	@Test public void testResponseParsing() {
		Response response = new Response(ResponseCode.CONTENT);
		response.setType(Type.NON);
		response.setMID(expectedMid);
		response.setToken(new byte[] { 22, -1, 0, 78, 100, 22 });
		response.getOptions().addETag(new byte[] { 1, 0, 0, 0, 0, 1 })
				.addLocationPath("/one/two/three/four/five/six/seven/eight/nine/ten")
				.addOption(new Option(57453, "Arbitrary".hashCode())).addOption(new Option(19205, "Arbitrary1"))
				.addOption(new Option(19205, "Arbitrary2")).addOption(new Option(19205, "Arbitrary3"));

		RawData rawData = serializer.serializeResponse(response);

		Response result = (Response) parser.parseMessage(rawData);
		assertEquals(response.getMID(), result.getMID());
		assertArrayEquals(response.getToken(), result.getToken());
		assertEquals(response.getOptions().asSortedList(), result.getOptions().asSortedList());
	}

	@Test public void testUTF8Encoding() {
		Response response = new Response(ResponseCode.CONTENT);
		response.setType(Type.NON);
		response.setMID(expectedMid);
		response.setToken(new byte[] {});
		response.getOptions().addLocationPath("ᚠᛇᚻ᛫ᛒᛦᚦ᛫ᚠᚱᚩᚠᚢᚱ᛫ᚠᛁᚱᚪ᛫ᚷᛖᚻᚹᛦᛚᚳᚢᛗ").addLocationPath("γλώσσα")
				.addLocationPath("пустынных").addLocationQuery("ვეპხის=யாமறிந்த").addLocationQuery("⠊⠀⠉⠁⠝=⠑⠁⠞⠀⠛⠇⠁⠎⠎");
		response.setPayload("⠊⠀⠉⠁⠝⠀⠑⠁⠞⠀⠛⠇⠁⠎⠎⠀⠁⠝⠙⠀⠊⠞⠀⠙⠕⠑⠎⠝⠞⠀⠓⠥⠗⠞⠀⠍⠑");

		RawData rawData = serializer.serializeResponse(response);

		Response result = (Response) parser.parseMessage(rawData);
		assertEquals("ᚠᛇᚻ᛫ᛒᛦᚦ᛫ᚠᚱᚩᚠᚢᚱ᛫ᚠᛁᚱᚪ᛫ᚷᛖᚻᚹᛦᛚᚳᚢᛗ/γλώσσα/пустынных", response.getOptions().getLocationPathString());
		assertEquals("ვეპხის=யாமறிந்த&⠊⠀⠉⠁⠝=⠑⠁⠞⠀⠛⠇⠁⠎⠎", response.getOptions().getLocationQueryString());
		assertEquals("⠊⠀⠉⠁⠝⠀⠑⠁⠞⠀⠛⠇⠁⠎⠎⠀⠁⠝⠙⠀⠊⠞⠀⠙⠕⠑⠎⠝⠞⠀⠓⠥⠗⠞⠀⠍⠑", result.getPayloadString());
		assertEquals(response.getMID(), result.getMID());
	}
}
