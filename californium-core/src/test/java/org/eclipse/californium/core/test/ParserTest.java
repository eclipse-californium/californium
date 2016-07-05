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
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.MessageFormatException;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.serialization.DataParser;
import org.eclipse.californium.core.network.serialization.DataSerializer;
import org.eclipse.californium.core.network.serialization.MessageHeader;
import org.eclipse.californium.core.network.serialization.TcpDataParser;
import org.eclipse.californium.core.network.serialization.TcpDataSerializer;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.core.network.serialization.UdpDataSerializer;
import org.eclipse.californium.elements.RawData;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

/**
 * This test tests the serialization of messages to byte arrays and the parsing
 * back to messages.
 */
@Category(Small.class)
@RunWith(Parameterized.class)
public class ParserTest {

	private final DataSerializer serializer;
	private final DataParser parser;
	private final int expectedMid;

	public ParserTest(DataSerializer serializer, DataParser parser, int expectedMid) {
		this.serializer = serializer;
		this.parser = parser;
		this.expectedMid = expectedMid;
	}

	@Parameterized.Parameters
	public static List<Object[]> parameters() {
		List<Object[]> parameters = new ArrayList<>();
		parameters.add(new Object[]{new UdpDataSerializer(), new UdpDataParser(), 7});
		parameters.add(new Object[]{new TcpDataSerializer(), new TcpDataParser(), 0});
		return parameters;
	}

	@Test
	public void testRequestParsing() {
		Request request = new Request(Code.POST);
		request.setType(Type.NON);
		request.setMID(expectedMid);
		request.setToken(new byte[] { 11, 82, -91, 77, 3 });
		request.getOptions().addIfMatch(new byte[] { 34, -17 }).addIfMatch(new byte[] { 88, 12, -2, -99, 5 })
				.setContentFormat(40).setAccept(40);

		RawData rawData = serializer.serializeRequest(request);
		MessageHeader header = parser.parseHeader(rawData);
		assertTrue(CoAP.isRequest(header.getCode()));

		Request result = parser.parseRequest(rawData);
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

		RawData rawData = new RawData(malformedRequest, new InetSocketAddress(0));

		// WHEN parsing the request
		try {
			parser.parseRequest(rawData);
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
		RawData rawData = new RawData(malformedRequest, new InetSocketAddress(0));

		// WHEN parsing the request
		try {
			parser.parseResponse(rawData);
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
		RawData rawData = new RawData(notAnEmptyMessage, new InetSocketAddress(0));

		// WHEN parsing the message as an empty message
		try {
			parser.parseEmptyMessage(rawData);
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
		RawData rawData = new RawData(malformedGetRequest, new InetSocketAddress(0));
		MessageHeader header = parser.parseHeader(rawData);
		assertTrue(CoAP.isRequest(header.getCode()));

		// WHEN parsing the request
		try {
			parser.parseRequest(rawData);
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
		RawData rawData = new RawData(malformedResponse, new InetSocketAddress(0));
		MessageHeader header = parser.parseHeader(rawData);
		assertTrue(CoAP.isResponse(header.getCode()));

		// WHEN parsing the response
		try {
			parser.parseResponse(rawData);
			fail("Parser should have detected missing payload");
		} catch (MessageFormatException e) {
			// THEN an exception is thrown by the parser
		}
	}

	@Test
	public void testResponseParsing() {
		Response response = new Response(ResponseCode.CONTENT);
		response.setType(Type.NON);
		response.setMID(expectedMid);
		response.setToken(new byte[] { 22, -1, 0, 78, 100, 22 });
		response.getOptions().addETag(new byte[] { 1, 0, 0, 0, 0, 1 })
				.addLocationPath("/one/two/three/four/five/six/seven/eight/nine/ten")
				.addOption(new Option(57453, "Arbitrary".hashCode())).addOption(new Option(19205, "Arbitrary1"))
				.addOption(new Option(19205, "Arbitrary2")).addOption(new Option(19205, "Arbitrary3"));

		RawData rawData = serializer.serializeResponse(response);
		MessageHeader header = parser.parseHeader(rawData);
		assertTrue(CoAP.isResponse(header.getCode()));

		Response result = parser.parseResponse(rawData);
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

		RawData rawData = serializer.serializeResponse(response);

		MessageHeader header = parser.parseHeader(rawData);
		assertTrue(CoAP.isResponse(header.getCode()));

		Response result = parser.parseResponse(rawData);
		assertEquals("ᚠᛇᚻ᛫ᛒᛦᚦ᛫ᚠᚱᚩᚠᚢᚱ᛫ᚠᛁᚱᚪ᛫ᚷᛖᚻᚹᛦᛚᚳᚢᛗ/γλώσσα/пустынных", response.getOptions().getLocationPathString());
		assertEquals("ვეპხის=யாமறிந்த&⠊⠀⠉⠁⠝=⠑⠁⠞⠀⠛⠇⠁⠎⠎", response.getOptions().getLocationQueryString());
		assertEquals("⠊⠀⠉⠁⠝⠀⠑⠁⠞⠀⠛⠇⠁⠎⠎⠀⠁⠝⠙⠀⠊⠞⠀⠙⠕⠑⠎⠝⠞⠀⠓⠥⠗⠞⠀⠍⠑", result.getPayloadString());
	}
}
