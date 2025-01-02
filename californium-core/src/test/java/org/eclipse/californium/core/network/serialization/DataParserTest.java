/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * <p>
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v20.html
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
 * Achim Kraus (Bosch Software Innovations GmbH) - parse byte[] instead of RawData
 ******************************************************************************/
package org.eclipse.californium.core.network.serialization;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeFalse;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.CoAPMessageFormatException;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageFormatException;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.coap.option.IntegerOption;
import org.eclipse.californium.core.coap.option.MapBasedOptionRegistry;
import org.eclipse.californium.core.coap.option.OptionRegistry;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.core.coap.option.StringOption;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 * This test tests the serialization of messages to byte arrays and the parsing
 * back to messages.
 */
@Category(Small.class)
@RunWith(Parameterized.class)
public class DataParserTest {

	private static final InetSocketAddress CONNECTOR = new InetSocketAddress(InetAddress.getLoopbackAddress(), 3000);

	private static final EndpointContext ENDPOINT_CONTEXT = new AddressEndpointContext(InetAddress.getLoopbackAddress(),
			1000);

	private static final int CUSTOM_OPTION_1 = 57453;
	private static final int CUSTOM_OPTION_2 = 19205;

	private static final IntegerOption.Definition CUSTOM_1 = new IntegerOption.Definition(CUSTOM_OPTION_1, "custom1",
			true, 0, 4);
	private static final StringOption.Definition CUSTOM_2 = new StringOption.Definition(CUSTOM_OPTION_2, "custom2", false,
			0, 64);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	private final DataSerializer serializer;
	private final DataParser parser;
	private final boolean tcp;
	private final boolean strictEmpty;
	private final int expectedMid;

	public DataParserTest(DataSerializer serializer, DataParser parser, OptionRegistry registry, boolean tcp,
			boolean strictEmpty) {
		this.serializer = serializer;
		this.parser = parser;
		this.tcp = tcp;
		this.strictEmpty = strictEmpty;
		this.expectedMid = tcp ? Message.NONE : 13;
		StandardOptionRegistry.setDefaultOptionRegistry(registry);

	}

	@After
	public void tearDown() {
		((CustomDataParser) parser).setIgnoreOptionError(false);
		((CustomDataParser) parser).setOptionException(null);
		StandardOptionRegistry.setDefaultOptionRegistry(null);
	}

	@Parameterized.Parameters
	public static List<Object[]> parameters() {

		// Default, if "registry" is "null"
		OptionRegistry registry = MapBasedOptionRegistry.builder()
				.add(StandardOptionRegistry.getDefaultOptionRegistry())
				.add(CUSTOM_1, CUSTOM_2).build();
		StandardOptionRegistry.setDefaultOptionRegistry(registry);

		List<Object[]> parameters = new ArrayList<>();
		parameters.add(new Object[] { new TcpDataSerializer(), new CustomTcpDataParser(), null, true, false });
		parameters.add(new Object[] { new UdpDataSerializer(), new CustomUdpDataParser(true), null, false, true });
		parameters.add(new Object[] { new UdpDataSerializer(), new CustomUdpDataParser(false), null, false, false });

		parameters.add(new Object[] { new UdpDataSerializer(), new CustomUdpDataParser(true, registry), registry, false,
				true });
		parameters.add(new Object[] { new TcpDataSerializer(), new CustomTcpDataParser(), registry, true, false });
		return parameters;
	}

	@Test
	public void testRequestParsing() {
		Request request = new Request(Code.POST);
		request.setDestinationContext(ENDPOINT_CONTEXT);
		request.setType(Type.NON);
		request.setMID(expectedMid);
		request.setToken(new byte[] { 11, 82, -91, 77, 3 });
		request.getOptions().addIfMatch(new byte[] { 34, -17 }).addIfMatch(new byte[] { 88, 12, -2, -99, 5 })
				.setContentFormat(40).setAccept(40);

		RawData rawData = serializer.serializeRequest(request);
		rawData = receive(rawData, CONNECTOR);

		Request result = (Request) parser.parseMessage(rawData);
		assertEquals(request.getMID(), result.getMID());
		assertEquals(request.getToken(), result.getToken());
		assertEquals(request.getOptions().asSortedList(), result.getOptions().asSortedList());
	}

	@Test
	public void testParseMessageDetectsIllegalCodeClass() {
		// GIVEN a message with a class code of 1, i.e. not a request
		byte[] malformedRequest = new byte[] { 0b01000000, // ver 1, CON, token
															// length: 0
				0b00100001, // code: 1.01 -> class 1 is reserved
				0x00, 0x10 // message ID
		};

		// WHEN parsing the request
		try {
			parser.parseMessage(malformedRequest);
			fail("Parser should have detected that message is not a request");
		} catch (CoAPMessageFormatException e) {
			assertEquals(0b00100001, e.getCode());
			assertEquals(true, e.isConfirmable());
			// THEN an exception is thrown by the parser
		}
	}

	@Test
	public void testParseMessageDetectsIllegalCode() {
		byte code = 0b00001000; // 0.08 is currently unassigned
		// GIVEN a message with a class code of 0.07, i.e. not a request
		byte[] malformedRequest = new byte[] { 0b01000000, // ver 1, CON, token
															// length: 0
				code, 0x00, 0x10 // message ID
		};

		// WHEN parsing the request
		try {
			parser.parseMessage(malformedRequest);
			fail("Parser should have detected that message is not a request");
		} catch (CoAPMessageFormatException e) {
			assertEquals(code, e.getCode());
			assertEquals(true, e.isConfirmable());
			// THEN an exception is thrown by the parser
		}
	}

	@Test
	public void testParseMessageDetectsMalformedRst() {
		assumeFalse(tcp);
		int code = CoAP.ResponseCode.UNAUTHORIZED.value; // 4.01
		// GIVEN a message with a class code of 0.07, i.e. not a request
		byte[] malformedRequest = new byte[] { 0b01110000, // ver 1, RST, token
															// length: 0
				(byte) code, 0x00, 0x10 // message ID
		};

		// WHEN parsing the request
		try {
			parser.parseMessage(malformedRequest);
			if (strictEmpty) {
				fail("Parser should have detected that RST is not empty");
			}
		} catch (CoAPMessageFormatException e) {
			if (!strictEmpty) {
				fail("Parser should have ignored that RST is not empty");
			}
			assertEquals(code, e.getCode());
			assertEquals(false, e.isConfirmable());
			// THEN an exception is thrown by the parser
		}
	}

	@Test
	public void testParseMessageDetectsMalformedOption() {
		// GIVEN a request with an option value shorter than specified
		byte[] malformedGetRequest = new byte[] { 0b01000000, // ver 1, CON,
																// token length:
																// 0
				0b00000001, // code: 0.01 (GET request)
				0x00, 0x10, // message ID
				0x24, // option number 2, length: 4
				0x01, 0x02, 0x03 // option value is one byte too short
		};
		if (tcp) {
			malformedGetRequest[0] = 0x42; // cheat, mid => 2 bytes token
		}

		// WHEN parsing the request
		try {
			parser.parseMessage(malformedGetRequest);
			fail("Parser should have detected malformed options");
		} catch (CoAPMessageFormatException e) {
			// THEN an exception is thrown by the parser
			assertEquals(0b00000001, e.getCode());
			assertEquals(true, e.isConfirmable());
		}
	}

	@Test
	public void testParseMessageDetectsBadOption() {
		// GIVEN a request with an option value shorter than specified
		byte[] malformedGetRequest = new byte[] { 0b01000000, // ver 1, CON,
																// token length:
																// 0
				0b00000001, // code: 0.01 (GET request)
				0x00, 0x10, // message ID
				0x74, // option number 7 (uri port), length: 4
				0x01, 0x02, 0x03, 0x04 // option value is too large
		};
		if (tcp) {
			malformedGetRequest[0] = 0x42; // cheat, mid => 2 bytes token
		}

		// WHEN parsing the request
		try {
			parser.parseMessage(malformedGetRequest);
			fail("Parser should have detected malformed options");
		} catch (CoAPMessageFormatException e) {
			// THEN an exception is thrown by the parser
			assertEquals(0b00000001, e.getCode());
			assertEquals(true, e.isConfirmable());
		}
	}

	@Test
	public void testParseMessageIgnoresBadOption() {
		// GIVEN a request with an option value shorter than specified
		byte[] malformedGetRequest = new byte[] { 0b01000000, // ver 1, CON,
																// token length:
																// 0
				0b00000001, // code: 0.01 (GET request)
				0x00, 0x10, // message ID
				0x74, // option number 7 (uri port), length: 4
				0x01, 0x02, 0x03, 0x04 // option value is too large
		};
		if (tcp) {
			malformedGetRequest[0] = 0x42; // cheat, mid => 2 bytes token
		}

		// WHEN parsing the request
		((CustomDataParser) parser).setIgnoreOptionError(true);
		Message message = parser.parseMessage(malformedGetRequest);
		assertFalse(message.getOptions().hasUriPort());
	}

	@Test
	public void testParseMessageDetectsUnknownCriticalOption() {

		// GIVEN a request with an option value shorter than specified
		byte[] malformedGetRequest = new byte[] { 0b01000000, // ver 1, CON,
																// token length:
																// 0
				0b00000001, // code: 0.01 (GET request)
				0x00, 0x10, // message ID
				(byte) 0xd1, 0x0c, // option number 25, length: 1
				0x64 // option value
		};
		if (tcp) {
			malformedGetRequest[0] = 0x32; // cheat, 2 bytes mid => 2 bytes
											// token
		}

		// WHEN parsing the request
		try {
			parser.parseMessage(malformedGetRequest);
			fail("Parser should have detected malformed options");
		} catch (CoAPMessageFormatException e) {
			// THEN an exception is thrown by the parser
			assertEquals(0b00000001, e.getCode());
			assertEquals(true, e.isConfirmable());
			assertEquals(ResponseCode.BAD_OPTION, e.getErrorCode());
		}
	}

	@Test
	public void testParseMessageDetectsMalformedToken() {
		// GIVEN a request with an option value shorter than specified
		byte[] malformedGetRequest = new byte[] { 0b01001000, // ver 1, CON,
																// token length:
																// 8
				0b00000001, // code: 0.01 (GET request)
				0x00, 0x10, // message ID
				0x24, // option number 2, length: 4
				0x01, 0x02, 0x03 // token value is one byte short
		};

		// WHEN parsing the request
		try {
			parser.parseMessage(malformedGetRequest);
			fail("Parser should have detected malformed options");
		} catch (CoAPMessageFormatException e) {
			// THEN an exception is thrown by the udp parser
			assertFalse(tcp);
			assertEquals(0b00000001, e.getCode());
			assertEquals(true, e.isConfirmable());
		} catch (MessageFormatException e) {
			// THEN an exception is thrown by the tcp parser
			assertTrue(tcp);
		}
	}

	@Test
	public void testParseMessageDetectsMissingPayload() {
		// GIVEN a request with a payload delimiter but empty payload
		byte[] malformedGetRequest = new byte[] { 0b01000000, // ver 1, CON,
																// token length:
																// 0
				0b00000001, // code: 0.01 (GET request)
				0x00, 0x10, // message ID
				(byte) 0xFF // payload marker
		};

		// WHEN parsing the request
		try {
			parser.parseMessage(malformedGetRequest);
			fail("Parser should have detected missing payload");
		} catch (CoAPMessageFormatException e) {
			// THEN an exception is thrown by the parser
			assertEquals(0b00000001, e.getCode());
			assertEquals(true, e.isConfirmable());
		}
	}

	@Test
	public void testResponseParsing() {
		Response response = new Response(ResponseCode.CONTENT);
		response.setDestinationContext(ENDPOINT_CONTEXT);
		response.setType(Type.NON);
		response.setMID(expectedMid);
		response.setToken(new byte[] { 22, -1, 0, 78, 100, 22 });
		response.getOptions().addETag(new byte[] { 1, 0, 0, 0, 0, 1 })
				.addLocationPath("/one/two/three/four/five/six/seven/eight/nine/ten")
				.addOption(CUSTOM_1.create(1234567)).addOption(CUSTOM_2.create("Arbitrary1"))
				.addOption(CUSTOM_2.create("Arbitrary2")).addOption(CUSTOM_2.create("Arbitrary3"));

		RawData rawData = serializer.serializeResponse(response);
		rawData = receive(rawData, CONNECTOR);

		Response result = (Response) parser.parseMessage(rawData);
		assertEquals(response.getMID(), result.getMID());
		assertEquals(response.getToken(), result.getToken());
		response.getOptions().asSortedList();
		result.getOptions().asSortedList();
		assertEquals(response.getOptions().asSortedList(), result.getOptions().asSortedList());
	}

	@Test
	public void testUTF8Encoding() {
		Response response = new Response(ResponseCode.CONTENT);
		response.setDestinationContext(ENDPOINT_CONTEXT);
		response.setType(Type.NON);
		response.setMID(expectedMid);
		response.setToken(Token.EMPTY);
		response.getOptions().addLocationPath("ᚠᛇᚻ᛫ᛒᛦᚦ᛫ᚠᚱᚩᚠᚢᚱ᛫ᚠᛁᚱᚪ᛫ᚷᛖᚻᚹᛦᛚᚳᚢᛗ").addLocationPath("γλώσσα")
				.addLocationPath("пустынных").addLocationQuery("ვეპხის=யாமறிந்த").addLocationQuery("⠊⠀⠉⠁⠝=⠑⠁⠞⠀⠛⠇⠁⠎⠎");
		response.setPayload("⠊⠀⠉⠁⠝⠀⠑⠁⠞⠀⠛⠇⠁⠎⠎⠀⠁⠝⠙⠀⠊⠞⠀⠙⠕⠑⠎⠝⠞⠀⠓⠥⠗⠞⠀⠍⠑");

		RawData rawData = serializer.serializeResponse(response);
		rawData = receive(rawData, CONNECTOR);

		Response result = (Response) parser.parseMessage(rawData);
		assertEquals("ᚠᛇᚻ᛫ᛒᛦᚦ᛫ᚠᚱᚩᚠᚢᚱ᛫ᚠᛁᚱᚪ᛫ᚷᛖᚻᚹᛦᛚᚳᚢᛗ/γλώσσα/пустынных", response.getOptions().getLocationPathString());
		assertEquals("ვეპხის=யாமறிந்த&⠊⠀⠉⠁⠝=⠑⠁⠞⠀⠛⠇⠁⠎⠎", response.getOptions().getLocationQueryString());
		assertEquals("⠊⠀⠉⠁⠝⠀⠑⠁⠞⠀⠛⠇⠁⠎⠎⠀⠁⠝⠙⠀⠊⠞⠀⠙⠕⠑⠎⠝⠞⠀⠓⠥⠗⠞⠀⠍⠑", result.getPayloadString());
		assertEquals(response.getMID(), result.getMID());
	}

	private static RawData receive(RawData data, InetSocketAddress connector) {
		return RawData.inbound(data.getBytes(), data.getEndpointContext(), data.isMulticast(),
				data.getReceiveNanoTimestamp(), connector);
	}

	public interface CustomDataParser {

		void setIgnoreOptionError(boolean ignore);

		void setOptionException(RuntimeException optionError);
	}

	public static class CustomUdpDataParser extends UdpDataParser implements CustomDataParser {

		private boolean ignoreOptionError;
		private RuntimeException optionError;

		public CustomUdpDataParser(boolean strictEmptyMessageFormat) {
			super(strictEmptyMessageFormat, (OptionRegistry) null);
		}

		public CustomUdpDataParser(boolean strictEmptyMessageFormat, OptionRegistry optionRegistry) {
			super(strictEmptyMessageFormat, optionRegistry);
		}

		@Override
		public void setIgnoreOptionError(boolean ignore) {
			this.ignoreOptionError = ignore;
		}

		@Override
		public void setOptionException(RuntimeException optionError) {
			this.optionError = optionError;
		}

		@Override
		public Option createOption(int code, int optionNumber, DatagramReader reader, int length) {
			if (optionError != null) {
				throw optionError;
			}
			try {
				return super.createOption(code, optionNumber, reader, length);
			} catch (RuntimeException ex) {
				if (ignoreOptionError) {
					return null;
				} else {
					throw ex;
				}
			}
		}
	}

	private static class CustomTcpDataParser extends TcpDataParser implements CustomDataParser {

		private boolean ignoreOptionError;
		private RuntimeException optionError;

		private CustomTcpDataParser() {
			super();
		}

		@Override
		public void setIgnoreOptionError(boolean ignore) {
			this.ignoreOptionError = ignore;
		}

		@Override
		public void setOptionException(RuntimeException optionError) {
			this.optionError = optionError;
		}

		@Override
		public Option createOption(int code, int optionNumber, DatagramReader reader, int length) {
			if (optionError != null) {
				throw optionError;
			}
			try {
				return super.createOption(code, optionNumber,  reader, length);
			} catch (RuntimeException ex) {
				if (ignoreOptionError) {
					return null;
				} else {
					throw ex;
				}
			}
		}
	}
}
