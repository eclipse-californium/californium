/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add tests for CorrelationContext
 *                                                    (fix GitHub issue #104)
 *    Achim Kraus (Bosch Software Innovations GmbH) - add null callback
 *                                                    for response and empty message
 *                                                    issue #305
 ******************************************************************************/
package org.eclipse.californium.core.network.serialization;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

/**
 * Verifies behavior of the common functionality of data serializers.
 */
@Category(Small.class)
@RunWith(Parameterized.class)
public class DataSerializerTest {

	private static final EndpointContext ENDPOINT_CONTEXT = new DtlsEndpointContext(new InetSocketAddress(0), null,
			null, new Bytes("session".getBytes()), 1, "CIPHER", 100);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	/**
	 * The concrete serializer to run the test cases with.
	 */
	@Parameter
	public DataSerializer serializer;

	/**
	 * Gets the concrete serializers to run the test cases with.
	 * 
	 * @return The serializers.
	 */
	@Parameters
	public static DataSerializer[] getSerializers() {
		return new DataSerializer[] { new UdpDataSerializer(), new TcpDataSerializer() };
	}

	/**
	 * Verifies that the getByteArray() method does not set the Message's
	 * <em>bytes</em> property.
	 */
	@Test
	public void testGetByteArrayDoesNotAlterMessage() {

		// GIVEN a CoAP request
		Request req = Request.newGet();
		req.setToken(new byte[] { 0x00 });
		req.getOptions().setObserve(0);
		req.setMID(1);

		// WHEN serializing the request to a byte array
		serializer.getByteArray(req);

		// THEN the serialized byte array is not written to the request's bytes
		// property
		assertNull(req.getBytes());
	}

	/**
	 * Verifies that the serializeRequest() method sets the Message's
	 * <em>bytes</em> property.
	 */
	@Test
	public void testSerializeRequestStoresBytesInMessage() {

		// GIVEN a CoAP request
		Request req = Request.newGet();
		req.setToken(new byte[] { 0x00 });
		req.getOptions().setObserve(0);
		req.setMID(1);
		req.setDestinationContext(new AddressEndpointContext(InetAddress.getLoopbackAddress(), CoAP.DEFAULT_COAP_PORT));

		// WHEN serializing the request to a RawData object
		RawData raw = serializer.serializeRequest(req);

		// THEN the serialized byte array is stored in the request's bytes
		// property
		assertNotNull(req.getBytes());
		assertThat(raw.getBytes(), is(req.getBytes()));
		assertThat(raw.getEndpointContext(), is(req.getDestinationContext()));
		if (serializer instanceof TcpDataSerializer) {
			assertThat(raw.getBytes(), is(StringUtil.hex2ByteArray("11010060")));
		} else {
			assertThat(raw.getBytes(), is(StringUtil.hex2ByteArray("410100010060")));
		}
	}

	@Test
	public void testSerializeRequestDifferentPayloads() {

		// GIVEN a CoAP request
		Request req = Request.newPut();
		req.setToken(new byte[] { 0x00, 0x01 });
		req.getOptions().setUriPath("coap://localhost/test");
		req.setMID(1);
		req.setDestinationContext(new AddressEndpointContext(InetAddress.getLoopbackAddress(), CoAP.DEFAULT_COAP_PORT));
		req.setPayload(TestTools.generatePayload(10));

		// WHEN serializing the request to a RawData object
		serializer.serializeRequest(req);

		// THEN the serialized byte array is stored in the request's bytes
		// property
		assertNotNull(req.getBytes());
		if (serializer instanceof TcpDataSerializer) {
			assertThat(req.getBytes().length, is(38));
			assertThat(req.getBytes(), is(StringUtil
					.hex2ByteArray("D214030001B5636F61703A00096C6F63616C686F73740474657374FF30313233343536373839")));
		} else {
			assertThat(req.getBytes().length, is(39));
			assertThat(req.getBytes(), is(StringUtil
					.hex2ByteArray("420300010001B5636F61703A00096C6F63616C686F73740474657374FF30313233343536373839")));
		}

		req.setBytes(null);
		req.setPayload(TestTools.generatePayload(245));
		serializer.serializeRequest(req);
		assertNotNull(req.getBytes());

		if (serializer instanceof TcpDataSerializer) {
			assertThat(req.getBytes().length, is(273));
			assertStarts(req.getBytes(),
					StringUtil.hex2ByteArray("D2FF030001B5636F61703A00096C6F63616C686F73740474657374FF303132"));
		} else {
			assertThat(req.getBytes().length, is(274));
			assertStarts(req.getBytes(),
					StringUtil.hex2ByteArray("420300010001B5636F61703A00096C6F63616C686F73740474657374FF303132"));
		}

		req.setBytes(null);
		req.setPayload(TestTools.generatePayload(246));
		serializer.serializeRequest(req);
		assertNotNull(req.getBytes());

		if (serializer instanceof TcpDataSerializer) {
			assertThat(req.getBytes().length, is(275));
			assertStarts(req.getBytes(),
					StringUtil.hex2ByteArray("E20000030001B5636F61703A00096C6F63616C686F73740474657374FF303132"));
		} else {
			assertThat(req.getBytes().length, is(275));
			assertStarts(req.getBytes(),
					StringUtil.hex2ByteArray("420300010001B5636F61703A00096C6F63616C686F73740474657374FF303132"));
		}

		req.setBytes(null);
		req.setPayload(TestTools.generatePayload(700));
		serializer.serializeRequest(req);
		assertNotNull(req.getBytes());

		if (serializer instanceof TcpDataSerializer) {
			assertThat(req.getBytes().length, is(729));
			assertStarts(req.getBytes(),
					StringUtil.hex2ByteArray("E201C6030001B5636F61703A00096C6F63616C686F73740474657374FF303132"));
		} else {
			assertThat(req.getBytes().length, is(729));
			assertStarts(req.getBytes(),
					StringUtil.hex2ByteArray("420300010001B5636F61703A00096C6F63616C686F73740474657374FF303132"));
		}

	}

	/**
	 * Verifies that the serializeResponse() method sets the Message's
	 * <em>endpointContext</em>.
	 */
	@Test
	public void testSerializeResponseWithEndpointContext() {

		Response response = new Response(ResponseCode.CONTENT);
		response.setDestinationContext(ENDPOINT_CONTEXT);
		response.setType(Type.ACK);
		response.setMID(1);
		response.setToken(new byte[] { 0x00 });
		RawData data = serializer.serializeResponse(response, null);

		assertThat(data.getEndpointContext(), is(equalTo(ENDPOINT_CONTEXT)));

		if (serializer instanceof TcpDataSerializer) {
			assertThat(data.getBytes(), is(StringUtil.hex2ByteArray("014500")));
		} else {
			assertThat(data.getBytes(), is(StringUtil.hex2ByteArray("6145000100")));
		}
	}

	/**
	 * Verifies that the serializeEmptyMessage() method sets the Message's
	 * <em>endpointContext</em>.
	 */
	@Test
	public void testSerializeEmptyMessageWithEndpointContext() {
		Request request = Request.newGet();
		request.setSourceContext(ENDPOINT_CONTEXT);
		request.setMID(1);

		EmptyMessage ack = EmptyMessage.newACK(request);
		ack.setToken(Token.EMPTY);
		RawData data = serializer.serializeEmptyMessage(ack, null);

		assertThat(data.getEndpointContext(), is(equalTo(ENDPOINT_CONTEXT)));

		if (serializer instanceof TcpDataSerializer) {
			assertThat(data.getBytes(), is(StringUtil.hex2ByteArray("0000")));
		} else {
			assertThat(data.getBytes(), is(StringUtil.hex2ByteArray("60000001")));
		}
	}

	/**
	 * Verifies that the serializeRequest() method creates bare empty messages
	 * with 4 bytes only!
	 */
	@Test
	public void testSerializeEmptyRequest() {

		// GIVEN a empty CoAP request
		Request request = new Request(null, Type.CON);
		request.setToken(Token.EMPTY);
		request.setMID(1);
		request.setURI("coap://localhost/test");

		// WHEN serializing the request to a RawData object
		RawData raw = serializer.serializeRequest(request);

		// THEN the serialized byte array is stored in the request's bytes
		// property
		assertNotNull(raw);
		assertNotNull(raw.getBytes());
		if (serializer instanceof TcpDataSerializer) {
			assertThat(raw.getBytes(), is(StringUtil.hex2ByteArray("0000")));
		} else {
			assertThat(raw.getBytes(), is(StringUtil.hex2ByteArray("40000001")));
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void testSerializeEmptyNonRequestFails() {
		// GIVEN a empty CoAP request
		Request request = new Request(null, Type.NON);
		request.setToken(Token.EMPTY);
		request.setMID(1);
		request.setURI("coap://localhost/test");

		// WHEN serializing the request to a RawData object
		serializer.serializeRequest(request);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testSerializeEmptyRequestWithTokenFails() {
		// GIVEN a empty CoAP request
		Request request = new Request(null, Type.CON);
		request.setToken(new byte[] { 1 });
		request.setMID(1);
		request.setURI("coap://localhost/test");

		// WHEN serializing the request to a RawData object
		serializer.serializeRequest(request);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testSerializeEmptyRequestWithPayloadFails() {

		// GIVEN a empty CoAP request
		Request request = new Request(null, Type.CON);
		request.setToken(Token.EMPTY);
		request.setMID(1);
		request.setPayload("test");
		request.setURI("coap://localhost/test");

		// WHEN serializing the request to a RawData object
		serializer.serializeRequest(request);
	}

	private static void assertStarts(byte[] actual, byte[] data) {
		assertThat(Arrays.copyOf(actual, data.length), is(data));
	}
}
