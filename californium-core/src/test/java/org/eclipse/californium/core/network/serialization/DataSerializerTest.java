/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add tests for CorrelationContext
 *                                                    (fix GitHub issue #104)
 *    Achim Kraus (Bosch Software Innovations GmbH) - add null callback
 *                                                    for response and empty message
 *                                                    issue #305
 ******************************************************************************/
package org.eclipse.californium.core.network.serialization;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.RawData;
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

	private static final EndpointContext ENDPOINT_CONTEXT = new DtlsEndpointContext(new InetSocketAddress(0), null, "session", "1", "CIPHER", "100");

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
	 * Verifies that the getByteArray() method does not set the Message's <em>bytes</em> property.
	 */
	@Test
	public void testGetByteArrayDoesNotAlterMessage() {

		// GIVEN a CoAP request
		Request req = Request.newGet();
		req.setToken(new byte[] { 0x00 });
		req.getOptions().setObserve(0);

		// WHEN serializing the request to a byte array
		serializer.getByteArray(req);

		// THEN the serialized byte array is not written to the request's bytes property
		assertNull(req.getBytes());
	}

	/**
	 * Verifies that the serializeRequest() method sets the Message's <em>bytes</em> property.
	 */
	@Test
	public void testSerializeRequestStoresBytesInMessage() {

		// GIVEN a CoAP request
		Request req = Request.newGet();
		req.setToken(new byte[] { 0x00 });
		req.getOptions().setObserve(0);
		req.setDestinationContext(new AddressEndpointContext(InetAddress.getLoopbackAddress(), CoAP.DEFAULT_COAP_PORT));

		// WHEN serializing the request to a RawData object
		RawData raw = serializer.serializeRequest(req);

		// THEN the serialized byte array is stored in the request's bytes property
		assertNotNull(req.getBytes());
		assertThat(raw.getBytes(), is(req.getBytes()));
		assertThat(raw.getEndpointContext(), is(req.getDestinationContext()));
	}

	/**
	 * Verifies that the serializeResponse() method sets the Message's
	 * <em>endpointContext</em>.
	 */
	@Test
	public void testSerializeResponseWithEndpointContext() {
		Request request = Request.newGet();
		request.setSourceContext(ENDPOINT_CONTEXT);
		request.setToken(new byte[] { 0x00 });
		request.setMID(1);
		Response response = Response.createResponse(request, ResponseCode.CONTENT);
		response.setType(Type.ACK);
		response.setMID(request.getMID());
		response.setToken(request.getToken());
		RawData data = serializer.serializeResponse(response, null);

		assertThat(data.getEndpointContext(), is(equalTo(ENDPOINT_CONTEXT)));
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
	}

	/**
	 * Verifies that the serializeRequest() method creates bare empty messages with 4 bytes only!
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

		// THEN the serialized byte array is stored in the request's bytes property
		assertNotNull(raw);
		assertNotNull(raw.getBytes());
		assertThat(raw.getSize(), either(is(4)).or(is(2)));
	}

	@Test (expected = IllegalArgumentException.class)
	public void testSerializeEmptyNonRequestFails() {
		// GIVEN a empty CoAP request
		Request request = new Request(null, Type.NON);
		request.setToken(Token.EMPTY);
		request.setMID(1);
		request.setURI("coap://localhost/test");

		// WHEN serializing the request to a RawData object
		serializer.serializeRequest(request);
	}

	@Test (expected = IllegalArgumentException.class)
	public void testSerializeEmptyRequestWithTokenFails() {
		// GIVEN a empty CoAP request
		Request request = new Request(null, Type.CON);
		request.setToken(new byte[]{1});
		request.setMID(1);
		request.setURI("coap://localhost/test");

		// WHEN serializing the request to a RawData object
		serializer.serializeRequest(request);
	}

	@Test (expected = IllegalArgumentException.class)
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

}
