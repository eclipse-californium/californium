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

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.elements.CorrelationContext;
import org.eclipse.californium.elements.DtlsCorrelationContext;
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
		return new DataSerializer[]{new UdpDataSerializer(), new TcpDataSerializer()};
	}

	/**
	 * Verifies that the getByteArray() method does not set the Message's <em>bytes</em> property.
	 */
	@Test
	public void testGetByteArrayDoesNotAlterMessage() {

		// GIVEN a CoAP request
		Request req = Request.newGet();
		req.setToken(new byte[]{0x00});
		req.getOptions().setObserve(0);
		req.setDestination(InetAddress.getLoopbackAddress());

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
		req.setToken(new byte[]{0x00});
		req.getOptions().setObserve(0);
		req.setDestination(InetAddress.getLoopbackAddress());

		// WHEN serializing the request to a RawData object
		RawData raw = serializer.serializeRequest(req);

		// THEN the serialized byte array is stored in the request's bytes property
		assertNotNull(req.getBytes());
		assertThat(raw.getBytes(), is(req.getBytes()));
	}

	/**
	 * Verifies that the serializeResponse() method sets the Message's
	 * <em>correlationContext</em>.
	 */
	@Test
	public void testSerializeResponseWithCorrelationContext() {
		CorrelationContext context = new DtlsCorrelationContext("session", "1", "CIPHER");
		Request request = Request.newGet();
		request.setToken(new byte[] { 0x00 });
		request.setMID(1);
		Response response = Response.createResponse(request, ResponseCode.CONTENT);
		response.setType(Type.ACK);
		response.setMID(request.getMID());
		response.setToken(request.getToken());
		RawData data = serializer.serializeResponse(response, context, null);

		assertThat(data.getCorrelationContext(), is(equalTo(context)));
	}

	/**
	 * Verifies that the serializeEmptyMessage() method sets the Message's
	 * <em>correlationContext</em>.
	 */
	@Test
	public void testSerializeEmptyMessageWithCorrelationContext() {
		CorrelationContext context = new DtlsCorrelationContext("session", "1", "CIPHER");
		Request request = Request.newGet();
		request.setMID(1);

		EmptyMessage ack = EmptyMessage.newACK(request);
		ack.setToken(new byte[0]);
		RawData data = serializer.serializeEmptyMessage(ack, context, null);

		assertThat(data.getCorrelationContext(), is(equalTo(context)));
	}
}
