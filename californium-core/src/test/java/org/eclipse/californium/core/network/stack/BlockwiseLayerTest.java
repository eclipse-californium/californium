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
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import static org.eclipse.californium.TestTools.generateRandomPayload;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MessageObserver;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;


/**
 * Verifies behavior of the {@code BlockwiseLayer}.
 *
 */
@Category(Small.class)
public class BlockwiseLayerTest {

	/**
	 * Verifies that conversion from block size to szx code works.
	 */
	@Test
	public void testComputeSzxReturnsNextSmallerSize() {
		assertThat(BlockwiseLayer.computeSZX(1600), is(6));
		assertThat(BlockwiseLayer.computeSZX(1024), is(6));
		assertThat(BlockwiseLayer.computeSZX(540), is(5));
		assertThat(BlockwiseLayer.computeSZX(512), is(5));
		assertThat(BlockwiseLayer.computeSZX(400), is(4));
		assertThat(BlockwiseLayer.computeSZX(256), is(4));
		assertThat(BlockwiseLayer.computeSZX(170), is(3));
		assertThat(BlockwiseLayer.computeSZX(128), is(3));
		assertThat(BlockwiseLayer.computeSZX(90), is(2));
		assertThat(BlockwiseLayer.computeSZX(64), is(2));
		assertThat(BlockwiseLayer.computeSZX(33), is(1));
		assertThat(BlockwiseLayer.computeSZX(32), is(1));
		assertThat(BlockwiseLayer.computeSZX(25), is(0));
		assertThat(BlockwiseLayer.computeSZX(16), is(0));
	}

	/**
	 * Verifies that block size < 16 is mapped to szx 0.
	 */
	@Test
	public void testComputeSzxReturnsMinSize() {
		assertThat(BlockwiseLayer.computeSZX(8), is(0));
	}

	/**
	 * Verifies that conversion from szx codes to block size works.
	 */
	@Test
	public void testGetSizeForSzx() {
		assertThat(BlockwiseLayer.getSizeForSzx(-1), is(16));
		assertThat(BlockwiseLayer.getSizeForSzx(0), is(16));
		assertThat(BlockwiseLayer.getSizeForSzx(1), is(32));
		assertThat(BlockwiseLayer.getSizeForSzx(2), is(64));
		assertThat(BlockwiseLayer.getSizeForSzx(3), is(128));
		assertThat(BlockwiseLayer.getSizeForSzx(4), is(256));
		assertThat(BlockwiseLayer.getSizeForSzx(5), is(512));
		assertThat(BlockwiseLayer.getSizeForSzx(6), is(1024));
		assertThat(BlockwiseLayer.getSizeForSzx(8), is(1024));
	}

	/**
	 * Verifies that an inbound blockwise request is forwarded to application layer
	 * if overall transparent blockwise handling is disabled.
	 */
	@Test
	public void testReceiveRequestDelegatesToApplicationLayer() {

		NetworkConfig config = NetworkConfig.createStandardWithoutFile()
				.setInt(Keys.MAX_MESSAGE_SIZE, 128)
				.setInt(Keys.MAX_RESOURCE_BODY_SIZE, 0);
		Layer appLayer = mock(Layer.class);

		BlockwiseLayer blockwiseLayer = new BlockwiseLayer(config);
		blockwiseLayer.setUpperLayer(appLayer);

		Request request = newBlockwiseRequest(256, 64);
		Exchange exchange = new Exchange(request, Origin.REMOTE);

		blockwiseLayer.receiveRequest(exchange, request);

		verify(appLayer).receiveRequest(exchange, request);
	}

	/**
	 * Verifies that an inbound blockwise request is rejected with a 4.13 error response.
	 */
	@Test
	public void testReceiveRequestRejectsExcessiveRequestBody() {

		NetworkConfig config = NetworkConfig.createStandardWithoutFile()
				.setInt(Keys.MAX_MESSAGE_SIZE, 128)
				.setInt(Keys.MAX_RESOURCE_BODY_SIZE, 200);
		Layer outbox = mock(Layer.class);
		ArgumentCaptor<Response> errorResponse = ArgumentCaptor.forClass(Response.class);

		BlockwiseLayer blockwiseLayer = new BlockwiseLayer(config);
		blockwiseLayer.setLowerLayer(outbox);

		Request request = newBlockwiseRequest(256, 64);
		Exchange exchange = new Exchange(request, Origin.REMOTE);

		blockwiseLayer.receiveRequest(exchange, request);

		verify(outbox).sendResponse(Mockito.any(Exchange.class), errorResponse.capture());
		assertThat(errorResponse.getValue().getCode(), is(ResponseCode.REQUEST_ENTITY_TOO_LARGE));
	}

	/**
	 * Verifies that a request for a resource with a body exceeding the max buffer size is
	 * cancelled when the first response block is received.
	 */
	@Test
	public void testReceiveResponseCancelsRequestForExcessiveResponseBody() {

		NetworkConfig config = NetworkConfig.createStandardWithoutFile()
				.setInt(Keys.MAX_MESSAGE_SIZE, 128)
				.setInt(Keys.MAX_RESOURCE_BODY_SIZE, 200);
		MessageObserver requestObserver = mock(MessageObserver.class);
		BlockwiseLayer blockwiseLayer = new BlockwiseLayer(config);

		Request req = Request.newGet();
		req.setURI("coap://127.0.0.1/bigResource");
		req.addMessageObserver(requestObserver);

		Response response = Response.createResponse(req, ResponseCode.CONTENT);
		response.getOptions().setSize2(256).setBlock2(BlockwiseLayer.computeSZX(64), true, 0);

		Exchange exchange = new Exchange(null, Origin.LOCAL);
		exchange.setRequest(req);

		blockwiseLayer.receiveResponse(exchange, response);

		verify(requestObserver).onCancel();
	}

	private static Request newBlockwiseRequest(final int bodySize, final int blockSize) {
		Request request = Request.newPut();
		request.getOptions().setBlock1(BlockwiseLayer.computeSZX(blockSize), true, 0).setSize1(bodySize);
		request.setPayload(generateRandomPayload(blockSize));
		return request;
	}
}
