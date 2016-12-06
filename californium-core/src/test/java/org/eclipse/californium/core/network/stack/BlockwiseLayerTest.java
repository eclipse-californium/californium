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
import org.eclipse.californium.core.coap.BlockOption;
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
		response.getOptions().setSize2(256).setBlock2(BlockOption.size2Szx(64), true, 0);

		Exchange exchange = new Exchange(null, Origin.LOCAL);
		exchange.setRequest(req);

		blockwiseLayer.receiveResponse(exchange, response);

		verify(requestObserver).onCancel();
	}

	private static Request newBlockwiseRequest(final int bodySize, final int blockSize) {
		Request request = Request.newPut();
		request.getOptions().setBlock1(BlockOption.size2Szx(blockSize), true, 0).setSize1(bodySize);
		request.setPayload(generateRandomPayload(blockSize));
		return request;
	}
}
