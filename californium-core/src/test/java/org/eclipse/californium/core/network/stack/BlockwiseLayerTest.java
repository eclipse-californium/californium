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
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import static org.eclipse.californium.TestTools.generateRandomPayload;
import static org.eclipse.californium.core.network.MatcherTestUtils.receiveResponseFor;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.net.InetAddress;

import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MessageObserver;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.MatcherTestUtils;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.Rule;
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
	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

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

		Request request = newReceivedBlockwiseRequest(256, 64);
		Exchange exchange = new Exchange(request, Origin.REMOTE, MatcherTestUtils.TEST_EXCHANGE_EXECUTOR);

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

		Request request = newReceivedBlockwiseRequest(256, 64);
		Exchange exchange = new Exchange(request, Origin.REMOTE, MatcherTestUtils.TEST_EXCHANGE_EXECUTOR);

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

		Response response = receiveResponseFor(req);
		response.getOptions().setSize2(256).setBlock2(BlockOption.size2Szx(64), true, 0);

		Exchange exchange = new Exchange(req, Origin.LOCAL, MatcherTestUtils.TEST_EXCHANGE_EXECUTOR);
		exchange.setRequest(req);
		blockwiseLayer.receiveResponse(exchange, response);

		verify(requestObserver).onCancel();
	}

	/**
	 * Verifies that a notification for a canceled observe relation is rejected.
	 */
	@Test
	public void testReceiveResponseForwardsNotificationForCanceledObservationToUpperLayer() {

		NetworkConfig config = NetworkConfig.createStandardWithoutFile()
				.setInt(Keys.MAX_MESSAGE_SIZE, 128)
				.setInt(Keys.MAX_RESOURCE_BODY_SIZE, 200);
		Layer upperLayer = mock(Layer.class);
		BlockwiseLayer blockwiseLayer = new BlockwiseLayer(config);
		blockwiseLayer.setUpperLayer(upperLayer);

		// GIVEN an established observation of a resource with a body requiring blockwise transfer
		Request req = Request.newGet();
		req.setURI("coap://127.0.0.1/bigResource");
		Exchange exchange = new Exchange(req, Origin.LOCAL, MatcherTestUtils.TEST_EXCHANGE_EXECUTOR);
		exchange.setRequest(req);

		// WHEN the request used to establish the observe relation has been canceled
		// and a notification arrives
		req.cancel();
		Response response = receiveResponseFor(req);
		response.getOptions().setSize2(100).setBlock2(BlockOption.size2Szx(64), true, 0).setObserve(12);
		blockwiseLayer.receiveResponse(exchange, response);

		// THEN the body is not retrieved using a blockwise transfer and the notification
		// is forwarded to the upper layer(s)
		verify(upperLayer).receiveResponse(exchange, response);
	}

	private static Request newReceivedBlockwiseRequest(final int bodySize, final int blockSize) {
		Request request = Request.newPut();
		request.getOptions().setBlock1(BlockOption.size2Szx(blockSize), true, 0).setSize1(bodySize);
		request.setPayload(generateRandomPayload(blockSize));
		request.setSourceContext(new AddressEndpointContext(InetAddress.getLoopbackAddress(), CoAP.DEFAULT_COAP_PORT));
		return request;
	}
}
