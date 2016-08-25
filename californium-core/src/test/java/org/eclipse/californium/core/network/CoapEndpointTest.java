/*******************************************************************************
 * Copyright (c) 2015, 2016 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation (465073)
 *    Bosch Software Innovations GmbH - add test case for GitHub issue #1
 ******************************************************************************/
package org.eclipse.californium.core.network;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.CorrelationContext;
import org.eclipse.californium.elements.DtlsCorrelationContext;
import org.eclipse.californium.elements.MapBasedCorrelationContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class CoapEndpointTest {

	static final NetworkConfig CONFIG = NetworkConfig.createStandardWithoutFile();
	static final int MESSAGE_ID = 4711;
	static final byte[] TOKEN = new byte[] { 0x01, 0x02, 0x03 };
	static final InetSocketAddress SOURCE_ADDRESS = new InetSocketAddress(InetAddress.getLoopbackAddress(), 12000);
	CoapEndpoint endpoint;
	SimpleConnector connector;
	List<Request> receivedRequests;
	CountDownLatch latch;
	CountDownLatch sentLatch;
	CorrelationContext context;

	@Before
	public void setUp() throws Exception {
		context = new MapBasedCorrelationContext();
		receivedRequests = new ArrayList<Request>();
		connector = new SimpleConnector();
		endpoint = new CoapEndpoint(connector, CONFIG);
		sentLatch = new CountDownLatch(1);
		MessageDeliverer deliverer = new MessageDeliverer() {

			@Override
			public void deliverResponse(Exchange exchange, Response response) {
			}

			@Override
			public void deliverRequest(Exchange exchange) {
				receivedRequests.add(exchange.getRequest());
				latch.countDown();
			}
		};

		endpoint.setMessageDeliverer(deliverer);
		endpoint.start();
	}

	@After
	public void shutDownEndpoint() {
		endpoint.stop();
	}

	@Test
	public void testSendRequestAddsMessageCallbackToOutboundMessage() throws Exception {

		// GIVEN an outbound request
		latch = new CountDownLatch(1);
		Request request = Request.newGet();
		request.setDestination(InetAddress.getLoopbackAddress());
		request.setDestinationPort(CoAP.DEFAULT_COAP_PORT);

		// WHEN sending the request to the peer
		endpoint.sendRequest(request);

		// THEN assert that the message delivered to the Connector contains a
		// MessageCallback
		assertTrue(latch.await(1, TimeUnit.SECONDS));
	}

	@Test
	public void testSenderIdentityIsAddedToIncomingRequest() throws Exception {
		Principal clientId = new Principal() {

			@Override
			public String getName() {
				return "Client";
			}
		};
		latch = new CountDownLatch(1);

		RawData inboundRequest = new RawData(getSerializedRequest(), new InetSocketAddress(CoAP.DEFAULT_COAP_PORT),
				clientId);
		connector.receiveMessage(inboundRequest);
		assertTrue(latch.await(2, TimeUnit.SECONDS));
		assertThat(receivedRequests.get(0).getSenderIdentity(), is(clientId));
	}

	@Test
	public void testStandardSchemeIsSetOnIncomingRequest() throws Exception {
		latch = new CountDownLatch(1);

		RawData inboundRequest = RawData.inbound(getSerializedRequest(), SOURCE_ADDRESS, null, null, false);
		connector.receiveMessage(inboundRequest);
		assertTrue(latch.await(2, TimeUnit.SECONDS));
		assertThat(receivedRequests.get(0).getScheme(), is(CoAP.COAP_URI_SCHEME));
	}

	@Test
	public void testSecureSchemeIsSetOnIncomingRequest() throws Exception {
		latch = new CountDownLatch(1);
		CorrelationContext secureCtx = new DtlsCorrelationContext("session", "1", "CIPHER");
		RawData inboundRequest = RawData.inbound(getSerializedRequest(), SOURCE_ADDRESS, null, secureCtx, false);
		connector.receiveMessage(inboundRequest);
		assertTrue(latch.await(2, TimeUnit.SECONDS));
		assertThat(receivedRequests.get(0).getScheme(), is(CoAP.COAP_SECURE_URI_SCHEME));
	}

	@Test
	public void testInboxImplRejectsMalformedRequest() throws Exception {

		// GIVEN a request with missing payload
		byte[] malformedGetRequest = new byte[] { 0b01000000, // ver 1, CON, token length: 0
				0b00000001, // code: 0.01 (GET request)
				0x00, 0x10, // message ID
				(byte) 0xFF // payload marker
		};
		RawData inboundMessage = RawData.inbound(malformedGetRequest, SOURCE_ADDRESS, null, null, false);

		// WHEN the incoming message is processed by the Inbox
		connector.receiveMessage(inboundMessage);

		// THEN an RST message is sent back to the sender and the incoming message is not being delivered
		assertTrue(sentLatch.await(2, TimeUnit.SECONDS));
		assertTrue(receivedRequests.isEmpty());
	}

	private byte[] getSerializedRequest() {
		return new byte[] { 0b01000011, // ver 1, CON, token length: 3
				0b00000001, // code: 0.01 (GET request)
				0x00, 0x10, // message ID
				0x01, 0x02, 0x03 // three byte token
		};
	}

	private class SimpleConnector implements Connector {

		RawDataChannel receiver;

		public SimpleConnector() {
		}

		public void receiveMessage(RawData message) {
			if (receiver != null) {
				receiver.receiveData(message);
			}
		}

		@Override
		public void start() throws IOException {
		}

		@Override
		public void stop() {
		}

		@Override
		public void destroy() {
		}

		@Override
		public void send(RawData msg) {
			if (msg.getMessageCallback() != null) {
				msg.getMessageCallback().onContextEstablished(context);
				latch.countDown();
			}
			sentLatch.countDown();
		}

		@Override
		public void setRawDataReceiver(RawDataChannel messageHandler) {
			receiver = messageHandler;
		}

		@Override
		public InetSocketAddress getAddress() {
			return new InetSocketAddress(0);
		}
	}
}
