/*******************************************************************************
 * Copyright (c) 2015, 2018 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation (465073)
 *    Bosch Software Innovations GmbH - add test case for GitHub issue #1
 *    Achim Kraus (Bosch Software Innovations GmbH) - dummy for setCorrelationContextMatcher
 *                                                    (fix GitHub issue #104)
 *    Achim Kraus (Bosch Software Innovations GmbH) - initialize latch always.
 *                                                    adjust MessageCallback test to
 *                                                    testSendRequestCallsMessageCallbackOnSent
 *                                                    issue #305
 ******************************************************************************/
package org.eclipse.californium.core.network;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.core.test.CountingMessageObserver;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class CoapEndpointTest {

	static final NetworkConfig CONFIG = NetworkConfig.createStandardWithoutFile();
	static final int MESSAGE_ID = 4711;
	static final byte[] TOKEN = new byte[] { 0x01, 0x02, 0x03 };
	static final InetSocketAddress SOURCE_ADDRESS = new InetSocketAddress(InetAddress.getLoopbackAddress(), 12000);
	static final InetSocketAddress CONNECTOR_ADDRESS = new InetSocketAddress(InetAddress.getLoopbackAddress(), 13000);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	CoapEndpoint endpoint;
	SimpleConnector connector;
	List<Request> receivedRequests;
	CountDownLatch latch;
	CountDownLatch connectorSentLatch;
	EndpointContext establishedContext;

	@Before
	public void setUp() throws Exception {
		establishedContext = new AddressEndpointContext(CONNECTOR_ADDRESS, null);
		receivedRequests = new ArrayList<Request>();
		connector = new SimpleConnector();
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setConnector(connector);
		builder.setNetworkConfig(CONFIG);

		endpoint = builder.build();
		connectorSentLatch = new CountDownLatch(1);
		latch = new CountDownLatch(1);
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
		endpoint.destroy();
	}

	@Test
	public void testGetUriReturnsConnectorUri() throws URISyntaxException {
		URI uri = new URI(TestTools.getUri(connector.getAddress().getAddress(), connector.getAddress().getPort(), null));
		assertThat(endpoint.getUri(), is(uri));
	}

	@Test
	public void testSendRequestCallsMessageCallbackOnSent() throws Exception {

		// GIVEN an outbound request
		Request request = Request.newGet();
		request.setDestinationContext(new AddressEndpointContext(InetAddress.getLoopbackAddress(), CoAP.DEFAULT_COAP_PORT));
		CountingMessageObserver observer = new CountingMessageObserver();
		request.addMessageObserver(observer);

		// WHEN sending the request to the peer
		endpoint.sendRequest(request);

		// THEN assert that the message delivered to the Connector contains a
		// MessageCallback
		assertTrue(observer.waitForSentCalls(1, 1, TimeUnit.SECONDS));
	}

	@Test
	public void testSenderIdentityIsAddedToIncomingRequest() throws Exception {
		Principal clientId = new Principal() {

			@Override
			public String getName() {
				return "Client";
			}
		};

		
		RawData inboundRequest = RawData.inbound(getSerializedRequest(), new AddressEndpointContext(SOURCE_ADDRESS, clientId), false, System.nanoTime());
		connector.receiveMessage(inboundRequest);
		assertTrue(latch.await(2, TimeUnit.SECONDS));
		assertThat(receivedRequests.get(0).getSourceContext().getPeerIdentity(), is(clientId));
	}

	@Test
	public void testStandardSchemeIsSetOnIncomingRequest() throws Exception {
		RawData inboundRequest = RawData.inbound(getSerializedRequest(), new AddressEndpointContext(SOURCE_ADDRESS), false, System.nanoTime());
		connector.receiveMessage(inboundRequest);
		assertTrue(latch.await(2, TimeUnit.SECONDS));
		assertThat(receivedRequests.get(0).getScheme(), is(CoAP.COAP_URI_SCHEME));
	}

	@Test
	public void testSecureSchemeIsSetOnIncomingRequest() throws Exception {
		SimpleConnector connector = new SimpleSecureConnector();
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setConnector(connector);
		builder.setNetworkConfig(CONFIG);
		Endpoint endpoint = builder.build();
		final CountDownLatch latch = new CountDownLatch(1);
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
		cleanup.add(endpoint);
		
		EndpointContext secureCtx = new DtlsEndpointContext(SOURCE_ADDRESS, null, "session", "1", "CIPHER", "100");
		RawData inboundRequest = RawData.inbound(getSerializedRequest(), secureCtx, false, System.nanoTime());
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
		RawData inboundMessage = RawData.inbound(malformedGetRequest, new AddressEndpointContext(SOURCE_ADDRESS), false, System.nanoTime());

		// WHEN the incoming message is processed by the Inbox
		connector.receiveMessage(inboundMessage);

		// THEN an RST message is sent back to the sender and the incoming message is not being delivered
		assertTrue(connectorSentLatch.await(2, TimeUnit.SECONDS));
		assertTrue(receivedRequests.isEmpty());
	}

	private static byte[] getSerializedRequest() {
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
			msg.onContextEstablished(establishedContext);
			msg.onSent();
			connectorSentLatch.countDown();
		}

		@Override
		public void setRawDataReceiver(RawDataChannel messageHandler) {
			receiver = messageHandler;
		}

		@Override
		public synchronized void setEndpointContextMatcher(EndpointContextMatcher strategy) {
		}

		@Override
		public InetSocketAddress getAddress() {
			return CONNECTOR_ADDRESS;
		}

		@Override
		public String getProtocol() {
			return CoAP.PROTOCOL_UDP;
		}

		@Override
		public String toString() {
			return getProtocol() + "-" + getAddress();
		}
	}

	private class SimpleSecureConnector extends SimpleConnector {

		@Override
		public String getProtocol() {
			return CoAP.PROTOCOL_DTLS;
		}
	}
}
