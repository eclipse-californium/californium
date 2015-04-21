/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 ******************************************************************************/
package org.eclipse.californium.core.network;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.serialization.DataSerializer;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class CoAPEndpointTest {

	CoAPEndpoint endpoint;
	SimpleConnector connector;
	DataSerializer serializer;
	
	@Before
	public void setUp() throws Exception {
		connector = new SimpleConnector();
		endpoint = new CoAPEndpoint(connector, NetworkConfig.getStandard());
		serializer = new DataSerializer();
	}

	@After
	public void shutDownEndpoint() {
		endpoint.stop();
	}
	
	@Test
	public void testSenderIdentityIsAddedToRequest() throws Exception {
		final String clientId = "Client";
		final CountDownLatch latch = new CountDownLatch(1);
		final List<Request> receivedRequests = new ArrayList<Request>();
		
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
		RawData msg = new RawData(getSerializedRequest(),
				new InetSocketAddress(CoAP.DEFAULT_COAP_PORT),
				new Principal() {
					
					@Override
					public String getName() {
						return clientId;
					}
		});
		connector.receiveMessage(msg);
		assertTrue(latch.await(2, TimeUnit.SECONDS));
		assertThat(receivedRequests.get(0).getSenderIdentity().getName(), is(clientId));
	}

	private byte[] getSerializedRequest() {
		Request request = new Request(Code.POST, Type.NON);
		request.setPayload("Hello World");
		request.setToken(new byte[]{0x01});
		return serializer.serializeRequest(request);
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
		}

		@Override
		public void setRawDataReceiver(RawDataChannel messageHandler) {
			receiver = messageHandler;
		}

		@Override
		public InetSocketAddress getAddress() {
			return null;
		}
	}
}
