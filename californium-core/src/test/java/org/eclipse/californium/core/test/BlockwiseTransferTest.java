/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - test stop transfer on cancel
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageInterceptor;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * This test tests the blockwise transfer of requests and responses. This test
 * sets the maximum message size and the default block size to 32 bytes and
 * sends messages blockwise. All four combinations with short and long requests
 * and responses are tested.
 */
// Category Medium because shutdown of the CoapServer runs into timeout (after 1 sec)
// because of pending BlockCleanupTask
@Category(Medium.class)
public class BlockwiseTransferTest {

	private static final String SHORT_POST_REQUEST  = "<Short request>";
	private static final String LONG_POST_REQUEST   = "<Long request 1x2x3x4x5x>".replace("x", "ABCDEFGHIJKLMNOPQRSTUVWXYZ ");
	private static final String SHORT_POST_RESPONSE = "<Short response>";
	private static final String LONG_POST_RESPONSE  = "<Long response 1x2x3x4x5x>".replace("x", "ABCDEFGHIJKLMNOPQRSTUVWXYZ ");
	private static final String SHORT_GET_RESPONSE = SHORT_POST_RESPONSE.toLowerCase();
	private static final String LONG_GET_RESPONSE  = LONG_POST_RESPONSE.toLowerCase();

	private static NetworkConfig config;

	private boolean request_short = true;
	private boolean respond_short = true;
	private boolean cancel_request = false;
	
	private CoapServer server;
	private ServerBlockwiseInterceptor interceptor = new ServerBlockwiseInterceptor();
	private int serverPort;
	
	private Endpoint clientEndpoint;

	@BeforeClass
	public static void prepare() {
		config = new NetworkConfig()
			.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 32)
			.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 32);
	}

	@Before
	public void setupServer() throws IOException {
		System.out.println(System.lineSeparator() + "Start " + getClass().getSimpleName());

		server = createSimpleServer();
		clientEndpoint = new CoapEndpoint(config);
		clientEndpoint.start();
	}

	@After
	public void shutdownServer() throws Exception {
		clientEndpoint.destroy();
		server.destroy();
		System.out.println("End " + getClass().getSimpleName());
	}

	@Test
	public void test_all() throws Exception {
		test_POST_short_short();
		test_POST_long_short();
		test_POST_short_long();
		test_POST_long_long();
		// repeat test to check ongoing clean-up
		test_POST_long_long();
		test_GET_short();
		test_GET_long();
		// repeat test to check ongoing clean-up
		test_GET_long();
		test_GET_long_cancel();
	}
	
	public void test_POST_short_short() throws Exception {
		System.out.println("-- POST short short --");
		request_short = true;
		respond_short = true;
		executePOSTRequest();
	}
	
	public void test_POST_long_short() throws Exception {
		System.out.println("-- POST long short --");
		request_short = false;
		respond_short = true;
		executePOSTRequest();
	}
	
	public void test_POST_short_long() throws Exception {
		System.out.println("-- POST short long --");
		request_short = true;
		respond_short = false;
		executePOSTRequest();
	}
	
	public void test_POST_long_long() throws Exception {
		System.out.println("-- POST long long --");
		request_short = false;
		respond_short = false;
		executePOSTRequest();
	}
	
	public void test_GET_short() throws Exception {
		System.out.println("-- GET short --");
		respond_short = true;
		executeGETRequest();
	}
	
	public void test_GET_long() throws Exception {
		System.out.println("-- GET long --");
		respond_short = false;
		executeGETRequest();
	}

	public void test_GET_long_cancel() throws Exception {
		System.out.println("-- GET long, cancel --");
		respond_short = false;
		cancel_request = true;
		executeGETRequest();
	}
	
	private void executeGETRequest() throws Exception {
		String payload = "nothing";
		try {
			interceptor.clear();
			final AtomicInteger counter = new AtomicInteger(0);
			final Request request = Request.newGet();
			request.setDestination(InetAddress.getLoopbackAddress());
			request.setDestinationPort(serverPort);
			interceptor.handler = new ReceiveRequestHandler() {
				@Override
				public void receiveRequest(Request received) {
					counter.getAndIncrement();
					if (cancel_request) {
						request.cancel();
					}
				}
			};
			
			clientEndpoint.sendRequest(request);
			
			// receive response and check
			Response response = request.waitForResponse(2000);

			if (cancel_request) {
				Thread.sleep(1000); // Quickly wait for more blocks (should not happen)
				assertEquals(1, counter.get());
			} else {
				assertNotNull("Client received no response", response);
				payload = response.getPayloadString();
				if (respond_short) assertEquals(SHORT_GET_RESPONSE, payload);
				else assertEquals(LONG_GET_RESPONSE, payload);
			}
		} finally {
			Thread.sleep(100); // Quickly wait until last ACKs arrive
			System.out.println("Client received "+payload
				+ "\n" + interceptor.toString() + "\n");
		}
	}
	
	private void executePOSTRequest() throws Exception {
		String payload = "--no payload--";
		try {
			interceptor.clear();
			String uri = String.format(
					"coap://%s:%d/%s%s",
					InetAddress.getLoopbackAddress().getHostAddress(),
					serverPort,
					request_short,
					respond_short);
			Request request = Request.newPost().setURI(uri);
			if (request_short) request.setPayload(SHORT_POST_REQUEST);
			else request.setPayload(LONG_POST_REQUEST);
			clientEndpoint.sendRequest(request);
			
			// receive response and check
			Response response = request.waitForResponse(2000);
			
			assertNotNull("Client received no response", response);
			payload = response.getPayloadString();
			
			if (respond_short)assertEquals(SHORT_POST_RESPONSE, payload);
			else assertEquals(LONG_POST_RESPONSE, payload);
		} finally {
			Thread.sleep(100); // Quickly wait until last ACKs arrive
			System.out.println("Client received "+payload
				+ "\n" + interceptor.toString() + "\n");
		}
	}

	private CoapServer createSimpleServer() {

		CoapServer result = new CoapServer();

		CoapEndpoint endpoint = new CoapEndpoint(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), config);
		endpoint.addInterceptor(interceptor);
		result.addEndpoint(endpoint);
		result.setMessageDeliverer(new MessageDeliverer() {
			@Override
			public void deliverRequest(Exchange exchange) {
				if (exchange.getRequest().getCode() == Code.GET)
					processGET(exchange);
				else
					processPOST(exchange);
			}

			private void processPOST(Exchange exchange) {
				String payload = exchange.getRequest().getPayloadString();
				if (request_short)assertEquals(payload, SHORT_POST_REQUEST);
				else assertEquals(payload, LONG_POST_REQUEST);
				System.out.println("Server received "+payload);
					
				Response response = new Response(ResponseCode.CHANGED);
				if (respond_short)
					response.setPayload(SHORT_POST_RESPONSE);
				else response.setPayload(LONG_POST_RESPONSE);
				exchange.sendResponse(response);
			}

			private void processGET(Exchange exchange) {
				System.out.println("Server received GET request");
				Response response = new Response(ResponseCode.CONTENT);
				if (respond_short)
					response.setPayload(SHORT_GET_RESPONSE);
				else response.setPayload(LONG_GET_RESPONSE);
				exchange.sendResponse(response);
			}

			@Override
			public void deliverResponse(Exchange exchange, Response response) { }
		});
		result.start();
		serverPort = endpoint.getAddress().getPort();
		System.out.println("serverPort: " + serverPort);
		return result;
	}

	public static class ServerBlockwiseInterceptor implements MessageInterceptor {

		private StringBuilder buffer = new StringBuilder();
		public ReceiveRequestHandler handler;
		
		@Override
		public void sendRequest(Request request) {
			buffer.append("\nERROR: Server sent "+request+"\n");
		}

		@Override
		public void sendResponse(Response response) {
			buffer.append(
					String.format("\n<-----   %s [MID=%d], %s%s%s%s    ",
					response.getType(), response.getMID(), response.getCode(),
					blockOptionString(1, response.getOptions().getBlock1()),
					blockOptionString(2, response.getOptions().getBlock2()),
					observeOptionString(response.getOptions()) ));
		}

		@Override
		public void sendEmptyMessage(EmptyMessage message) {
			buffer.append(
					String.format("\n<-----   %s [MID=%d], 0",
					message.getType(), message.getMID()));
		}

		@Override
		public void receiveRequest(Request request) {
			buffer.append(
					String.format("\n%s [MID=%d], %s, /%s%s%s%s    ----->",
					request.getType(), request.getMID(), request.getCode(),
					request.getOptions().getUriPathString(),
					blockOptionString(1, request.getOptions().getBlock1()),
					blockOptionString(2, request.getOptions().getBlock2()),
					observeOptionString(request.getOptions()) ));
			if (null != handler) handler.receiveRequest(request);
		}

		@Override
		public void receiveResponse(Response response) {
			buffer.append("ERROR: Server received "+response);
		}

		@Override
		public void receiveEmptyMessage(EmptyMessage message) {
			buffer.append(
					String.format("\n%-19s                       ----->",
					String.format("%s [MID=%d], 0",message.getType(), message.getMID())
					));
		}
		
		public void log(String str) {
			buffer.append(str);
		}
		
		private String blockOptionString(int nbr, BlockOption option) {
			if (option == null) return "";
			return String.format(", %d:%d/%d/%d", nbr, option.getNum(),
					option.isM()?1:0, option.getSize());
		}
		
		private String observeOptionString(OptionSet options) {
			if (options == null) return "";
			if (!options.hasObserve()) return "";
			return ", observe("+options.getObserve()+")";
		}
		
		public String toString() {
			return buffer.append("\n").substring(1);
		}
		
		public void clear() {
			buffer = new StringBuilder();
		}
		
	}
	
	public interface ReceiveRequestHandler {
		void receiveRequest(Request received);
	}
}
