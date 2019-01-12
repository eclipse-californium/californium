/*******************************************************************************
 * Copyright (c) 2019 Rogier Cobben.
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
 *    Rogier Cobben - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.net.InetSocketAddress;
import java.util.Arrays;

import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

/**
 * Test correct handling of request payloads.
 */
@RunWith(Parameterized.class)
@Category(Medium.class)
public class RequestPayloadTest {

	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);
	@Rule
	public ExpectedException exception = ExpectedException.none();

	/**
	 * Service resource name.
	 */
	private static final String TARGET = "return_payload_length";

	/**
	 * Small test payload size.
	 */
	private static final int SMALL_CONTENT_SIZE = 10;

	/**
	 * Large test payload size.
	 */
	private static final int LARGE_CONTENT_SIZE = 8192;

	/**
	 * @return List of test payload sizes.
	 */
	@Parameters(name = "bodySize = {0}")
	public static Iterable<Integer> bodySizeParams() {
		return Arrays.asList(SMALL_CONTENT_SIZE, LARGE_CONTENT_SIZE);
	}

	/**
	 * Actual size of request payload to test.
	 */
	@Parameter
	public int bodySize;

	/**
	 * Test server.
	 */
	private static CoapServer server = null;
	/**
	 * Test client.
	 */
	private CoapClient client = null;

	/**
	 * Start server
	 */
	@BeforeClass
	public static void setupServer() {
		System.out.println(System.lineSeparator() + "Start " + RequestPayloadTest.class.getName());
		server = new CoapServer();
		server.add(new PayloadLengthResource(TARGET));
		server.start();
	}

	/**
	 * Stop server.
	 */
	@AfterClass
	public static void tearDownServer() {
		if (server != null) {
			server.stop();
			server.destroy();
			server = null;
		}
	}

	/**
	 * Create client.
	 */
	@Before
	public void setupClient() {

		client = new CoapClient("coap://127.0.0.1/" + TARGET);
		client.setTimeout(1000L);
	}

	/**
	 * Destroy client.
	 */
	@After
	public void tearDownClient() {
		if (client != null) {
			client.shutdown();
			client = null;
		}
	}

	/**
	 * Run test using given payload and assert returned responsecode and payload
	 * length.
	 * 
	 * @param code is the request code to use
	 * @param payload to use in the request
	 * @param expect is the expected response code
	 */
	public void runTestCase(Code code, byte[] payload, ResponseCode expect, boolean forceUnintendedPayload) {
		Request request = new Request(code);
		if (forceUnintendedPayload)
			request.setUnintendedPayload();
		request.setPayload(payload);

		CoapResponse response = client.advanced(request);

		assertNotNull("no response from server: ", response);
		assertEquals("wrong responsecode: ", expect, response.getCode());
		assertEquals("wrong content length returned: ", payload.length, Integer.parseInt(response.getResponseText()));
	}

	/**
	 * Test get with payload.
	 */
	@Test
	public void testGetWithPayload() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("Message must not have payload!");
		runTestCase(Code.GET, getContent(), ResponseCode.CONTENT, false);
	}

	/**
	 * test get with uninteded payload forced
	 */
	@Test
	public void testGetWithForcedPayload() {
		runTestCase(Code.GET, getContent(), ResponseCode.CONTENT, true);
	}

	/**
	 * test post with payload
	 */
	@Test
	public void testPostWithPayload() {
		runTestCase(Code.POST, getContent(), ResponseCode.CREATED, false);
	}

	/**
	 * Test put with payload.
	 */
	@Test
	public void testPutWithPayload() {
		runTestCase(Code.PUT, getContent(), ResponseCode.CHANGED, false);
	}

	/**
	 * Test delete with payload.
	 */
	@Test
	public void testDeleteWithPayload() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("Message must not have payload!");
		runTestCase(Code.DELETE, getContent(), ResponseCode.DELETED, false);
	}

	/**
	 * test delete with uninteded payload forced
	 */
	@Test
	public void testDeleteWithForcedPayload() {
		runTestCase(Code.DELETE, getContent(), ResponseCode.DELETED, true);
	}

	/**
	 * Test fetch with payload.
	 */
	@Test
	public void testFetchWithPayload() {
		runTestCase(Code.FETCH, getContent(), ResponseCode.CONTENT, false);
	}

	/**
	 * test patch with payload
	 */
	@Test
	public void testPatchWithPayload() {
		runTestCase(Code.PATCH, getContent(), ResponseCode.CHANGED, false);
	}

	/**
	 * Create test content.
	 * 
	 * @return the test content
	 */
	public byte[] getContent() {
		byte[] content = new byte[bodySize];
		for (int i = 0; i < bodySize; i++) {
			content[i] = (byte) (i % (Byte.MAX_VALUE + 1));
		}
		return content;
	}

	/**
	 * Service resource.
	 *
	 */
	public static class PayloadLengthResource extends CoapResource {

		/**
		 * Constuctor.
		 * 
		 * @param name of the resource
		 */
		public PayloadLengthResource(String name) {
			super(name);
		}

		/**
		 * Validate test content.
		 * 
		 * @param content
		 * @return true when content is as expected, otherwise false
		 */
		private boolean validateContent(byte[] content) {
			for (int i = 0; i < content.length; i++) {
				if (content[i] != (byte) (i % (Byte.MAX_VALUE + 1))) {
					return false;
				}
			}
			return true;
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			byte[] requestPayload = exchange.getRequestPayload();
			if (validateContent(requestPayload)) {
				exchange.respond(ResponseCode.CONTENT, Integer.toString(requestPayload.length));
			} else {
				exchange.respond(ResponseCode.BAD_REQUEST);
			}
		}

		@Override
		public void handlePOST(CoapExchange exchange) {
			byte[] requestPayload = exchange.getRequestPayload();
			if (validateContent(requestPayload)) {
				exchange.respond(ResponseCode.CREATED, Integer.toString(requestPayload.length));
			} else {
				exchange.respond(ResponseCode.BAD_REQUEST);
			}
		}

		@Override
		public void handlePUT(CoapExchange exchange) {
			byte[] requestPayload = exchange.getRequestPayload();
			if (validateContent(requestPayload)) {
				exchange.respond(ResponseCode.CHANGED, Integer.toString(requestPayload.length));
			} else {
				exchange.respond(ResponseCode.BAD_REQUEST);
			}
		}

		@Override
		public void handleDELETE(CoapExchange exchange) {
			byte[] requestPayload = exchange.getRequestPayload();
			if (validateContent(requestPayload)) {
				exchange.respond(ResponseCode.DELETED, Integer.toString(requestPayload.length));
			} else {
				exchange.respond(ResponseCode.BAD_REQUEST);
			}
		}

		@Override
		public void handleFETCH(CoapExchange exchange) {
			byte[] requestPayload = exchange.getRequestPayload();
			if (validateContent(requestPayload)) {
				exchange.respond(ResponseCode.CONTENT, Integer.toString(requestPayload.length));
			} else {
				exchange.respond(ResponseCode.BAD_REQUEST);
			}
		}

		@Override
		public void handlePATCH(CoapExchange exchange) {
			byte[] requestPayload = exchange.getRequestPayload();
			if (validateContent(requestPayload)) {
				exchange.respond(ResponseCode.CHANGED, Integer.toString(requestPayload.length));
			} else {
				exchange.respond(ResponseCode.BAD_REQUEST);
			}
		}
	}
}
