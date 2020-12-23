/*******************************************************************************
 * Copyright (c) 2019 Rogier Cobben.
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
 *    Rogier Cobben - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.util.Arrays;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.ExpectedExceptionWrapper;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.After;
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

	@ClassRule
	public static CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	@Rule
	public ExpectedException exception = ExpectedExceptionWrapper.none();

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
	 * Test client.
	 */
	private CoapClient client = null;

	/**
	 * Start server
	 */
	@BeforeClass
	public static void setupServer() {
		CoapServer server = new CoapServer(network.getStandardTestConfig());
		cleanup.add(server);
		server.add(new PayloadLengthResource(TARGET));
		server.start();
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
	public void runTestCase(Code code, byte[] payload, ResponseCode expect, boolean forceUnintendedPayload) throws ConnectorException, IOException {
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
	public void testGetWithPayload() throws ConnectorException, IOException {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("Message must not have payload!");
		runTestCase(Code.GET, getContent(), ResponseCode.CONTENT, false);
	}

	/**
	 * test get with uninteded payload forced
	 */
	@Test
	public void testGetWithForcedPayload() throws ConnectorException, IOException {
		runTestCase(Code.GET, getContent(), ResponseCode.CONTENT, true);
	}

	/**
	 * test post with payload
	 */
	@Test
	public void testPostWithPayload() throws ConnectorException, IOException {
		runTestCase(Code.POST, getContent(), ResponseCode.CREATED, false);
	}

	/**
	 * Test put with payload.
	 */
	@Test
	public void testPutWithPayload() throws ConnectorException, IOException {
		runTestCase(Code.PUT, getContent(), ResponseCode.CHANGED, false);
	}

	/**
	 * Test delete with payload.
	 */
	@Test
	public void testDeleteWithPayload() throws ConnectorException, IOException {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("Message must not have payload!");
		runTestCase(Code.DELETE, getContent(), ResponseCode.DELETED, false);
	}

	/**
	 * test delete with uninteded payload forced
	 */
	@Test
	public void testDeleteWithForcedPayload() throws ConnectorException, IOException {
		runTestCase(Code.DELETE, getContent(), ResponseCode.DELETED, true);
	}

	/**
	 * Test fetch with payload.
	 */
	@Test
	public void testFetchWithPayload() throws ConnectorException, IOException {
		runTestCase(Code.FETCH, getContent(), ResponseCode.CONTENT, false);
	}

	/**
	 * test patch with payload
	 */
	@Test
	public void testPatchWithPayload() throws ConnectorException, IOException {
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
