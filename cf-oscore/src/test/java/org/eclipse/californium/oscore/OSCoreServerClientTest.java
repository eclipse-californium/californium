/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 * This test class is based on org.eclipse.californium.core.test.SmallServerClientTest
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CoapNetworkRule for
 *                                                    setup of test-network
 *    Achim Kraus (Bosch Software Innovations GmbH) - destroy server after test
 *    Rikard Höglund (RISE SICS) - testing using OSCORE
 ******************************************************************************/
package org.eclipse.californium.oscore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * Tests working OSCORE confirmable request and response.
 * Also tests OSCORE functionality when the server replies with a non-OSCORE CoAP error message.
 * 
 */
@Category(Medium.class)
public class OSCoreServerClientTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	private static String SERVER_RESPONSE = "server responds hi";

	private CoapServer server;

	private Endpoint serverEndpoint;

	//OSCORE context information shared between server and client
	private final static HashMapCtxDB dbServer = new HashMapCtxDB();
	private final static HashMapCtxDB dbClient = new HashMapCtxDB();
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] context_id = { 0x74, 0x65, 0x73, 0x74, 0x74, 0x65, 0x73, 0x74 };
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	@Before
	public void initLogger() {
		System.out.println(System.lineSeparator() + "Start " + getClass().getSimpleName());
		EndpointManager.clear();
	}
	
	//Use the OSCORE stack factory
	@BeforeClass
	public static void setStackFactory() {
		OSCoreCoapStackFactory.useAsDefault(dbClient);
	}

	@After
	public void after() {
		if (null != server) {
			server.destroy();
		}
		System.out.println("End " + getClass().getSimpleName());
	}

	/**
	 * Tests working OSCORE confirmable request and response.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testConfirmable() throws Exception {	
		createSimpleServer();

		//Set up OSCORE context information for request (client)
		byte[] sid = new byte[0];
		byte[] rid = new byte[] { 0x01 };
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, context_id, MAX_UNFRAGMENTED_SIZE);
		dbClient.addContext(TestTools.getUri(serverEndpoint, ""), ctx);

		// send request
		Request request = new Request(CoAP.Code.POST);
		request.getOptions().setOscore(new byte[0]); //Use OSCORE
		int requestMID = 10000;
		request.setMID(requestMID);
		request.setConfirmable(true);
		request.setDestinationContext(new AddressEndpointContext(serverEndpoint.getAddress()));
		request.setPayload("client says hi");
		request.send();
		System.out.println("client sent request");

		// receive response and check
		Response response = request.waitForResponse(1000);
		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals(response.getPayloadString(), SERVER_RESPONSE);
		assertEquals(response.getMID(), requestMID); //Response MID matches Request MID
	}

	/**
	 * Tests OSCORE functionality when the server replies with a non-OSCORE CoAP
	 * error message. In this test the client Sender ID is modified to be
	 * incorrect. The server will reply with an error message with a payload
	 * describing the error.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testErrorResponse() throws Exception {	
		createSimpleServer();

		//Set up OSCORE context information for request (client)
		byte[] sid = new byte[] { 0x77 }; //Modified sender ID to be incorrect
		byte[] rid = new byte[] { 0x01 };
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, context_id, MAX_UNFRAGMENTED_SIZE);
		dbClient.addContext(TestTools.getUri(serverEndpoint, ""), ctx);
		
		// send request
		Request request = new Request(CoAP.Code.POST);
		request.getOptions().setOscore(new byte[0]); //Use OSCORE
		int requestMID = 10000;
		request.setMID(requestMID);
		request.setConfirmable(true);
		request.setDestinationContext(new AddressEndpointContext(serverEndpoint.getAddress()));
		request.setPayload("client says hi");
		request.send();
		System.out.println("client sent request");

		// receive response and check
		Response response = request.waitForResponse(1000);
		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals(response.getOptions().getOscore(), null); //Response is not OSCORE protected
		assertEquals(response.getCode(), ResponseCode.UNAUTHORIZED); //Response error code
		assertEquals(response.getPayloadString(), ErrorDescriptions.CONTEXT_NOT_FOUND); //Response error payload
		assertEquals(response.getMID(), requestMID); //Response MID matches Request MID
	}
	
	/**
	 * Tests OSCORE functionality when the server cannot find the correct
	 * context due to the ID Context not being included in the request (since
	 * many contexts match that RID). The server replies with a non-OSCORE CoAP
	 * error message. The server will reply with an error message with a payload
	 * describing the error.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testIncludeContextIDResponse() throws Exception {	
		createSimpleServer();

		// Add one more context to the server context DB with duplicate RID.
		// But different ID Context.
		byte[] sid = new byte[] { 0x01 };
		byte[] rid = new byte[0];
		OSCoreCtx serverCtxDup = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, Bytes.EMPTY, MAX_UNFRAGMENTED_SIZE);
		dbServer.addContext(serverCtxDup);

		//Set up OSCORE context information for request (client)
		sid = Bytes.EMPTY;
		rid = new byte[] { 0x01 };
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, context_id, MAX_UNFRAGMENTED_SIZE);
		dbClient.addContext(TestTools.getUri(serverEndpoint, ""), ctx);
		
		// send request
		Request request = new Request(CoAP.Code.POST);
		request.getOptions().setOscore(new byte[0]); //Use OSCORE
		int requestMID = 10000;
		request.setMID(requestMID);
		request.setConfirmable(true);
		request.setDestinationContext(new AddressEndpointContext(serverEndpoint.getAddress()));
		request.setPayload("client says hi");
		request.send();
		System.out.println("client sent request");

		// receive response and check (expect specific error message)
		Response response = request.waitForResponse(1000);
		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals(ErrorDescriptions.CONTEXT_NOT_FOUND_IDCONTEXT, response.getPayloadString());
		assertEquals(response.getMID(), requestMID); //Response MID matches Request MID
		assertNull(response.getOptions().getOscore()); // No OSCORE
		
		// Now resend with ID Context included
		ctx.setIncludeContextId(true);
		request = new Request(CoAP.Code.POST);
		request.getOptions().setOscore(new byte[0]); //Use OSCORE
		requestMID = 10001;
		request.setMID(requestMID);
		request.setConfirmable(true);
		request.setDestinationContext(new AddressEndpointContext(serverEndpoint.getAddress()));
		request.setPayload("client says hi");
		request.send();
		System.out.println("client sent request");

		// receive response and check (server should respond correctly)
		response = request.waitForResponse(1000);
		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals(SERVER_RESPONSE, response.getPayloadString());
		assertEquals(response.getMID(), requestMID); //Response MID matches Request MID
		assertNotNull(response.getOptions().getOscore()); // OSCORE
		ctx.setIncludeContextId(false);
		dbServer.removeContext(serverCtxDup);
		
	}
	
	/**
	 * Build a simple OSCORE request.
	 * 
	 * @return the request
	 */
	private Request buildOscoreRequest(CoAP.Code code) {
		Request request = new Request(code);
		request.getOptions().setOscore(new byte[0]); // Use OSCORE
		request.setConfirmable(true);
		request.setDestinationContext(new AddressEndpointContext(serverEndpoint.getAddress()));
		request.setPayload("client says hi");

		return request;
	}

	/**
	 * Tests replay scenario where client first sends two correct messages,
	 * resets its sequence number and then sends a third message. This simulates
	 * a client restarting.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testRestartReplay() throws Exception {
		createSimpleServer();

		// Set up OSCORE context information for request (client)
		byte[] sid = new byte[0];
		byte[] rid = new byte[] { 0x01 };
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, context_id,
				MAX_UNFRAGMENTED_SIZE);
		dbClient.addContext(TestTools.getUri(serverEndpoint, ""), ctx);

		// send first request
		Request request = buildOscoreRequest(CoAP.Code.POST);
		request.send();

		// receive first response and check
		Response response = request.waitForResponse(1000);
		assertNotNull("Client received no response", response);
		assertEquals(SERVER_RESPONSE, response.getPayloadString());

		// send second request
		request = buildOscoreRequest(CoAP.Code.POST);
		request.send();

		// receive second response and check
		response = request.waitForResponse(1000);
		assertNotNull("Client received no response", response);
		assertEquals(SERVER_RESPONSE, response.getPayloadString());

		// reset client sender sequence number
		ctx.setSenderSeq(0);

		// send third request (replay)
		request = buildOscoreRequest(CoAP.Code.POST);
		request.send();

		// receive second response and check
		response = request.waitForResponse(1000);
		assertNotNull("Client received no response", response);
		assertEquals(ErrorDescriptions.REPLAY_DETECT, response.getPayloadString()); // replay
	}

	/**
	 * Tests replay scenario where client first sends a request with Sender
	 * Sequence Number 10, followed by a request with Sender Sequence Number 5.
	 * This tests that the replay window is working as expected, and the message
	 * is accepted.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testReplayWindow() throws Exception {
		createSimpleServer();

		// Set up OSCORE context information for request (client)
		byte[] sid = new byte[0];
		byte[] rid = new byte[] { 0x01 };
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, context_id,
				MAX_UNFRAGMENTED_SIZE);
		dbClient.addContext(TestTools.getUri(serverEndpoint, ""), ctx);

		// set SSN to 10
		ctx.setSenderSeq(10);

		// send first request
		Request request = buildOscoreRequest(CoAP.Code.POST);
		request.send();

		// receive first response and check
		Response response = request.waitForResponse(1000);
		assertNotNull("Client received no response", response);
		assertEquals(SERVER_RESPONSE, response.getPayloadString());

		// set SSN to 5
		ctx.setSenderSeq(5);

		// send second request
		request = buildOscoreRequest(CoAP.Code.POST);
		request.send();

		// receive second response and check
		response = request.waitForResponse(1000);
		assertNotNull("Client received no response", response);
		assertEquals(SERVER_RESPONSE, response.getPayloadString());
	}

	/**
	 * Tests scenario where the client sends a larger number of requests (300)
	 * to the server.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testManyRequests() throws Exception {
		createSimpleServer();

		// Set up OSCORE context information for request (client)
		byte[] sid = new byte[0];
		byte[] rid = new byte[] { 0x01 };
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, context_id,
				MAX_UNFRAGMENTED_SIZE);
		dbClient.addContext(TestTools.getUri(serverEndpoint, ""), ctx);

		// Tests sending a larger number of requests in sequence
		int requestsToSend = 300;
		for (int i = 0; i < requestsToSend; i++) {
			// send request
			Request request = buildOscoreRequest(CoAP.Code.POST);
			request.send();

			// receive response and check
			Response response = request.waitForResponse(1000);
			assertNotNull("Client received no response for request: " + i, response);
			assertEquals(SERVER_RESPONSE, response.getPayloadString());
		}
	}

	/**
	 * Tests scenario where the client varies the sender sequence number (SSN)
	 * used in requests from 0 to 2^30. This tests that the whole range of
	 * Partial IVs (which are built from the SSN) works correctly.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testVaryingSsn() throws Exception {
		createSimpleServer();

		// Set up OSCORE context information for request (client)
		byte[] sid = new byte[0];
		byte[] rid = new byte[] { 0x01 };
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, context_id,
				MAX_UNFRAGMENTED_SIZE);
		dbClient.addContext(TestTools.getUri(serverEndpoint, ""), ctx);

		// Sends requests with varying SSN
		for (int i = 0; i < 30; i++) {

			int senderSequenceNumber = (int) Math.pow(2, i);
			ctx.setSenderSeq(senderSequenceNumber);

			// send request
			Request request = buildOscoreRequest(CoAP.Code.POST);
			request.send();

			// receive response and check
			Response response = request.waitForResponse(1000);
			assertNotNull("Client received no response for request with seq: " + senderSequenceNumber, response);
			assertEquals(SERVER_RESPONSE, response.getPayloadString());
		}
	}

	/**
	 * Tests replay scenario where client first sends a request with Sender
	 * Sequence Number 1000, followed by a request with Sender Sequence Number
	 * 100 - 3 * Replay Window Size. This tests that this old message is
	 * rejected.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testReplayWindowTooOld() throws Exception {
		createSimpleServer();

		// Set up OSCORE context information for request (client)
		byte[] sid = new byte[0];
		byte[] rid = new byte[] { 0x01 };
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, context_id,
				MAX_UNFRAGMENTED_SIZE);
		dbClient.addContext(TestTools.getUri(serverEndpoint, ""), ctx);

		// set SSN to 1000
		int initialSeq = 1000;
		ctx.setSenderSeq(initialSeq);

		// send first request
		Request request = buildOscoreRequest(CoAP.Code.POST);
		request.send();

		// receive first response and check
		Response response = request.waitForResponse(1000);
		assertNotNull("Client received no response", response);
		assertEquals(SERVER_RESPONSE, response.getPayloadString());

		// set SSN to too low value
		int tooLowSeq = (int) (initialSeq - 3 * ctx.getRecipientReplaySize());
		ctx.setSenderSeq(tooLowSeq);

		// send second request
		request = buildOscoreRequest(CoAP.Code.POST);
		request.send();

		// receive second response and check
		response = request.waitForResponse(1000);
		assertNotNull("Client received no response", response);
		assertEquals(ErrorDescriptions.REPLAY_DETECT, response.getPayloadString());
	}

	private void createSimpleServer() throws Exception {

		// Don't start server if it is already running
		if (server != null) {
			return;
		}

		// Set up OSCORE context information for response (server)
		byte[] sid = new byte[] { 0x01 };
		byte[] rid = new byte[0];
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, context_id, MAX_UNFRAGMENTED_SIZE);
		dbServer.addContext(ctx);

		// Create server
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCustomCoapStackArgument(dbServer);
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		serverEndpoint = builder.build();
		server = new CoapServer();
		server.addEndpoint(serverEndpoint);
		server.setMessageDeliverer(new MessageDeliverer() {

			@Override
			public void deliverRequest(Exchange exchange) {
				Response response = new Response(ResponseCode.CONTENT);
				response.setMID(exchange.getRequest().getMID());
				response.setConfirmable(false);
				response.setPayload(SERVER_RESPONSE);
				exchange.sendResponse(response);
			}

			@Override
			public void deliverResponse(Exchange exchange, Response response) {
			}
		});
		server.start();
	}

}
