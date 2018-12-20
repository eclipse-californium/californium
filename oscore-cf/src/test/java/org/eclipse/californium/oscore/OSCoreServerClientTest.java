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

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.AddressEndpointContext;
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

	private int serverPort;
	
	//OSCORE context information shared between server and client
	private final static HashMapCtxDB db = HashMapCtxDB.getInstance();
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	
	@Before
	public void initLogger() {
		System.out.println(System.lineSeparator() + "Start " + getClass().getSimpleName());
		EndpointManager.clear();
	}
	
	//Use the OSCORE stack factory
	@BeforeClass
	public static void setStackFactory() {
		OSCoreCoapStackFactory.useAsDefault();
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
	 */
	@Test
	public void testConfirmable() throws Exception {	
		createSimpleServer();

		//Set up OSCORE context information for request (client)
		byte[] sid = new byte[0];
		byte[] rid = new byte[] { 0x01 };
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null);
		db.addContext("coap://" + InetAddress.getLoopbackAddress().getHostAddress(), ctx);
		
		// send request
		Request request = new Request(CoAP.Code.POST);
		request.getOptions().setOscore(new byte[0]); //Use OSCORE
		int requestMID = 10000;
		request.setMID(requestMID);
		request.setConfirmable(true);
		request.setDestinationContext(new AddressEndpointContext(InetAddress.getLoopbackAddress(), serverPort));
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
	 * Tests OSCORE functionality when the server replies with a non-OSCORE CoAP error message.
	 * In this test the client Sender ID is modified to be incorrect.
	 * The server will reply with an error message with a payload describing the error.
	 */
	@Test
	public void testErrorResponse() throws Exception {	
		createSimpleServer();

		//Set up OSCORE context information for request (client)
		byte[] sid = new byte[] { 0x77 }; //Modified sender ID to be incorrect
		byte[] rid = new byte[] { 0x01 };
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null);
		db.addContext("coap://" + InetAddress.getLoopbackAddress().getHostAddress(), ctx);
		
		// send request
		Request request = new Request(CoAP.Code.POST);
		request.getOptions().setOscore(new byte[0]); //Use OSCORE
		int requestMID = 10000;
		request.setMID(requestMID);
		request.setConfirmable(true);
		request.setDestinationContext(new AddressEndpointContext(InetAddress.getLoopbackAddress(), serverPort));
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
	
	private void createSimpleServer() throws Exception {
		//Set up OSCORE context information for response (server)
		byte[] sid = new byte[] { 0x01 };
		byte[] rid = new byte[0];
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null);
		db.addContext("coap://" + InetAddress.getLoopbackAddress().getHostName(), ctx);
		
		//Create server
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
		CoapEndpoint endpoint = builder.build();
		server = new CoapServer();
		server.addEndpoint(endpoint);
		server.setMessageDeliverer(new MessageDeliverer() {
			@Override
			public void deliverRequest(Exchange exchange) {
				System.out.println("server received request");
				Response response = new Response(ResponseCode.CONTENT);
				response.setMID(exchange.getRequest().getMID());
				response.setConfirmable(false);
				response.setPayload(SERVER_RESPONSE);
				exchange.sendResponse(response);
			}
			@Override
			public void deliverResponse(Exchange exchange, Response response) { }
		});
		server.start();
		serverPort = endpoint.getAddress().getPort();
	}
}
