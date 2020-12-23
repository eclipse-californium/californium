/*******************************************************************************
 * Copyright (c) 2020 RISE and others.
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
 *    Rikard Höglund (RISE) - testing OSCORE algorithm support
 ******************************************************************************/
package org.eclipse.californium.oscore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

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
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.ExpectedExceptionWrapper;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * Test usage of the supported encryption algorithms with OSCORE.
 * 
 */
public class OSCoreAlgorithmsTest {

	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	private static String SERVER_RESPONSE = "server responds hi";

	private CoapServer server;

	private Endpoint serverEndpoint;

	// OSCORE context information shared between server and client
	private final static HashMapCtxDB dbServer = new HashMapCtxDB();
	private final static HashMapCtxDB dbClient = new HashMapCtxDB();
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] context_id = { 0x74, 0x65, 0x73, 0x74, 0x74, 0x65, 0x73, 0x74 };

	@Before
	public void initLogger() {
		System.out.println(System.lineSeparator() + "Start " + getClass().getSimpleName());
		EndpointManager.clear();
	}

	// Use the OSCORE stack factory
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

	@Test
	public void test_AES_CCM_16_64_128() throws Exception {
		sendRequest(AlgorithmID.AES_CCM_16_64_128);
	}

	@Test
	public void test_AES_CCM_64_64_128() throws Exception {
		sendRequest(AlgorithmID.AES_CCM_64_64_128);
	}

	@Test
	public void test_AES_CCM_16_128_128() throws Exception {
		sendRequest(AlgorithmID.AES_CCM_16_128_128);
	}

	@Test
	public void test_AES_CCM_64_128_128() throws Exception {
		sendRequest(AlgorithmID.AES_CCM_64_128_128);
	}

	@Rule
	public ExpectedException exceptionRule = ExpectedExceptionWrapper.none();

	@Test
	public void testNotSupported() throws Exception {
		exceptionRule.expect(RuntimeException.class);
		exceptionRule.expectMessage("Unable to set lengths, since algorithm");

		sendRequest(AlgorithmID.AES_CCM_16_64_256);

	}

	/**
	 * Sends and OSCORE request with a context using the selected encryption
	 * algorithm.
	 * 
	 * @param alg the encryption algorithm to use
	 * @throws Exception on test failure
	 */
	public void sendRequest(AlgorithmID alg) throws Exception {
		createSimpleServer(alg);

		// Set up OSCORE context information for request (client)
		byte[] sid = new byte[] { 0x02 };
		byte[] rid = new byte[] { 0x01 };
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, context_id);
		dbClient.addContext("coap://" + serverEndpoint.getAddress().getAddress().getHostAddress(), ctx);

		// send request
		Request request = new Request(CoAP.Code.POST);
		request.getOptions().setOscore(Bytes.EMPTY); // Use OSCORE
		request.setDestinationContext(new AddressEndpointContext(serverEndpoint.getAddress()));
		request.setPayload("client says hi");
		request.send();

		// receive response and check
		Response response = request.waitForResponse(1000);
		assertNotNull("Client received no response using this algorithm", response);
		System.out.println("client received response");
		assertEquals(response.getPayloadString(), SERVER_RESPONSE);
	}

	private void createSimpleServer(AlgorithmID alg) throws Exception {
		// Set up OSCORE context information for response (server)
		byte[] sid = new byte[] { 0x01 };
		byte[] rid = new byte[] { 0x02 };
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, context_id);
		dbServer.addContext(ctx);

		// Create server
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCustomCoapStackArgument(dbServer);
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		serverEndpoint = builder.build();
		server = new CoapServer();
		server.addEndpoint(serverEndpoint);
		cleanup.add(serverEndpoint);
		server.setMessageDeliverer(new MessageDeliverer() {

			@Override
			public void deliverRequest(Exchange exchange) {
				System.out.println("server received request");
				Response response = new Response(ResponseCode.CONTENT);
				response.setMID(exchange.getRequest().getMID());
				response.setConfirmable(false);

				if (exchange.getRequest().getOptions().hasOscore()) {
					response.setPayload(SERVER_RESPONSE);
				}

				exchange.sendResponse(response);
			}

			@Override
			public void deliverResponse(Exchange exchange, Response response) {
			}
		});
		server.start();
	}
}
