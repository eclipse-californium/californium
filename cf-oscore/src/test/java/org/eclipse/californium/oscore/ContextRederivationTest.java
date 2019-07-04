/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
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
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;

/**
 * Class that implements test of functionality for re-derivation of contexts.
 * As detailed in Appendix B.2. of the OSCORE draft:
 * https://tools.ietf.org/html/draft-ietf-core-object-security-16#appendix-B.2
 *
 * This can for instance be used when one device has lost power and information
 * about the mutable parts of a context (e.g. sequence number) but retains information
 * about static parts (e.g. master secret)
 * 
 */
public class ContextRederivationTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);
	
	private CoapServer server;
	private int serverPort;
	private static String serverAddress = InetAddress.getLoopbackAddress().getHostAddress();

	private static String clientAddress = InetAddress.getLoopbackAddress().getHostName();

	private static String SERVER_RESPONSE = "Hello World!";
	
	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static String hello1 = "/hello";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// test vector OSCORE draft Appendix C.1.1
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] sid = new byte[0];
	private final static byte[] rid = new byte[] { 0x01 };
	
	@Before
	public void initLogger() {
		System.out.println(System.lineSeparator() + "Start " + getClass().getSimpleName());
		EndpointManager.clear();
	}

	//Use the OSCORE stack factory
	@BeforeClass
	public static void setStackFactory() {
		OSCoreCoapStackFactory.useAsDefault(db);
	}

	@After
	public void after() {
		if (null != server) {
			server.destroy();
		}
		System.out.println("End " + getClass().getSimpleName());
	}

	/**
	 * Test context re-derivation followed by a normal message exchange.
	 * 
	 * @throws OSException
	 * @throws ConnectorException
	 * @throws IOException
	 */
	@Test
	public void rederivationTest() throws OSException, ConnectorException, IOException {
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null);
		String serverUri = "coap://" + serverAddress + ":" + serverPort;
		db.addContext(serverUri, ctx);

		//Indicate that context information has been lost for the context associated to this URI
		ContextRederivation.setLostContext(db, serverUri);
		
		//Now proceed with a normal request from the client
		CoapClient c = new CoapClient(serverUri + hello1);
		Request r = new Request(Code.GET);
		r.getOptions().setOscore(new byte[0]);
		System.out.println((Utils.prettyPrint(r)));
		
		CoapResponse resp = c.advanced(r);
		System.out.println((Utils.prettyPrint(resp)));
		
		assertEquals(resp.getCode(), ResponseCode.CONTENT);
		assertEquals(resp.getResponseText(), SERVER_RESPONSE);
		c.shutdown();
	}

	/**
	 * Creates server with resources for test
	 * @throws InterruptedException if resource update task fails
	 * @throws OSException 
	 */
	@Before
	public void createServer() throws InterruptedException, OSException {
		//Do not create server if it is already running
		if(server != null) {
			return;
		}
		
		//Set up OSCORE context information for response (server)
		byte[] sid = new byte[] { 0x01 };
		byte[] rid = new byte[0];
		OSCoreCtx ctx = new OSCoreCtx(master_secret, false, alg, sid, rid, kdf, 32, master_salt, null);
		db.addContext("coap://" + clientAddress, ctx);

		//Create server
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		
		InetAddress serverInetAddress = null;
		try {
			serverInetAddress = InetAddress.getByName(serverAddress);
		} catch (UnknownHostException e) {
			System.err.println("Failed to find server address!");
		}
		
		builder.setInetSocketAddress(new InetSocketAddress(serverInetAddress, 0));
		CoapEndpoint endpoint = builder.build();
		server = new CoapServer();
		server.addEndpoint(endpoint);

		/** --- Resources for tests follow --- **/

		//Create Hello World-resource
		OSCoreResource hello = new OSCoreResource("hello", true) {

			@Override
			public void handleGET(CoapExchange exchange) {
				System.out.println("Accessing hello resource");
				Response r = new Response(ResponseCode.CONTENT);
				r.setPayload(SERVER_RESPONSE);
				exchange.respond(r);
			}
		};
		
		//Creating resource hierarchy
		server.add(hello);

		/** --- End of resources for tests **/

		//Start server
		server.start();
		serverPort = endpoint.getAddress().getPort();
	}
}
