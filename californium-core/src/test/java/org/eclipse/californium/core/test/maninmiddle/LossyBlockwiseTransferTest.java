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
 ******************************************************************************/
package org.eclipse.californium.core.test.maninmiddle;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Random;

import org.junit.Assert;
import org.eclipse.californium.category.Large;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * This test randomly drops packets of a blockwise transfer and checks if the
 * transfer still succeeds.
 */
@Category(Large.class)
public class LossyBlockwiseTransferTest {

	private static boolean RANDOM_PAYLOAD_GENERATION = true;
	
	private CoapServer server;
	private Endpoint client;
	private ManInTheMiddle middle;
	
	private int clientPort;
	private int serverPort;
	private int middlePort;
	
	private TestResource testResource;
	private String respPayload;
	private String reqtPayload;
	
	@Before
	public void setupServer() throws Exception {
		System.out.println("\nStart "+getClass().getSimpleName());
		
		NetworkConfig config = new NetworkConfig()
			.setInt(NetworkConfig.Keys.ACK_TIMEOUT, 200)
			.setFloat(NetworkConfig.Keys.ACK_RANDOM_FACTOR, 1f)
			.setFloat(NetworkConfig.Keys.ACK_TIMEOUT_SCALE, 1f)
			.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 32)
			.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 32);
		
		client = new CoapEndpoint(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), config);
		client.start();
		
		server = new CoapServer(config, 0);
		testResource = new TestResource("test");
		server.add(testResource);
		server.start();

		clientPort = client.getAddress().getPort();
		serverPort = server.getEndpoints().get(0).getAddress().getPort();
		middle = new ManInTheMiddle(clientPort, serverPort);
		middlePort = middle.getPort();
		
		System.out.println("Client at "+clientPort+", middle at "+middlePort+", server at "+serverPort);
	}
	
	@After
	public void shutdownServer() {
		System.out.println();
		server.destroy();
		client.destroy();
		System.out.println("End "+getClass().getSimpleName());
	}
	
	@Test
	public void test() throws Throwable {
		try {
			
			String uri = "coap://localhost:" + middlePort + "/test";
			reqtPayload = "";
			respPayload = generatePayload(250);
			
			System.out.println("uri: "+uri);

			CoapClient coapclient = new CoapClient(uri);
			coapclient.setTimeout(5000);
			coapclient.setEndpoint(client);
			
			middle.drop(5,6,8,9,15);
			
			String resp = coapclient.get().getResponseText();
			Assert.assertEquals(respPayload, resp);
			System.out.println("Received " + resp.length() + " bytes");

			Random rand = new Random();
			
			for (int i=0;i<5;i++) {
				int[] numbers = new int[10];
				for (int j=0;j<numbers.length;j++)
					numbers[j] = rand.nextInt(16);
				
				middle.reset();
				middle.drop(numbers);
				
				resp = coapclient.get().getResponseText();
				Assert.assertEquals(respPayload, resp);
				System.out.println("Received " + resp.length() + " bytes");
				
			}
			
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		} catch (Throwable t) {
			System.err.println(t);
			throw t;
		}
	}
	
	private static String generatePayload(int length) {
		StringBuffer buffer = new StringBuffer();
		if (RANDOM_PAYLOAD_GENERATION) {
			Random rand = new Random();
			while(buffer.length() < length) {
				buffer.append(rand.nextInt());
			}
		} else { // Deterministic payload
			int n = 1;
			while(buffer.length() < length) {
				buffer.append(n++);
			}
		}
		return buffer.substring(0, length);
	}
	
	// All tests are made with this resource
	private class TestResource extends CoapResource {
		
		public TestResource(String name) { 
			super(name);
		}
		
		public void handleGET(CoapExchange exchange) {
			exchange.respond(ResponseCode.CONTENT, respPayload);
		}
		
		public void handlePUT(CoapExchange exchange) {
			System.out.println("Server has received request payload: "+exchange.getRequestText());
			Assert.assertEquals(reqtPayload, exchange.getRequestText());
			exchange.respond(ResponseCode.CHANGED, respPayload);
		}
		
		public void handlePOST(CoapExchange exchange) {
			System.out.println("Server has received request payload: "+exchange.getRequestText());
			Assert.assertEquals(reqtPayload, exchange.getRequestText());
			exchange.respond(ResponseCode.CHANGED, respPayload);
		}
	}
}
