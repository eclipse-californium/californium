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
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CoapNetworkRule for
 *                                                    setup of test-network
 ******************************************************************************/
package org.eclipse.californium.core.test;

import java.net.DatagramSocket;

import org.junit.Assert;
import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * This test tests whether we are able to properly start, stop and then again
 * start a server. We create two servers each with one resource. Both use an
 * endpoint that both listen on the same port when started. Therefore, they
 * should not be started at the same time. First, we start server 1 and send a
 * request and validate the response come from server 1. Second, we stop server
 * 1, start server 2 and again send a new request and validate that server 2
 * responds. Finally, we stop and destroy both servers.
 */
@Category(Medium.class)
public class StartStopTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	public static final String SERVER_1_RESPONSE = "This is server one";
	public static final String SERVER_2_RESPONSE = "This is server two";
	
	private CoapServer server1, server2;
	private int serverPort;
	
	@Before
	public void setupServers() throws Exception {
		System.out.println("\nStart "+getClass().getSimpleName());
		EndpointManager.clear();
		
		// Find a port
//		// Not possible in Java 1.6
//		try (DatagramSocket s = new DatagramSocket()) {
//			serverPort = s.getLocalPort();
//		} // here, Java closes the socket
		DatagramSocket s = new DatagramSocket();
		serverPort = s.getLocalPort();
		s.close();
		
		Thread.sleep(500);
		System.out.println("Socket port: "+serverPort);
		
		server1 = new CoapServer(serverPort);
		server1.add(new CoapResource("res") {
			@Override public void handleGET(CoapExchange exchange) {
				exchange.respond(SERVER_1_RESPONSE);
			}
		});
		
		server2 = new CoapServer(serverPort);
		server2.add(new CoapResource("res") {
			@Override public void handleGET(CoapExchange exchange) {
				exchange.respond(SERVER_2_RESPONSE);
			}
		});
	}
	
	@After
	public void shutdownServers() {
		if (server1 != null) server1.destroy();
		if (server2 != null) server2.destroy();
		EndpointManager.reset();
		System.out.println("End "+getClass().getSimpleName());
	}
	
	@Test
	public void test() throws Exception {
		System.out.println("Start server 1");
		server1.start();
		sendRequestAndExpect(SERVER_1_RESPONSE);
		
		for (int i=0;i<3;i++) {
			System.out.println("Stop server 1 and start server 2");
			server1.stop();
			Thread.sleep(100); // sometimes Travis does not free the port immediately
			EndpointManager.clear(); // forget all duplicates
			server2.start();
			sendRequestAndExpect(SERVER_2_RESPONSE);

			System.out.println("Stop server 2 and start server 1");
			server2.stop();
			Thread.sleep(100); // sometimes Travis does not free the port immediately
			EndpointManager.clear(); // forget all duplicates
			server1.start();
			sendRequestAndExpect(SERVER_1_RESPONSE);
		}
		
		System.out.println("Stop server 1");
		server1.stop();
	}
	
	private void sendRequestAndExpect(String expected) throws Exception {
		System.out.println();
		Thread.sleep(100);
		Request request = Request.newGet();
		request.setURI("localhost:"+serverPort+"/res");
		String response = request.send().waitForResponse(1000).getPayloadString();
		Assert.assertEquals(expected, response);
	}
	
}
