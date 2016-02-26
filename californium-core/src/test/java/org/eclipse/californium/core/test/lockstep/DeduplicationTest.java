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
package org.eclipse.californium.core.test.lockstep;

import static org.eclipse.californium.core.coap.CoAP.Code.GET;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.Type.ACK;
import static org.eclipse.californium.core.coap.CoAP.Type.CON;
import static org.eclipse.californium.core.coap.CoAP.Type.RST;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.junit.Assert;

import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * This test checks for correct MID namespaces and deduplication.
 */
@Category(Medium.class)
public class DeduplicationTest {
	
	private LockstepEndpoint server;
	
	private Endpoint client;
	private int clientPort;
	
	@Before
	public void setupServer() throws IOException {
		System.out.println("\nStart "+getClass().getSimpleName());
		
		NetworkConfig config = new NetworkConfig()
			.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 128)
			.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 128)
			.setInt(NetworkConfig.Keys.ACK_TIMEOUT, 200) // client retransmits after 200 ms
			.setInt(NetworkConfig.Keys.ACK_RANDOM_FACTOR, 1);
		client = new CoapEndpoint(new InetSocketAddress(0), config);
		client.addInterceptor(new MessageTracer());
		client.start();
		clientPort = client.getAddress().getPort();
		System.out.println("Client binds to port "+clientPort);
	}
	
	@After
	public void shutdownServer() {
		System.out.println();
		client.destroy();
		System.out.println("End "+getClass().getSimpleName());
	}
	
	@Test
	public void test() throws Throwable {
		try {
			testGET();
			
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Make sure you did not forget a .go() at the end of a line.");
			throw e;
		} catch (Throwable t) {
			System.err.println(t);
			throw t;
		}
	}
	
	private void testGET() throws Exception {
		System.out.println("Simple blockwise GET:");
		String path = "test";
		String payload = "possible conflict";
		server = createLockstepEndpoint();
		
		Request request = createRequest(GET, path);
		request.setMID(1234);
		client.sendRequest(request);
		
		server.expectRequest(CON, GET, path).storeToken("A").go();
		server.sendEmpty(ACK).mid(1234).go();
		server.sendEmpty(ACK).mid(1234).go();
		server.sendResponse(CON, CONTENT).loadToken("A").mid(4711).payload("separate").go();
		server.expectEmpty(ACK, 4711).go();
		server.sendResponse(CON, CONTENT).loadToken("A").mid(4711).payload("separate").go();
		server.expectEmpty(ACK, 4711).go();
		server.sendResponse(CON, CONTENT).loadToken("A").mid(42).payload("separate").go();
		server.expectEmpty(RST, 42).go();
		
		request = createRequest(GET, path);
		request.setMID(4711);
		client.sendRequest(request);
		
		server.expectRequest(CON, GET, path).storeBoth("B").storeToken("C").go();
		server.sendResponse(ACK, CONTENT).loadBoth("B").payload("possible conflict").go();
		server.sendResponse(ACK, CONTENT).loadBoth("B").payload("possible conflict").go();
		
		Response response = request.waitForResponse(1000);
		Assert.assertNotNull("Client received no response", response);
		Assert.assertEquals("Client received wrong response code:", CONTENT, response.getCode());
		Assert.assertEquals("Client received wrong payload:", payload, response.getPayloadString());
		
		response = request.waitForResponse(1000);
		Assert.assertNull("Client received duplicate", response);
	}
		
	private LockstepEndpoint createLockstepEndpoint() {
		try {
			LockstepEndpoint endpoint = new LockstepEndpoint();
			endpoint.setDestination(new InetSocketAddress(InetAddress.getByName("localhost"), clientPort));
			return endpoint;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	private Request createRequest(Code code, String path) throws Exception {
		Request request = new Request(code);
		String uri = "coap://localhost:"+(server.getPort())+"/"+path;
		request.setURI(uri);
		return request; 
	}
}
