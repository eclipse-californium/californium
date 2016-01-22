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
import static org.eclipse.californium.core.coap.CoAP.Type.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Random;

import org.junit.Assert;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;


/**
 * This test implements all examples from the blockwise draft 14 for a client.
 */
public class ObserveClientSideTest {

	private static boolean RANDOM_PAYLOAD_GENERATION = true;
	
	private LockstepEndpoint server;
	
	private Endpoint client;
	private int clientPort;
	
	private int mid = 8000;
	
	private String respPayload;
	
	private ClientBlockwiseInterceptor clientInterceptor = new ClientBlockwiseInterceptor();
	
	@Before
	public void setupClient() throws IOException {
		System.out.println("\nStart "+getClass().getSimpleName());
		
		NetworkConfig config = new NetworkConfig()
			.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 16)
			.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 16)
			.setInt(NetworkConfig.Keys.ACK_TIMEOUT, 200) // client retransmits after 200 ms
			.setFloat(NetworkConfig.Keys.ACK_RANDOM_FACTOR, 1f)
			.setFloat(NetworkConfig.Keys.ACK_TIMEOUT_SCALE, 1f);
		client = new CoapEndpoint(new InetSocketAddress(0), config);
		client.addInterceptor(clientInterceptor);
		client.addInterceptor(new MessageTracer());
		client.start();
		clientPort = client.getAddress().getPort();
		System.out.println("Client binds to port "+clientPort);
	}
	
	@After
	public void shutdownClient() {
		System.out.println();
		client.destroy();
		System.out.println("End "+getClass().getSimpleName());
	}
	
	@Test
	public void test() throws Throwable {
		try {
			testGETObserveWithLostACK();
			testBlockwiseObserve();
			
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Make sure you did not forget a .go() at the end of a line.");
			throw e;
		} catch (Throwable t) {
			System.err.println(t);
			throw t;
		}
	}
	
	private void testGETObserveWithLostACK() throws Exception {
		System.out.println("Observe with lost ACKs:");
		respPayload = generatePayload(10);
		String path = "test";
		server = createLockstepEndpoint();
		int obs = 100;
		
		Request request = createRequest(GET, path);
		request.setObserve();
		client.sendRequest(request);
		
		server.expectRequest(CON, GET, path).storeMID("A").storeToken("B").observe(0).go();
		server.sendEmpty(ACK).loadMID("A").go();
		Thread.sleep(50);
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(++obs).go();
		server.expectEmpty(ACK, mid).go(); // lost
		clientInterceptor.log(" // lost");
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(mid).observe(obs).go();
		server.expectEmpty(ACK, mid).go();
		
		Response response = request.waitForResponse(1000);
		printServerLog();
		
		Assert.assertNotNull("Client received no response", response);
		Assert.assertEquals("Client received wrong response code:", CONTENT, response.getCode());
		Assert.assertEquals("Client received wrong payload:", respPayload, response.getPayloadString());
		System.out.println("Relation established");
		Thread.sleep(1000);
		
		respPayload = generatePayload(10); // changed
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(++obs).go();

		server.expectEmpty(ACK, mid).go(); // lost
		
		clientInterceptor.log(" // lost");
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(mid).observe(obs).go();
		server.expectEmpty(ACK, mid).go();

		response = request.waitForResponse(1000);
		printServerLog();
		
		Assert.assertNotNull("Client received no response", response);
		Assert.assertEquals("Client received wrong response code:", CONTENT, response.getCode());
		Assert.assertEquals("Client received wrong payload:", respPayload, response.getPayloadString());
	}
	
	private void testBlockwiseObserve() throws Exception {
		System.out.println("Blockwise Observe:");
		respPayload = generatePayload(40);
		String path = "test";
		server = createLockstepEndpoint();
		
		Request request = createRequest(GET, path);
		request.setObserve();
		client.sendRequest(request);
		
		server.expectRequest(CON, GET, path).storeBoth("A").storeToken("T").go();
		server.sendResponse(ACK, CONTENT).loadBoth("A").observe(0).block2(0, true, 16).payload(respPayload.substring(0, 16)).go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 16).payload(respPayload.substring(16, 32)).go();
		server.expectRequest(CON, GET, path).storeBoth("C").block2(2, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("C").block2(2, false, 16).payload(respPayload.substring(32, 40)).go();
		
		Response response = request.waitForResponse(1000);
		printServerLog();
		
		Assert.assertNotNull("Client received no response", response);
		Assert.assertEquals("Client received wrong response code:", CONTENT, response.getCode());
		Assert.assertEquals("Client received wrong payload:", respPayload, response.getPayloadString());
		
		// normal notification
		Thread.sleep(50);
		server.sendResponse(CON, CONTENT).loadToken("T").mid(++mid).observe(1).block2(0, true, 16).payload(respPayload.substring(0, 16)).go();
		server.expectEmpty(ACK, mid).go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 16).payload(respPayload.substring(16, 32)).go();
		server.expectRequest(CON, GET, path).storeBoth("C").block2(2, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("C").block2(2, false, 16).payload(respPayload.substring(32, 40)).go();
		
		response = request.waitForResponse(1000);
		printServerLog();
		
		Assert.assertNotNull("Client received no notification", response);
		Assert.assertEquals("Client received wrong response code:", CONTENT, response.getCode());
		Assert.assertEquals("Client received wrong payload:", respPayload, response.getPayloadString());
		
		// override transfer with new notification
		Thread.sleep(50);
		server.sendResponse(CON, CONTENT).loadToken("T").mid(++mid).observe(2).block2(0, true, 16).payload(respPayload.substring(0, 16)).go();
		server.expectEmpty(ACK, mid).go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 16).payload(respPayload.substring(16, 32)).go();
		server.expectRequest(CON, GET, path).storeBoth("C").block2(2, false, 16).go();
		clientInterceptor.log("\n\n//////// Overriding notification ////////");
		String respPayload3 = "abcdefghijklmnopqrstuvwxyzabcdefghijklmn";
		server.sendResponse(CON, CONTENT).loadToken("T").mid(++mid).observe(3).block2(0, true, 16).payload(respPayload3.substring(0, 16)).go();
		server.expectEmpty(ACK, mid).go();
		// old block
		server.sendResponse(ACK, CONTENT).loadBoth("C").block2(2, false, 16).payload(respPayload.substring(32, 40)).go();
		// new block
		server.expectRequest(CON, GET, path).storeBoth("D").block2(1, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("D").block2(1, true, 16).payload(respPayload3.substring(16, 32)).go();
		server.expectRequest(CON, GET, path).storeBoth("E").block2(2, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("E").block2(2, false, 16).payload(respPayload3.substring(32, 40)).go();
		
		response = request.waitForResponse(1000);
		printServerLog();
		
		Assert.assertNotNull("Client received no notification", response);
		Assert.assertEquals("Client received wrong response code:", CONTENT, response.getCode());
		Assert.assertEquals("Client received wrong payload:", respPayload3, response.getPayloadString());
		
		// override transfer with new notification and conflicting block number
		Thread.sleep(50);
		server.sendResponse(CON, CONTENT).loadToken("T").mid(++mid).observe(4).block2(0, true, 16).payload(respPayload.substring(0, 16)).go();
		server.expectEmpty(ACK, mid).go();
		server.expectRequest(CON, GET, path).storeBoth("F").block2(1, false, 16).go();
		clientInterceptor.log("\n\n//////// Overriding notification 2 ////////");
		String respPayload4 = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMN";
		server.sendResponse(CON, CONTENT).loadToken("T").mid(++mid).observe(5).block2(0, true, 16).payload(respPayload4.substring(0, 16)).go();
		server.expectEmpty(ACK, mid).go();
		// old block
		clientInterceptor.log("\n\n//////// Conflicting notification block ////////");
		server.sendResponse(ACK, CONTENT).loadBoth("F").block2(1, true, 16).payload(respPayload.substring(16, 32)).go();
		// new block
		server.expectRequest(CON, GET, path).storeBoth("G").block2(1, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("G").block2(1, true, 16).payload(respPayload4.substring(16, 32)).go();
		server.expectRequest(CON, GET, path).storeBoth("H").block2(2, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("H").block2(2, false, 16).payload(respPayload4.substring(32, 40)).go();
		
		response = request.waitForResponse(1000);
		printServerLog();
		
		Assert.assertNotNull("Client received no notification", response);
		Assert.assertEquals("Client received wrong response code:", CONTENT, response.getCode());
		Assert.assertEquals("Client received wrong payload:", respPayload4, response.getPayloadString());
		
		// cancel
		Thread.sleep(50);
		clientInterceptor.log("\n\n//////// Notification after cancellation ////////");
		server.sendResponse(CON, CONTENT).loadToken("T").mid(++mid).observe(6).block2(0, true, 16).payload(respPayload.substring(0, 16)).go();
		server.expectEmpty(ACK, mid).go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 16).go();
		// canceling in the middle of blockwise transfer
		request.cancel();
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 16).payload(respPayload.substring(16, 32)).go();
		
		// notification may not be delivered
		response = request.waitForResponse(1000);
		printServerLog();
		
		Assert.assertNull("Client received notification although canceled", response);
		
		// next notification must be rejected
		Thread.sleep(50);
		server.sendResponse(CON, CONTENT).loadToken("T").mid(++mid).observe(5).block2(0, true, 16).payload(respPayload.substring(0, 16)).go();
		server.expectEmpty(RST, mid).go();
		
		// notification may not be delivered
		response = request.waitForResponse(1000);
		printServerLog();
		
		Assert.assertNull("Client received notification although canceled", response);
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
	
	private void printServerLog() {
		System.out.println(clientInterceptor.toString());
		clientInterceptor.clear();
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
}
