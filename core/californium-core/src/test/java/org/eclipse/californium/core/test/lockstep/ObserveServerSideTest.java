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
import static org.eclipse.californium.core.coap.CoAP.Type.NON;
import static org.eclipse.californium.core.coap.CoAP.Type.RST;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.Assert;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.test.BlockwiseTransferTest.ServerBlockwiseInterceptor;
import org.eclipse.californium.elements.UDPConnector;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;


public class ObserveServerSideTest {

private static boolean RANDOM_PAYLOAD_GENERATION = true;
	
	private CoapServer server;
	private int serverPort;
	
	private int mid = 7000;
	
	private TestObserveResource testObsResource;
	private String respPayload;
	private Type respType;
	private int timeout = 100;
	
	private ServerBlockwiseInterceptor serverInterceptor = new ServerBlockwiseInterceptor();
	
	@Before
	public void setupServer() {
		System.out.println("\nStart "+getClass().getSimpleName());
		Logger ul = Logger.getLogger(UDPConnector.class.toString());
		ul.setLevel(Level.OFF);
		LockstepEndpoint.DEFAULT_VERBOSE = false;
		
		testObsResource = new TestObserveResource("obs");
		
		NetworkConfig config = new NetworkConfig()
			.setInt(NetworkConfig.Keys.ACK_TIMEOUT, timeout)
			.setFloat(NetworkConfig.Keys.ACK_RANDOM_FACTOR, 1f)
			.setFloat(NetworkConfig.Keys.ACK_TIMEOUT_SCALE, 1f)
			.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 32)
			.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 32);
		
		server = new CoapServer(config, 0);
		server.add(testObsResource);
		server.getEndpoints().get(0).addInterceptor(serverInterceptor);
		server.start();
		serverPort = server.getEndpoints().get(0).getAddress().getPort();
		System.out.println("Server binds to port "+serverPort);
	}
	
	@After
	public void shutdownServer() {
		System.out.println();
		server.destroy();
		System.out.println("End "+getClass().getSimpleName());
	}
	
	@Test
	public void test() throws Throwable {
		try {
			
			testEstablishmentAndTimeout();
			testEstablishmentAndTimeoutWithUpdateInMiddle();
			testEstablishmentAndRejectCancellation();
			testObserveWithBlock();
			testNON();
			testNONWithBlock();
			testQuickChangeAndTimeout();
			
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		} catch (Throwable t) {
			System.err.println(t);
			throw t;
		}
	}
	
	private void testEstablishmentAndTimeout() throws Exception {
		System.out.println("Establish an observe relation. Cancellation after timeout");
		respPayload = generatePayload(30);
		byte[] tok = generateNextToken();
		String path = "obs";
		
		LockstepEndpoint client = createLockstepEndpoint();
		respType = null;
		client.sendRequest(CON, GET, tok, ++mid).path(path).observe(0).go();
		client.expectResponse(ACK, CONTENT, tok, mid).storeObserve("Z").payload(respPayload).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log("\nObserve relation established");
		
		// First notification
		respType = NON;
		testObsResource.change("First notification");
		client.expectResponse().type(NON).code(CONTENT).token(tok).checkObs("Z", "A").payload(respPayload).go();
		
		// Second notification
		testObsResource.change("Second notification");
		client.expectResponse().type(NON).code(CONTENT).token(tok).checkObs("A", "B").payload(respPayload).go();
		
		// Third notification
		respType = CON;
		testObsResource.change("Third notification");
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("MID").checkObs("B", "C").payload(respPayload).go();
		client.sendEmpty(ACK).loadMID("MID").go();
		
		// Forth notification
		respType = NON;
		testObsResource.change("Forth notification");
		client.expectResponse().type(NON).code(CONTENT).token(tok).checkObs("C", "D").payload(respPayload).go();
		
		// Fifth notification
		respType = CON;
		testObsResource.change("Fifth notification");
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("MID").checkObs("D", "E").payload(respPayload).go();
		serverInterceptor.log("// lost");
		client.expectResponse().type(CON).code(CONTENT).token(tok).loadMID("MID").loadObserve("E").payload(respPayload).go();
		serverInterceptor.log("// lost");
		client.expectResponse().type(CON).code(CONTENT).token(tok).loadMID("MID").loadObserve("E").payload(respPayload).go();
		serverInterceptor.log("// lost");
		client.expectResponse().type(CON).code(CONTENT).token(tok).loadMID("MID").loadObserve("E").payload(respPayload).go();
		serverInterceptor.log("// lost");
		client.expectResponse().type(CON).code(CONTENT).token(tok).loadMID("MID").loadObserve("E").payload(respPayload).go();
		serverInterceptor.log("// lost");
		
		Thread.sleep(timeout+100);
		
		Assert.assertEquals("Resource has not removed relation:", 0, testObsResource.getObserverCount());
		
		printServerLog();
	}
	
	private void testEstablishmentAndTimeoutWithUpdateInMiddle() throws Exception {
		System.out.println("Establish an observe relation. Cancellation after timeout. During the timeouts, the resource still changes.");
		respPayload = generatePayload(30);
		byte[] tok = generateNextToken();
		String path = "obs";
		
		LockstepEndpoint client = createLockstepEndpoint();
		respType = null;
		client.sendRequest(CON, GET, tok, ++mid).path(path).observe(0).go();
		client.expectResponse(ACK, CONTENT, tok, mid).storeObserve("A").payload(respPayload).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log("\nObserve relation established");
		
		// First notification
		respType = CON;
		testObsResource.change("First notification "+generatePayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("MID").checkObs("A", "B").payload(respPayload).go();
		serverInterceptor.log("// lost ");
		client.expectResponse().type(CON).code(CONTENT).token(tok).loadMID("MID").loadObserve("B").payload(respPayload).go();
		serverInterceptor.log("// lost (1. retransmission)");
		
		// Resource changes and sends next CON which will be transmitted after the former has timeouted
		testObsResource.change("Second notification "+generatePayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("MID").checkObs("B", "C").payload(respPayload).go();
		serverInterceptor.log("// lost (2. retransmission)");
		
		// Resource changes. Even though the next notification is a NON it becomes
		// a CON because it replaces the retransmission of the former CON control notifiation
		respType = NON;
		testObsResource.change("Third notification "+generatePayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("MID").checkObs("C", "D").payload(respPayload).go();
		serverInterceptor.log("// lost (3. retransmission)");
		
		client.expectResponse().type(CON).code(CONTENT).token(tok).loadMID("MID").loadObserve("D").payload(respPayload).go();
		serverInterceptor.log("// lost (4. retransmission)");
		
		Thread.sleep(timeout+100);
		Assert.assertEquals("Resource has not removed relation:", 0, testObsResource.getObserverCount());
		
		printServerLog();
	}
	
	private void testEstablishmentAndRejectCancellation() throws Exception {
		System.out.println("Establish an observe relation. Cancellation due to a reject from the client");
		respPayload = generatePayload(30);
		byte[] tok = generateNextToken();
		String path = "obs";
		
		LockstepEndpoint client = createLockstepEndpoint();
		respType = null;
		client.sendRequest(CON, GET, tok, ++mid).path(path).observe(0).go();
		client.expectResponse(ACK, CONTENT, tok, mid).storeObserve("A").payload(respPayload).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log("\nObserve relation established");
		
		// First notification
		respType = CON;
		testObsResource.change("First notification "+generatePayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("MID").checkObs("A", "B").payload(respPayload).go();
		serverInterceptor.log("// lost ");
		client.expectResponse().type(CON).code(CONTENT).token(tok).loadMID("MID").loadObserve("B").payload(respPayload).go();
		
		System.out.println("Reject notification");
		client.sendEmpty(RST).loadMID("MID").go();
		
		Thread.sleep(100);
		Assert.assertEquals("Resource has not removed relation:", 0, testObsResource.getObserverCount());
		printServerLog();
	}
	
	private void testObserveWithBlock() throws Exception {
		System.out.println("Observe with blockwise");
		respPayload = generatePayload(80);
		byte[] tok = generateNextToken();
		String path = "obs";
		
		// Establish relation
		LockstepEndpoint client = createLockstepEndpoint();
		respType = null; // first type is normal ACK
		client.sendRequest(CON, GET, tok, ++mid).path(path).observe(0).go();
		client.expectResponse(ACK, CONTENT, tok, mid).storeObserve("A").block2(0, true, 32).payload(respPayload, 0, 32).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log("\nObserve relation established");
		
		// Get remaining blocks
		byte[] tok2 = generateNextToken();
		client.sendRequest(CON, GET, tok2, ++mid).path(path).block2(1, false, 32).go();
		client.expectResponse(ACK, CONTENT, tok2, mid).block2(1, true, 32).payload(respPayload, 32, 64).go();
		client.sendRequest(CON, GET, tok2, ++mid).path(path).block2(2, false, 32).go();
		client.expectResponse(ACK, CONTENT, tok2, mid).block2(2, false, 32).payload(respPayload, 64, 80).go(); 
		
		// First notification
		Thread.sleep(50);
		respType = CON;
		testObsResource.change(generatePayload(80));
		serverInterceptor.log("\n   === changed ===");
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("MID").checkObs("A", "B").block2(0, true, 32).payload(respPayload, 0, 32).go();
		client.sendEmpty(ACK).loadMID("MID").go();

		// Get remaining blocks
		byte[] tok3 = generateNextToken();
		client.sendRequest(CON, GET, tok3, ++mid).path(path).block2(1, false, 32).go();
		client.expectResponse(ACK, CONTENT, tok3, mid).block2(1, true, 32).payload(respPayload, 32, 64).go();
		client.sendRequest(CON, GET, tok3, ++mid).path(path).block2(2, false, 32).go();
		client.expectResponse(ACK, CONTENT, tok3, mid).block2(2, false, 32).payload(respPayload, 64, 80).go();
		
		// Second notification
		Thread.sleep(50);
		respType = CON;
		testObsResource.change(generatePayload(80));
		serverInterceptor.log("\n   === changed ===");
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("MID").checkObs("A", "B").block2(0, true, 32).payload(respPayload, 0, 32).go();
		client.sendEmpty(RST).loadMID("MID").go();
		
		
		Thread.sleep(timeout+100);
		Assert.assertEquals("Resource has not removed relation:", 0, testObsResource.getObserverCount());
		printServerLog();
	}
	
	private LockstepEndpoint createLockstepEndpoint() {
		try {
			LockstepEndpoint endpoint = new LockstepEndpoint();
			endpoint.setDestination(new InetSocketAddress(InetAddress.getByName("localhost"), serverPort));
			return endpoint;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	private void printServerLog() {
		System.out.println(serverInterceptor.toString());
		serverInterceptor.clear();
	}
	
	private static int currentToken = 10;
	private static byte[] generateNextToken() {
		return b(++currentToken);
	}
	
	private static byte[] b(int... is) {
		byte[] bytes = new byte[is.length];
		for (int i=0;i<bytes.length;i++)
			bytes[i] = (byte) is[i];
		return bytes;
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
	private class TestObserveResource extends CoapResource {
		
		public TestObserveResource(String name) { 
			super(name);
			setObservable(true);
		}
		
		public void handleGET(CoapExchange exchange) {
			Response response = new Response(CONTENT);
			response.setType(respType);
			response.setPayload(respPayload);
			exchange.respond(response);
		}
		
		public void change(String newPayload) {
			System.out.println("Resource changed: "+newPayload);
			respPayload = newPayload;
			changed();
		}
	}
	
	private void testNON() throws Exception {
		System.out.println("Establish an observe relation and receive NON notifications");
		respPayload = generatePayload(30);
		byte[] tok = generateNextToken();
		String path = "obs";
		
		LockstepEndpoint client = createLockstepEndpoint();
		respType = null;
		client.sendRequest(NON, GET, tok, ++mid).path(path).observe(0).go();
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeObserve("A").payload(respPayload).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log("\nObserve relation established");
		
		// First notification
		testObsResource.change("First notification "+generatePayload(10));
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeMID("MID").checkObs("A", "B").payload(respPayload).go();
		
		respType = CON;
		testObsResource.change("Second notification "+generatePayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("MID").checkObs("B", "C").payload(respPayload).go();

		/* In transit */ {
			respType = NON;
			testObsResource.change("Third notification "+generatePayload(10));
			// resource postpones third notification
		}
		client.sendEmpty(ACK).loadMID("MID").go();
		
		// resource releases third notification
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeMID("MID").checkObs("C", "D").payload(respPayload).go();

		System.out.println("Reject notification");
		client.sendEmpty(RST).loadMID("MID").go();
		
		Thread.sleep(100);
		Assert.assertEquals("Resource has not removed relation:", 0, testObsResource.getObserverCount());
		printServerLog();
	}
	
	private void testNONWithBlock() throws Exception {
		System.out.println("Establish an observe relation and receive NON notifications");
		respPayload = generatePayload(30);
		byte[] tok = generateNextToken();
		String path = "obs";
		
		LockstepEndpoint client = createLockstepEndpoint();
		respType = null;
		client.sendRequest(NON, GET, tok, ++mid).path(path).observe(0).block2(0, false, 32).go();
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeObserve("A").payload(respPayload).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log("\nObserve relation established");
		
		// First notification
		testObsResource.change("First notification "+generatePayload(10));
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeMID("MID").checkObs("A", "B").payload(respPayload).go();
		
		respType = CON;
		testObsResource.change("Second notification "+generatePayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("MID").checkObs("B", "C").payload(respPayload).go();

		/* In transit */ {
			respType = NON;
			testObsResource.change("Third notification "+generatePayload(10));
			// resource postpones third notification
		}
		client.sendEmpty(ACK).loadMID("MID").go();
		
		// resource releases third notification
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeMID("MID").checkObs("C", "D").payload(respPayload).go();

		testObsResource.change("Fourth notification "+generatePayload(10));
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeMID("MID").checkObs("C", "D").payload(respPayload).go();
		
		System.out.println("Reject notification");
		client.sendEmpty(RST).loadMID("MID").go();
		
		Thread.sleep(100);
		Assert.assertEquals("Resource has not removed relation:", 0, testObsResource.getObserverCount());
		printServerLog();
	}
	
	private void testQuickChangeAndTimeout() throws Exception {
		System.out.println("Establish an observe relation to a quickly changing resource and do no longer respond");
		respPayload = generatePayload(20);
		byte[] tok = generateNextToken();
		String path = "obs";
		
		LockstepEndpoint client = createLockstepEndpoint();
		respType = null;
		client.sendRequest(CON, GET, tok, ++mid).path(path).observe(0).go();
		client.expectResponse(ACK, CONTENT, tok, mid).storeObserve("A").payload(respPayload).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log("\nObserve relation established");
		
		// First notification
		testObsResource.change("First notification "+generatePayload(10));
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeMID("MID").checkObs("A", "B").payload(respPayload).go();
		
		// Now client crashes and no longer responds
		
		respType = CON;
		testObsResource.change("Second notification "+generatePayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).checkObs("B", "C").payload(respPayload).go();

		respType = NON;
		testObsResource.change("NON notification 1 "+generatePayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).checkObs("B", "B").payload(respPayload).go();

		testObsResource.change("NON notification 2 "+generatePayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).checkObs("B", "B").payload(respPayload).go();

		testObsResource.change("NON notification 3 "+generatePayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).checkObs("B", "B").payload(respPayload).go();

		testObsResource.change("NON notification 4 "+generatePayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).checkObs("B", "B").payload(respPayload).go();

		serverInterceptor.log("\n   server cancels the relation");
		
		Thread.sleep(timeout+100);
		Assert.assertEquals("Resource has not removed relation:", 0, testObsResource.getObserverCount());
		printServerLog();
	}
	
}
