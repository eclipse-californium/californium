/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Bosch Software Innovations GmbH - reduce code duplication, split up into
 *                                      separate test cases, remove wait cycles
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import static org.eclipse.californium.core.coap.CoAP.Code.GET;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.Type.ACK;
import static org.eclipse.californium.core.coap.CoAP.Type.CON;
import static org.eclipse.californium.core.coap.CoAP.Type.NON;
import static org.eclipse.californium.core.coap.CoAP.Type.RST;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.Assert;
import org.eclipse.californium.category.Large;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.test.BlockwiseTransferTest.ServerBlockwiseInterceptor;
import org.eclipse.californium.elements.UDPConnector;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Large.class)
public class ObserveServerSideTest {

	private static final int TIMEOUT = 100;
	private static NetworkConfig CONFIG;

	private CoapServer server;
	private InetSocketAddress serverAddress;
	private LockstepEndpoint client;
	private int mid = 7000;

	private TestObserveResource testObsResource;
	private String respPayload;
	private Type respType;

	private ServerBlockwiseInterceptor serverInterceptor = new ServerBlockwiseInterceptor();

	@BeforeClass
	public static void start() {
		System.out.println(System.lineSeparator() + "Start " + ObserveServerSideTest.class.getSimpleName());

		Logger ul = Logger.getLogger(UDPConnector.class.getName());
		ul.setLevel(Level.OFF);

		CONFIG = new NetworkConfig()
				.setInt(NetworkConfig.Keys.ACK_TIMEOUT, TIMEOUT)
				.setFloat(NetworkConfig.Keys.ACK_RANDOM_FACTOR, 1f)
				.setFloat(NetworkConfig.Keys.ACK_TIMEOUT_SCALE, 1f)
				.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 32)
				.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 32);
	}

	@Before
	public void setupServer() throws Exception {
		LockstepEndpoint.DEFAULT_VERBOSE = false;

		testObsResource = new TestObserveResource("obs");

		server = new CoapServer();
		server.addEndpoint(new CoapEndpoint(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), CONFIG));
		server.add(testObsResource);
		server.getEndpoints().get(0).addInterceptor(serverInterceptor);
		server.start();
		serverAddress = server.getEndpoints().get(0).getAddress();
		System.out.println("Server binds to port " + serverAddress.getPort());
		client = createLockstepEndpoint(serverAddress);
	}

	@After
	public void shutdownServer() {
		System.out.println();
		client.destroy();
		server.destroy();
	}

	@AfterClass
	public static void finish() {
		System.out.println("End " + ObserveServerSideTest.class.getSimpleName());
	}

	@Test
	public void testEstablishmentAndTimeout() throws Exception {
		System.out.println("Establish an observe relation. Cancellation after timeout");
		respPayload = generateRandomPayload(30);
		byte[] tok = generateNextToken();
		String path = "obs";

		respType = null;
		client.sendRequest(CON, GET, tok, ++mid).path(path).observe(0).go();
		client.expectResponse(ACK, CONTENT, tok, mid).storeObserve("Z").payload(respPayload).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log(System.lineSeparator() + "Observe relation established");

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

		Thread.sleep(TIMEOUT + 100);

		Assert.assertEquals("Resource should have removed observe relation after timeout", 0, testObsResource.getObserverCount());

		printServerLog(serverInterceptor);
	}

	@Test
	public void testEstablishmentAndTimeoutWithUpdateInMiddle() throws Exception {
		System.out.println("Establish an observe relation. Cancellation after timeout. During the timeouts, the resource still changes.");
		respPayload = generateRandomPayload(30);
		byte[] tok = generateNextToken();
		String path = "obs";

		respType = null;
		client.sendRequest(CON, GET, tok, ++mid).path(path).observe(0).go();
		client.expectResponse(ACK, CONTENT, tok, mid).storeObserve("A").payload(respPayload).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log(System.lineSeparator() + "Observe relation established");

		// First notification
		respType = CON;
		testObsResource.change("First notification " + generateRandomPayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("MID").checkObs("A", "B").payload(respPayload).go();
		serverInterceptor.log("// lost ");
		client.expectResponse().type(CON).code(CONTENT).token(tok).loadMID("MID").loadObserve("B").payload(respPayload).go();
		serverInterceptor.log("// lost (1. retransmission)");

		// Resource changes and sends next CON which will be transmitted after the former has timeouted
		testObsResource.change("Second notification " + generateRandomPayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("MID").checkObs("B", "C").payload(respPayload).go();
		serverInterceptor.log("// lost (2. retransmission)");

		// Resource changes. Even though the next notification is a NON it becomes
		// a CON because it replaces the retransmission of the former CON control notifiation
		respType = NON;
		testObsResource.change("Third notification " + generateRandomPayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("MID").checkObs("C", "D").payload(respPayload).go();
		serverInterceptor.log("// lost (3. retransmission)");

		client.expectResponse().type(CON).code(CONTENT).token(tok).loadMID("MID").loadObserve("D").payload(respPayload).go();
		serverInterceptor.log("// lost (4. retransmission)");

		Thread.sleep(TIMEOUT + 100);
		Assert.assertEquals("Resource has not removed relation:", 0, testObsResource.getObserverCount());

		printServerLog(serverInterceptor);
	}

	@Test
	public void testEstablishmentAndRejectCancellation() throws Exception {
		System.out.println("Establish an observe relation. Cancellation due to a reject from the client");
		respPayload = generateRandomPayload(30);
		byte[] tok = generateNextToken();
		String path = "obs";

		respType = null;
		client.sendRequest(CON, GET, tok, ++mid).path(path).observe(0).go();
		client.expectResponse(ACK, CONTENT, tok, mid).storeObserve("A").payload(respPayload).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log(System.lineSeparator() + "Observe relation established");

		// First notification
		respType = CON;
		testObsResource.change("First notification " + generateRandomPayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("MID").checkObs("A", "B").payload(respPayload).go();
		serverInterceptor.log("// lost ");
		client.expectResponse().type(CON).code(CONTENT).token(tok).loadMID("MID").loadObserve("B").payload(respPayload).go();

		System.out.println("Reject notification");
		client.sendEmpty(RST).loadMID("MID").go();

		Thread.sleep(100);
		Assert.assertEquals("Resource has not removed relation:", 0, testObsResource.getObserverCount());
		printServerLog(serverInterceptor);
	}

	@Test
	public void testObserveWithBlock() throws Exception {
		System.out.println("Observe with blockwise");
		respPayload = generateRandomPayload(80);
		byte[] tok = generateNextToken();
		String path = "obs";

		// Establish relation
		respType = null; // first type is normal ACK
		client.sendRequest(CON, GET, tok, ++mid).path(path).observe(0).go();
		client.expectResponse(ACK, CONTENT, tok, mid).storeObserve("A").block2(0, true, 32).payload(respPayload, 0, 32).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log(System.lineSeparator() + "Observe relation established");

		// Get remaining blocks
		byte[] tok2 = generateNextToken();
		client.sendRequest(CON, GET, tok2, ++mid).path(path).block2(1, false, 32).go();
		client.expectResponse(ACK, CONTENT, tok2, mid).block2(1, true, 32).payload(respPayload, 32, 64).go();
		client.sendRequest(CON, GET, tok2, ++mid).path(path).block2(2, false, 32).go();
		client.expectResponse(ACK, CONTENT, tok2, mid).block2(2, false, 32).payload(respPayload, 64, 80).go(); 

		// First notification
		Thread.sleep(50);
		respType = CON;
		testObsResource.change(generateRandomPayload(80));
		serverInterceptor.log(System.lineSeparator() + "   === changed ===");
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
		testObsResource.change(generateRandomPayload(80));
		serverInterceptor.log(System.lineSeparator() + "   === changed ===");
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("MID").checkObs("A", "B").block2(0, true, 32).payload(respPayload, 0, 32).go();
		client.sendEmpty(RST).loadMID("MID").go();


		Thread.sleep(TIMEOUT + 100);
		Assert.assertEquals("Resource has not removed relation:", 0, testObsResource.getObserverCount());
		printServerLog(serverInterceptor);
	}

	@Test
	public void testNON() throws Exception {
		System.out.println("Establish an observe relation and receive NON notifications");
		respPayload = generateRandomPayload(30);
		byte[] tok = generateNextToken();
		String path = "obs";

		respType = null;
		client.sendRequest(NON, GET, tok, ++mid).path(path).observe(0).go();
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeObserve("A").payload(respPayload).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log(System.lineSeparator() + "Observe relation established");

		// First notification
		testObsResource.change("First notification " + generateRandomPayload(10));
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeMID("MID").checkObs("A", "B").payload(respPayload).go();

		respType = CON;
		testObsResource.change("Second notification " + generateRandomPayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("MID").checkObs("B", "C").payload(respPayload).go();

		/* In transit */ {
			respType = NON;
			testObsResource.change("Third notification " + generateRandomPayload(10));
			// resource postpones third notification
		}
		client.sendEmpty(ACK).loadMID("MID").go();

		// resource releases third notification
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeMID("MID").checkObs("C", "D").payload(respPayload).go();

		System.out.println("Reject notification");
		client.sendEmpty(RST).loadMID("MID").go();

		Thread.sleep(100);
		Assert.assertEquals("Resource has not removed relation:", 0, testObsResource.getObserverCount());
		printServerLog(serverInterceptor);
	}

	@Test
	public void testNONWithBlock() throws Exception {
		System.out.println("Establish an observe relation and receive NON notifications");
		respPayload = generateRandomPayload(30);
		byte[] tok = generateNextToken();
		String path = "obs";

		respType = null;
		client.sendRequest(NON, GET, tok, ++mid).path(path).observe(0).block2(0, false, 32).go();
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeObserve("A").payload(respPayload).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log(System.lineSeparator() + "Observe relation established");

		// First notification
		testObsResource.change("First notification " + generateRandomPayload(10));
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeMID("MID").checkObs("A", "B").payload(respPayload).go();

		respType = CON;
		testObsResource.change("Second notification " + generateRandomPayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("MID").checkObs("B", "C").payload(respPayload).go();

		/* In transit */ {
			respType = NON;
			testObsResource.change("Third notification " + generateRandomPayload(10));
			// resource postpones third notification
		}
		client.sendEmpty(ACK).loadMID("MID").go();

		// resource releases third notification
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeMID("MID").checkObs("C", "D").payload(respPayload).go();

		testObsResource.change("Fourth notification " + generateRandomPayload(10));
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeMID("MID").checkObs("C", "D").payload(respPayload).go();

		System.out.println("Reject notification");
		client.sendEmpty(RST).loadMID("MID").go();

		Thread.sleep(100);
		Assert.assertEquals("Resource has not removed relation:", 0, testObsResource.getObserverCount());
		printServerLog(serverInterceptor);
	}

	@Test
	public void testQuickChangeAndTimeout() throws Exception {
		System.out.println("Establish an observe relation to a quickly changing resource and do no longer respond");
		respPayload = generateRandomPayload(20);
		byte[] tok = generateNextToken();
		String path = "obs";

		respType = null;
		client.sendRequest(CON, GET, tok, ++mid).path(path).observe(0).go();
		client.expectResponse(ACK, CONTENT, tok, mid).storeObserve("A").payload(respPayload).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log(System.lineSeparator() + "Observe relation established");

		// First notification
		testObsResource.change("First notification " + generateRandomPayload(10));
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeMID("MID").checkObs("A", "B").payload(respPayload).go();

		// Now client crashes and no longer responds

		respType = CON;
		testObsResource.change("Second notification " + generateRandomPayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).checkObs("B", "C").payload(respPayload).go();

		respType = NON;
		testObsResource.change("NON notification 1 " + generateRandomPayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).checkObs("B", "B").payload(respPayload).go();

		testObsResource.change("NON notification 2 " + generateRandomPayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).checkObs("B", "B").payload(respPayload).go();

		testObsResource.change("NON notification 3 " + generateRandomPayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).checkObs("B", "B").payload(respPayload).go();

		testObsResource.change("NON notification 4 " + generateRandomPayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).checkObs("B", "B").payload(respPayload).go();

		serverInterceptor.log(System.lineSeparator() + "   server cancels the relation");

		Thread.sleep(TIMEOUT + 100);
		Assert.assertEquals("Resource has not removed relation:", 0, testObsResource.getObserverCount());
		printServerLog(serverInterceptor);
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
}
