/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CoapNetworkRule for
 *                                                    setup of test-network
 *    Achim Kraus (Bosch Software Innovations GmbH) - add volatile and AtomicInteger
 *                                                    Relax retransmission timing by
 *                                                    increasing the ACK_TIMEOUT.
 *    Achim Kraus (Bosch Software Innovations GmbH) - check MIDs of notifies
 *    Achim Kraus (Bosch Software Innovations GmbH) - use renamed sameMID instead
 *                                                    of loadMID
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import static org.eclipse.californium.TestTools.generateRandomPayload;
import static org.eclipse.californium.core.coap.CoAP.Code.GET;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.Type.ACK;
import static org.eclipse.californium.core.coap.CoAP.Type.CON;
import static org.eclipse.californium.core.coap.CoAP.Type.NON;
import static org.eclipse.californium.core.coap.CoAP.Type.RST;
import static org.eclipse.californium.core.test.MessageExchangeStoreTool.assertAllExchangesAreCompleted;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.createLockstepEndpoint;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.generateNextToken;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.printServerLog;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.CheckCondition;
import org.eclipse.californium.TestTools;
import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.test.ErrorInjector;
import org.eclipse.californium.core.test.MessageExchangeStoreTool.CoapTestEndpoint;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Tests for server side observes.
 * 
 * Understanding the threading model of this test isn't easy. The
 * {@link #TestObserveResource} is mainly executed synchronous to the test
 * execution. But there are exceptions, especially the response and some
 * retransmission are executed in an other thread. So be careful!
 */
@Category(Medium.class)
public class ObserveServerSideTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	private static final int ACK_TIMEOUT = 200;
	private static final String RESOURCE_PATH = "obs";
	private static NetworkConfig CONFIG;

	private static CoapServer server;
	private static InetSocketAddress serverAddress;
	private static CoapTestEndpoint serverEndpoint;

	private LockstepEndpoint client;
	private int mid = 7000;

	private static TestObserveResource testObsResource;
	private volatile static String respPayload;
	private volatile static Type respType;

	private static ServerBlockwiseInterceptor serverInterceptor = new ServerBlockwiseInterceptor();

	@BeforeClass
	public static void start() {
		System.out.println(System.lineSeparator() + "Start " + ObserveServerSideTest.class.getSimpleName());

		CONFIG = network.createTestConfig()
				.setInt(NetworkConfig.Keys.ACK_TIMEOUT, ACK_TIMEOUT)
				.setFloat(NetworkConfig.Keys.ACK_RANDOM_FACTOR, 1f)
				.setFloat(NetworkConfig.Keys.ACK_TIMEOUT_SCALE, 1f)
				.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 32)
				.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 32)
				.setInt(NetworkConfig.Keys.MARK_AND_SWEEP_INTERVAL, 200)
				.setLong(NetworkConfig.Keys.EXCHANGE_LIFETIME, 247)
				.setLong(NetworkConfig.Keys.BLOCKWISE_STATUS_LIFETIME, 300);

		testObsResource = new TestObserveResource(RESOURCE_PATH);

		server = new CoapServer();
		serverEndpoint = new CoapTestEndpoint(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), CONFIG);
		server.addEndpoint(serverEndpoint);
		server.add(testObsResource);
		server.getEndpoints().get(0).addInterceptor(serverInterceptor);
		server.start();
		serverAddress = server.getEndpoints().get(0).getAddress();
		System.out.println("Server binds to port " + serverAddress.getPort());

	}

	@Before
	public void setupClient() throws Exception {

		client = createLockstepEndpoint(serverAddress);
		testObsResource.clearObserveRelations();
	}

	@After
	public void stopClient() {
		try {
			assertAllExchangesAreCompleted(serverEndpoint);
		} finally {
			printServerLog(serverInterceptor);
			System.out.println();
			client.destroy();
		}
	}

	@AfterClass
	public static void finish() {

		System.out.println("End " + ObserveServerSideTest.class.getSimpleName());
		server.destroy();
	}

	@Test
	public void testEstablishmentAndTimeout() throws Exception {

		System.out.println("Establish an observe relation. Cancellation after timeout");
		respPayload = generateRandomPayload(30);
		Token tok = generateNextToken();

		respType = null;
		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).observe(0).go();
		client.expectResponse(ACK, CONTENT, tok, mid).storeObserve("Z").payload(respPayload).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log(System.lineSeparator() + "Observe relation established");

		// First notification
		respType = NON;
		testObsResource.change("First notification");
		client.expectResponse().type(respType).code(CONTENT).token(tok).checkObs("Z", "A").payload(respPayload).go();

		// Second notification
		testObsResource.change("Second notification");
		client.expectResponse().type(respType).code(CONTENT).token(tok).checkObs("A", "B").payload(respPayload).go();

		// Third notification
		respType = CON;
		testObsResource.change("Third notification");
		client.expectResponse().type(respType).code(CONTENT).token(tok).storeMID("MID").checkObs("B", "C").payload(respPayload).go();
		client.sendEmpty(ACK).loadMID("MID").go();

		// Forth notification
		respType = NON;
		testObsResource.change("Fourth notification");
		client.expectResponse().type(respType).code(CONTENT).token(tok).checkObs("C", "D").payload(respPayload).go();

		// Fifth notification
		respType = CON;
		testObsResource.change("Fifth notification");
		client.expectResponse().type(respType).code(CONTENT).token(tok).storeMID("MID").checkObs("D", "E").payload(respPayload).go();
		serverInterceptor.log(" // lost");
		client.expectResponse().type(respType).code(CONTENT).token(tok).sameMID("MID").loadObserve("E").payload(respPayload).go();
		serverInterceptor.log(" // lost");
		client.expectResponse().type(respType).code(CONTENT).token(tok).sameMID("MID").loadObserve("E").payload(respPayload).go();
		serverInterceptor.log(" // lost");
		client.expectResponse().type(respType).code(CONTENT).token(tok).sameMID("MID").loadObserve("E").payload(respPayload).go();
		serverInterceptor.log(" // lost");
		client.expectResponse().type(respType).code(CONTENT).token(tok).sameMID("MID").loadObserve("E").payload(respPayload).go();
		serverInterceptor.log(" // lost");

		Assert.assertEquals("Resource should have removed observe relation after timeout", 0, waitForObservers(ACK_TIMEOUT + 100, 0));
	}

	@Test
	public void testEstablishmentAndTimeoutWithUpdateInMiddle() throws Exception {
		System.out.println("Establish an observe relation. Cancellation after timeout. During the timeouts, the resource still changes.");
		respPayload = generateRandomPayload(30);
		Token tok = generateNextToken();

		respType = null;
		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).observe(0).go();
		client.expectResponse(ACK, CONTENT, tok, mid).storeObserve("A").payload(respPayload).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log(System.lineSeparator() + "Observe relation established");

		// First notification
		respType = CON;
		testObsResource.change("First notification " + generateRandomPayload(10));
		client.expectResponse().type(respType).code(CONTENT).token(tok).storeMID("MID").checkObs("A", "B").payload(respPayload).go();
		serverInterceptor.log("// lost ");
		client.expectResponse().type(respType).code(CONTENT).token(tok).sameMID("MID").loadObserve("B").payload(respPayload).go();
		serverInterceptor.log("// lost (1. retransmission)");

		// Resource changes and sends next CON which will be transmitted after the former has timed out
		testObsResource.change("Second notification " + generateRandomPayload(10));
		client.expectResponse().type(respType).code(CONTENT).token(tok).storeMID("MID").checkObs("B", "C").payload(respPayload).go();
		serverInterceptor.log("// lost (2. retransmission)");

		// Resource changes. Even though the next notification is a NON it becomes
		// a CON because it replaces the retransmission of the former CON control notification
		respType = NON;
		testObsResource.change("Third notification " + generateRandomPayload(10));
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("MID").checkObs("C", "D").payload(respPayload).go();
		serverInterceptor.log("// lost (3. retransmission)");

		client.expectResponse().type(CON).code(CONTENT).token(tok).sameMID("MID").loadObserve("D").payload(respPayload).go();
		serverInterceptor.log("// lost (4. retransmission)");

		Assert.assertEquals("Resource has not removed relation after timeout:", 0, waitForObservers(ACK_TIMEOUT + 100, 0));
	}

	@Test
	public void testEstablishmentAndRejectCancellation() throws Exception {
		System.out.println("Establish an observe relation. Cancellation due to a reject from the client");
		respPayload = generateRandomPayload(30);
		Token tok = generateNextToken();

		respType = null;
		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).observe(0).go();
		client.expectResponse(ACK, CONTENT, tok, mid).storeObserve("A").payload(respPayload).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log(System.lineSeparator() + "Observe relation established");

		// First notification
		respType = CON;
		testObsResource.change("First notification " + generateRandomPayload(10));
		client.expectResponse().type(respType).code(CONTENT).token(tok).storeMID("MID").checkObs("A", "B").payload(respPayload).go();
		serverInterceptor.log("// lost ");
		client.expectResponse().type(respType).code(CONTENT).token(tok).sameMID("MID").loadObserve("B").payload(respPayload).go();

		serverInterceptor.log("// Reject notification (cancel observe)");
		client.sendEmpty(RST).loadMID("MID").go();

		Assert.assertEquals("Resource has not removed observe relation:", 0, waitForObservers(ACK_TIMEOUT + 100, 0));
	}

	@Test
	public void testObserveWithBlock() throws Exception {
		System.out.println("Observe with blockwise");
		respPayload = generateRandomPayload(80);
		Token tok = generateNextToken();

		// Establish relation
		respType = null; // first type is normal ACK
		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).observe(0).go();
		client.expectResponse(ACK, CONTENT, tok, mid).storeObserve("A").storeETag("tag")
			.block2(0, true, 32).size2(respPayload.length()).payload(respPayload, 0, 32).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log(System.lineSeparator() + "Observe relation established");

		// Get remaining blocks
		Token tok2 = generateNextToken();
		client.sendRequest(CON, GET, tok2, ++mid).path(RESOURCE_PATH).loadETag("tag").block2(1, false, 32).go();
		client.expectResponse(ACK, CONTENT, tok2, mid).block2(1, true, 32).payload(respPayload, 32, 64).go();
		client.sendRequest(CON, GET, tok2, ++mid).path(RESOURCE_PATH).loadETag("tag").block2(2, false, 32).go();
		client.expectResponse(ACK, CONTENT, tok2, mid).block2(2, false, 32).payload(respPayload, 64, 80).go();

		// First notification
		respType = CON;
		testObsResource.change(generateRandomPayload(80));
		serverInterceptor.log(System.lineSeparator() + "   === changed ===");
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("MID").checkObs("A", "B").storeETag("tag")
				.block2(0, true, 32).size2(respPayload.length()).payload(respPayload, 0, 32).go();
		client.sendEmpty(ACK).loadMID("MID").go();

		// Get remaining blocks
		Token tok3 = generateNextToken();
		client.sendRequest(CON, GET, tok3, ++mid).path(RESOURCE_PATH).loadETag("tag").block2(1, false, 32).go();
		client.expectResponse(ACK, CONTENT, tok3, mid).block2(1, true, 32).payload(respPayload, 32, 64).go();
		client.sendRequest(CON, GET, tok3, ++mid).path(RESOURCE_PATH).loadETag("tag").block2(2, false, 32).go();
		client.expectResponse(ACK, CONTENT, tok3, mid).block2(2, false, 32).payload(respPayload, 64, 80).go();

		// Second notification
		respType = CON;
		testObsResource.change(generateRandomPayload(80));
		serverInterceptor.log(System.lineSeparator() + "   === changed ===");
		client.expectResponse().type(respType).code(CONTENT).token(tok).storeMID("MID").checkObs("A", "B").block2(0, true, 32).payload(respPayload, 0, 32).go();
		
		serverInterceptor.log("// Reject notification (cancel observe)");
		client.sendEmpty(RST).loadMID("MID").go(); // client cancels observation

		Assert.assertEquals("Resource has not removed observe relation:", 0, waitForObservers(ACK_TIMEOUT + 100, 0));
	}

	@Test
	public void testNON() throws Exception {

		System.out.println("Establish an observe relation and receive NON notifications");
		respPayload = generateRandomPayload(30);
		Token tok = generateNextToken();

		respType = null;
		client.sendRequest(NON, GET, tok, ++mid).path(RESOURCE_PATH).observe(0).go();
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeObserve("A").payload(respPayload).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log(System.lineSeparator() + "Observe relation established");

		// First notification
		testObsResource.change("First notification " + generateRandomPayload(10));
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeMID("MID").checkObs("A", "B").payload(respPayload).go();

		respType = CON;
		testObsResource.change("Second notification " + generateRandomPayload(10));
		client.expectResponse().type(respType).code(CONTENT).token(tok).storeMID("MID").checkObs("B", "C").payload(respPayload).go();
		client.sendEmpty(ACK).loadMID("MID").go();

		// wait, hopefully the ACK is processed before the next notification is send.
		Thread.sleep(100);
		respType = NON;
		testObsResource.change("Third notification " + generateRandomPayload(10));
		// NON, or CON, if ACK is not processed yet.
		client.expectResponse().type(NON, CON).code(CONTENT).token(tok).storeMID("MID").checkObs("C", "D").payload(respPayload).go();

		serverInterceptor.log("// Reject notification (cancel observe)");
		client.sendEmpty(RST).loadMID("MID").go();

		Assert.assertEquals("Resource has not removed observe relation:", 0, waitForObservers(ACK_TIMEOUT + 100, 0));
	}

	@Test
	public void testRejectPreviousNON() throws Exception {

		System.out.println("Establish an observe relation and receive NON notifications");
		respPayload = generateRandomPayload(30);
		Token tok = generateNextToken();

		respType = null;
		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).observe(0).go();
		client.expectResponse().type(ACK).code(CONTENT).token(tok).storeObserve("A").payload(respPayload).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log(System.lineSeparator() + "Observe relation established");

		// First notification
		testObsResource.change("First notification " + generateRandomPayload(10));
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeMID("MID1").checkObs("A", "B").payload(respPayload).go();

		testObsResource.change("Second notification " + generateRandomPayload(10));
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeMID("MID2").checkObs("B", "C").payload(respPayload).go();

		testObsResource.change("Third notification " + generateRandomPayload(10));
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeMID("MID3").checkObs("C", "D").payload(respPayload).go();

		serverInterceptor.log("// Reject 1. notification (cancel observe)");
		client.sendEmpty(RST).loadMID("MID1").go();

		Assert.assertEquals("Resource has not removed observe relation:", 0, waitForObservers(ACK_TIMEOUT + 100, 0));
	}

	@Test
	public void testNONWithBlock() throws Exception {

		System.out.println("Establish an observe relation and receive NON notifications");
		respPayload = generateRandomPayload(30);
		Token tok = generateNextToken();

		respType = null;
		client.sendRequest(NON, GET, tok, ++mid).path(RESOURCE_PATH).observe(0).block2(0, false, 16).go();
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeObserve("A").storeETag("tag")
			.size2(respPayload.length()).payload(respPayload, 0, 16).go();
		client.sendRequest(NON, GET, tok, ++mid).path(RESOURCE_PATH).loadETag("tag").block2(1, false, 16).go();
		client.expectResponse().type(NON).code(CONTENT).token(tok).payload(respPayload, 16, 30).go();

		assertThat("Resource has not added relation", testObsResource.getObserverCount(), is(1));
		serverInterceptor.log(System.lineSeparator() + "Observe relation established");

		// First notification
		testObsResource.change("First notification " + generateRandomPayload(10));
		client.expectResponse().type(NON).code(CONTENT).token(tok).checkObs("A", "B").storeETag("tag")
			.size2(respPayload.length()).block2(0, true, 16).payload(respPayload, 0, 16).go();
		client.sendRequest(NON, GET, tok, ++mid).path(RESOURCE_PATH).loadETag("tag").block2(1, false, 16).go();
		client.expectResponse().type(NON).code(CONTENT).token(tok).payload(respPayload, 16, respPayload.length()).go();

		respType = CON;
		testObsResource.change("Second notification " + generateRandomPayload(10));
		client.expectResponse().type(respType).code(CONTENT).token(tok).storeMID("MID").checkObs("B", "C").storeETag("tag")
			.size2(respPayload.length()).block2(0, true, 16).payload(respPayload, 0, 16).go();
		client.sendEmpty(ACK).loadMID("MID").go();
		client.sendRequest(NON, GET, tok, ++mid).path(RESOURCE_PATH).loadETag("tag").block2(1, false, 16).go();
		client.expectResponse().type(NON).code(CONTENT).token(tok).payload(respPayload, 16, respPayload.length()).go();

		respType = NON;
		testObsResource.change("Third notification " + generateRandomPayload(10));
		client.expectResponse().type(respType).code(CONTENT).token(tok).storeMID("MID").checkObs("C", "D")
			.size2(respPayload.length()).block2(0, true, 16).payload(respPayload, 0, 16).go();

		serverInterceptor.log("// Reject notification (cancel observe)");
		client.sendEmpty(RST).loadMID("MID").go();

		Assert.assertEquals("Resource has not removed relation:", 0, waitForObservers(ACK_TIMEOUT + 100, 0));
	}

	@Test
	public void testQuickChangeAndTimeout() throws Exception {
		System.out.println("Establish an observe relation to a quickly changing resource and do no longer respond");
		respPayload = generateRandomPayload(20);
		Token tok = generateNextToken();

		respType = null;
		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).observe(0).go();
		client.expectResponse(ACK, CONTENT, tok, mid).storeObserve("A").payload(respPayload).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log(System.lineSeparator() + "Observe relation established");

		// First notification
		testObsResource.change("First notification " + generateRandomPayload(10));
		client.expectResponse().type(NON).code(CONTENT).token(tok).newMID("MID").checkObs("A", "B").payload(respPayload).go();

		// Now client crashes and no longer responds

		respType = CON;
		testObsResource.change("Second notification " + generateRandomPayload(10));
		client.expectResponse().type(respType).code(CONTENT).token(tok).newMID("MID").checkObs("B", "C").payload(respPayload).go();
		// client does not ACK the CON notification

		respType = NON;
		testObsResource.change("NON notification 1 " + generateRandomPayload(10));
		// server re-transmits unACKed CON notification but client does not reply
		client.expectResponse().type(CON).code(CONTENT).token(tok).newMID("MID").checkObs("B", "B").payload(respPayload).go();

		testObsResource.change("NON notification 2 " + generateRandomPayload(10));
		// server re-transmits unACKed CON notification but client does not reply
		client.expectResponse().type(CON).code(CONTENT).token(tok).newMID("MID").storeMID("MID_R").checkObs("B", "B").payload(respPayload).go();

		// server re-transmits unACKed CON notification with unmodified payload and (repeated) MID
		client.expectResponse().type(CON).code(CONTENT).token(tok).sameMID("MID_R").loadObserve("B").payload(respPayload).go();
		
		testObsResource.change("NON notification 3 " + generateRandomPayload(10));
		// server re-transmits unACKed CON notification but client does not reply
		client.expectResponse().type(CON).code(CONTENT).token(tok).newMID("MID").checkObs("B", "B").payload(respPayload).go();

		// after 4 retransmission attempts the server cancels the observation
		serverInterceptor.log(System.lineSeparator() + "   server cancels observe relation");

		Assert.assertEquals("Resource has not removed observe relation after timeout:", 0, waitForObservers(ACK_TIMEOUT + 100, 0));
	}

	/**
	 * Test incomplete block2 notification (missing request)
	 * 
	 * @throws Exception
	 */
	@Test
	public void testIncompleteBlock2Notification() throws Exception {
		System.out.println("Observe with blockwise");
		respPayload = generateRandomPayload(32);
		Token tok = generateNextToken();

		// Establish observe relation
		respType = null; // first type is normal ACK
		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).observe(0).go();
		client.expectResponse(ACK, CONTENT, tok, mid).storeObserve("A").storeETag("tag").payload(respPayload).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log(System.lineSeparator() + "Observe relation established");

		// First notification
		respType = CON;
		testObsResource.change(generateRandomPayload(80));
		serverInterceptor.log(System.lineSeparator() + "   === changed ===");
		client.expectResponse().type(CON).code(CONTENT).token(tok).storeMID("MID").checkObs("A", "B").storeETag("tag")
				.block2(0, true, 32).size2(respPayload.length()).payload(respPayload, 0, 32).go();
		client.sendEmpty(ACK).loadMID("MID").go();

		// Get remaining blocks
		Token tok3 = generateNextToken();
		client.sendRequest(CON, GET, tok3, ++mid).path(RESOURCE_PATH).loadETag("tag").block2(1, false, 32).go();
		client.expectResponse(ACK, CONTENT, tok3, mid).block2(1, true, 32).payload(respPayload, 32, 64).go();
		// we don't send last request, @after should check is there is
		// no leak.
	}

	@Test
	public void testFailedToSendNonNotification() throws Exception {

		System.out.println("Establish an observe relation and failed to send NON notification");
		respPayload = generateRandomPayload(30);
		Token tok = generateNextToken();

		ErrorInjector errorInjector = new ErrorInjector();
		serverEndpoint.addInterceptor(errorInjector);

		respType = null;
		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).observe(0).go();
		client.expectResponse().type(ACK).code(CONTENT).token(tok).storeObserve("A").payload(respPayload).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log(System.lineSeparator() + "Observe relation established");

		// First notification
		testObsResource.change("First notification " + generateRandomPayload(10));
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeMID("MID1").checkObs("A", "B").payload(respPayload).go();

		// Simulate error when we send response
		errorInjector.setErrorOnReadyToSend();
		testObsResource.change("Second notification " + generateRandomPayload(10));

		Thread.sleep(100);
		Assert.assertEquals("Resource has still its observe relation:", 1, testObsResource.getObserverCount());

		// Ensure we get the third notification
		testObsResource.change("Third notification " + generateRandomPayload(10));
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeMID("MID3").checkObs("B", "C").payload(respPayload).go();

		// Cancel observe relation
		serverInterceptor.log("// Reject 1. notification (cancel observe)");
		client.sendEmpty(RST).loadMID("MID1").go();

		Assert.assertEquals("Resource has not removed observe relation:", 0, waitForObservers(ACK_TIMEOUT + 100, 0));
	}

	@Test
	public void testRejectAfterFailedToSendNonNotification() throws Exception {

		System.out.println("Establish an observe relation and failed to send NON notification");
		respPayload = generateRandomPayload(30);
		Token tok = generateNextToken();

		ErrorInjector errorInjector = new ErrorInjector();
		serverEndpoint.addInterceptor(errorInjector);

		respType = null;
		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).observe(0).go();
		client.expectResponse().type(ACK).code(CONTENT).token(tok).storeObserve("A").payload(respPayload).go();
		Assert.assertEquals("Resource has not added relation:", 1, testObsResource.getObserverCount());
		serverInterceptor.log(System.lineSeparator() + "Observe relation established");

		// First notification
		testObsResource.change("First notification " + generateRandomPayload(10));
		client.expectResponse().type(NON).code(CONTENT).token(tok).storeMID("MID1").checkObs("A", "B")
				.payload(respPayload).go();

		// Simulate error when we send response
		errorInjector.setErrorOnReadyToSend();
		testObsResource.change("Second notification " + generateRandomPayload(10));

		Thread.sleep(100);

		serverInterceptor.log("// Reject 1. notification (cancel observe)");
		client.sendEmpty(RST).loadMID("MID1").go();

		Assert.assertEquals("Resource has not removed observe relation:", 0, waitForObservers(ACK_TIMEOUT + 100, 0));
	}

	private int waitForObservers(long timeoutMillis, final int count) throws InterruptedException {

		TestTools.waitForCondition(timeoutMillis, 50, TimeUnit.MILLISECONDS, new CheckCondition() {

			@Override
			public boolean isFulFilled() throws IllegalStateException {
				return testObsResource.getObserverCount() == count;
			}
		});

		return testObsResource.getObserverCount();
	}

	// All tests are made with this resource
	private static class TestObserveResource extends CoapResource {

		private AtomicInteger etagSequence = new AtomicInteger(1);

		public TestObserveResource(String name) {
			super(name);
			setObservable(true);
		}

		public void handleGET(CoapExchange exchange) {
			Response response = new Response(CONTENT);
			response.setType(respType); // respType is altered throughout the
										// test cases
			response.setPayload(respPayload); // payload is altered throughout
												// the test cases
			addEtag(response);

			exchange.respond(response);
		}

		public void change(final String newPayload) {
			System.out.println("Resource body changed to: [" + newPayload + "]");
			respPayload = newPayload;
			changed();
		}

		private void addEtag(final Response response) {
			short etag = (short) etagSequence.getAndIncrement();
			ByteBuffer b = ByteBuffer.wrap(new byte[2]);
			b.putShort(etag);
			b.flip();
			response.getOptions().addETag(b.array());
		}
	}
}
