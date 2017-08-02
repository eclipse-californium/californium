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
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CoapNetworkRule for
 *                                                    setup of test-network
 *    Achim Kraus (Bosch Software Innovations GmbH) - add testBlockwiseNotifyAndGet
 *                                                    and testBlockwiseGetAndNotify.
 *                                                    Add printServerLog after
 *                                                    tests.
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import static org.eclipse.californium.TestTools.*;
import static org.eclipse.californium.core.coap.CoAP.Code.GET;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.Type.*;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.*;
import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.category.Large;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * This test implements all examples from the blockwise draft 14 for a client.
 */
@Category(Large.class)
public class ObserveClientSideTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	private static NetworkConfig CONFIG;

	private LockstepEndpoint server;
	private Endpoint client;
	private int mid = 8000;
	private String respPayload;
	private ClientBlockwiseInterceptor clientInterceptor = new ClientBlockwiseInterceptor();
	
	@BeforeClass
	public static void init() {
		System.out.println(System.lineSeparator() + "Start " + ObserveClientSideTest.class.getSimpleName());
		CONFIG = network.createTestConfig()
				.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 16)
				.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 16)
				.setInt(NetworkConfig.Keys.ACK_TIMEOUT, 200) // client retransmits after 200 ms
				.setFloat(NetworkConfig.Keys.ACK_RANDOM_FACTOR, 1f)
				.setFloat(NetworkConfig.Keys.ACK_TIMEOUT_SCALE, 1f);
	}

	@Before
	public void setupEndpoints() throws Exception {
		//exchangeStore = new InMemoryMessageExchangeStore(CONFIG, new InMemoryRandomTokenProvider(CONFIG));
		// bind to loopback address using an ephemeral port
	//	CoapEndpoint udpEndpoint = new CoapEndpoint(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), CONFIG, exchangeStore);

		client = new CoapEndpoint(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), CONFIG);
		client.addInterceptor(clientInterceptor);
		client.addInterceptor(new MessageTracer());
		client.start();
		System.out.println("Client binds to port " + client.getAddress().getPort());
		server = createLockstepEndpoint(client.getAddress());
	}

	@After
	public void shutdownEndpoints() {
		printServerLog(clientInterceptor);
		client.destroy();
		server.destroy();
	}

	@AfterClass
	public static void end() {
		System.out.println("End " + ObserveClientSideTest.class.getSimpleName());
	}

	@Test
	public void testGETObserveWithLostACK() throws Exception {
		System.out.println("Observe with lost ACKs:");
		respPayload = generateRandomPayload(10);
		String path = "test";
		int obs = 100;

		Request request = createRequest(GET, path, server);
		SynchronousNotificationListener notificationListener = new SynchronousNotificationListener(request);
		client.addNotificationListener(notificationListener);
		request.setObserve();
		client.sendRequest(request);

		server.expectRequest(CON, GET, path).storeMID("A").storeToken("B").observe(0).go();
		server.sendEmpty(ACK).loadMID("A").go();
		Thread.sleep(50);
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(++obs).go();
		server.expectEmpty(ACK, mid).go(); // lost
		clientInterceptor.log(" // lost");
		// retransmit notification using modified payload
		// client must be able to identify this notification as a duplicate and ignore it
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload + "_DUPLICATE").mid(mid).observe(obs).go();
		server.expectEmpty(ACK, mid).go();

		Response response = request.waitForResponse(1000);
		printServerLog(clientInterceptor);

		assertResponseContainsExpectedPayload(response, respPayload);
		System.out.println("Relation established");

		respPayload = generateRandomPayload(10); // changed
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(++obs).go();
		server.expectEmpty(ACK, mid).go(); // lost
		clientInterceptor.log(" // lost");
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload + "_DUPLICATE").mid(mid).observe(obs).go();
		server.expectEmpty(ACK, mid).go();

		Response notification1 = notificationListener.waitForResponse(1000);
		printServerLog(clientInterceptor);

		assertResponseContainsExpectedPayload(notification1, respPayload);
		assertNumberOfReceivedNotifications(notificationListener, 1, true);
	}

	/**
	 * Verifies behavior of observing a resource that is transferred in multiple chunks using blockwise transfer.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testBlockwiseObserve() throws Exception {

		System.out.println("Blockwise Observe:");
		respPayload = generateRandomPayload(40);
		String path = "test";

		Request request = createRequest(GET, path, server);
		request.setObserve();
		SynchronousNotificationListener notificationListener = new SynchronousNotificationListener(request);
		client.addNotificationListener(notificationListener);
		client.sendRequest(request);

		server.expectRequest(CON, GET, path).storeBoth("A").storeToken("T").go();
		server.sendResponse(ACK, CONTENT).loadBoth("A").observe(0).block2(0, true, 16).size2(respPayload.length()).payload(respPayload.substring(0, 16)).go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 16).payload(respPayload.substring(16, 32)).go();
		server.expectRequest(CON, GET, path).storeBoth("C").block2(2, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("C").block2(2, false, 16).payload(respPayload.substring(32)).go();

		Response response = request.waitForResponse(1000);
		printServerLog(clientInterceptor);

		assertResponseContainsExpectedPayload(response, respPayload);
		System.out.println("observe relation has been established, server now sends a notification");

		respPayload = generateRandomPayload(45);
		// normal notification
		server.sendResponse(CON, CONTENT).loadToken("T").mid(++mid).observe(1).block2(0, true, 16).size2(respPayload.length()).payload(respPayload.substring(0, 16)).go();
		// TODO: allow for messages to be received in arbitrary order
		server.startMultiExpectation();
		server.expectEmpty(ACK, mid).go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 16).go();
		server.goMultiExpectation();
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 16).payload(respPayload.substring(16, 32)).go();
		server.expectRequest(CON, GET, path).storeBoth("C").block2(2, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("C").block2(2, false, 16).payload(respPayload.substring(32)).go();

		Response notification = notificationListener.waitForResponse(1000);
		printServerLog(clientInterceptor);

		assertResponseContainsExpectedPayload(notification, respPayload);
		assertNumberOfReceivedNotifications(notificationListener, 1, true);

		System.out.println("client has successfully retrieved content for notification using blockwise transfer");
		System.out.println("server now sends notifications interfering with ongoing blockwise transfer");

		respPayload = generateRandomPayload(42);
		//
		// notification 2
		//
		server.sendResponse(CON, CONTENT).loadToken("T").mid(++mid).observe(2).block2(0, true, 16).size2(respPayload.length()).payload(respPayload.substring(0, 16)).go();
		server.startMultiExpectation();
		server.expectEmpty(ACK, mid).go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 16).go();
		server.goMultiExpectation();
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 16).payload(respPayload.substring(16, 32)).go();
		server.expectRequest(CON, GET, path).storeBoth("C").block2(2, false, 16).go();

		clientInterceptor.log(System.lineSeparator() + "//////// Overriding notification ////////");
		String respPayload3 = "abcdefghijklmnopqrstuvwxyzabcdefghijklmn";

		//
		// (interfering) notification 3
		// 
		server.sendResponse(CON, CONTENT).loadToken("T").mid(++mid).observe(3).block2(0, true, 16).size2(respPayload3.length()).payload(respPayload3.substring(0, 16)).go();
		server.startMultiExpectation();
		server.expectEmpty(ACK, mid).go();
		// new block
		server.expectRequest(CON, GET, path).storeBoth("D").block2(1, false, 16).go();
		server.goMultiExpectation();
		// old block
		// this block should be discarded by client
		server.sendResponse(ACK, CONTENT).loadBoth("C").block2(2, false, 16).payload(respPayload.substring(32)).go();
		server.sendResponse(ACK, CONTENT).loadBoth("D").block2(1, true, 16).payload(respPayload3.substring(16, 32)).go();
		server.expectRequest(CON, GET, path).storeBoth("E").block2(2, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("E").block2(2, false, 16).payload(respPayload3.substring(32)).go();

		Thread.sleep(50);
		notification = notificationListener.waitForResponse(1000);
		printServerLog(clientInterceptor);

		assertResponseContainsExpectedPayload(notification, respPayload3);
		assertNumberOfReceivedNotifications(notificationListener, 1, true);

		System.out.println("client has detected newly arriving notification while doing blockwise transfer of previous notification");
		System.out.println("server now sends notifications interfering with ongoing blockwise transfer using conflicting block numbers");

		respPayload = generateRandomPayload(38);
		// override transfer with new notification and conflicting block number
		//
		// notification 4
		//
		server.sendResponse(CON, CONTENT).loadToken("T").mid(++mid).observe(4).block2(0, true, 16).size2(respPayload.length()).payload(respPayload.substring(0, 16)).go();
		server.startMultiExpectation();
		server.expectEmpty(ACK, mid).go();
		server.expectRequest(CON, GET, path).storeBoth("F").block2(1, false, 16).go();
		server.goMultiExpectation();

		clientInterceptor.log(System.lineSeparator() + "//////// Overriding notification (4) ////////");
		String respPayload4 = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMN";

		// start new block
		//
		// notification 5
		//
		server.sendResponse(CON, CONTENT).loadToken("T").mid(++mid).observe(5).block2(0, true, 16).size2(respPayload4.length()).payload(respPayload4.substring(0, 16)).go();
		server.startMultiExpectation();
		server.expectEmpty(ACK, mid).go();
		server.expectRequest(CON, GET, path).storeBoth("G").block2(1, false, 16).go();
		server.goMultiExpectation();

		// old block from notification 4 transfer
		clientInterceptor.log(System.lineSeparator() + "//////// Conflicting notification block ////////");
		// this block should be discarded by client
		server.sendResponse(ACK, CONTENT).loadBoth("F").block2(1, true, 16).payload(respPayload.substring(16, 32)).go();

		// new block
		server.sendResponse(ACK, CONTENT).loadBoth("G").block2(1, true, 16).payload(respPayload4.substring(16, 32)).go();
		server.expectRequest(CON, GET, path).storeBoth("I").block2(2, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("I").block2(2, false, 16).payload(respPayload4.substring(32)).go();

		Thread.sleep(50);
		notification = notificationListener.waitForResponse(1000);
		printServerLog(clientInterceptor);

		assertResponseContainsExpectedPayload(notification, respPayload4);
		assertNumberOfReceivedNotifications(notificationListener, 1, true);

		// cancel
		clientInterceptor.log(System.lineSeparator() + "//////// Notification after cancellation ////////");
		respPayload = generateRandomPayload(34);
		server.sendResponse(CON, CONTENT).loadToken("T").mid(++mid).observe(6).block2(0, true, 16).size2(respPayload.length()).payload(respPayload.substring(0, 16)).go();
		server.startMultiExpectation();
		server.expectEmpty(ACK, mid).go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 16).go();
		server.goMultiExpectation();

		// canceling in the middle of blockwise transfer
		client.cancelObservation(request.getToken());
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 16).payload(respPayload.substring(16, 32)).go();

		// notification must not be delivered
		notification = notificationListener.waitForResponse(400);
		printServerLog(clientInterceptor);

		assertThat("Client received notification although canceled", notification, is(nullValue()));

		// next notification must be rejected
		server.sendResponse(CON, CONTENT).loadToken("T").mid(++mid).observe(7).block2(0, true, 16).payload(respPayload.substring(0, 16)).go();
		server.expectEmpty(RST, mid).go();

		// notification must not be delivered
		notification = notificationListener.waitForResponse(400);
		printServerLog(clientInterceptor);

		assertThat("Client received notification although canceled", notification, is(nullValue()));
	}

	/**
	 * Verifies behavior of observing a resource which start a blockwise
	 * transfer and receiving a none-blockwise notification before previous
	 * blockwise transfer finished.
	 * 
	 * <pre>
	 *    (actual used MIDs and Tokens my vary!)
	 *    ####### establish observe an start blockwise tranfer #############
	 *    CON [MID=37434, T=cbeb45abdb65aba2], GET, /test, observe(0)    ----->
	 *    <-----   ACK [MID=37434, T=cbeb45abdb65aba2], 2.05, 2:0/1/16, observe(1)
	 *    CON [MID=37435, T=d2b1c9e97df24976], GET, /test, 2:1/0/16    ----->
	 *    ####### receive none blockwise notification #############
	 *    <-----   CON [MID=222, T=cbeb45abdb65aba2], 2.05, observe(2)
	 *    ACK [MID=222]   ----->
	 *    ####### ensure previous blockwise tranfer is stopped #############
	 *    <-----   CON [MID=37435, T=d2b1c9e97df24976], 2.05, 2:1/1/16
	 *    RST [MID=37435]   ----->
	 *    ####### ensure next none-blockwise notification is received #############
	 *    <-----   CON [MID=223, T=cbeb45abdb65aba2], 2.05, observe(3)
	 *    ACK [MID=223]   ----->
	 *    ####### ensure next blockwise notification is received #############
	 *    <-----   CON [MID=224, T=cbeb45abdb65aba2], 2.05, 2:0/1/16, observe(4)
	 *    ACK [MID=224]   ----->
	 *    CON [MID=21291, T=61c34585da9003e7], GET, /test, 2:1/0/16    ----->
	 *    <-----   ACK [MID=21291, T=61c34585da9003e7], 2.05, 2:1/0/16
	 * </pre>
	 * 
	 * @throws Exception
	 */
	@Test
	public void testBlockwiseObserveAndNotificationWithoutBlockwise() throws Exception {
		System.out.println("Blockwise Observe:");
		// observer request response will be sent using blockwise
		respPayload = generateRandomPayload(25 * 16);
		// notification payload sended without blockwise
		String notifpayload = generateRandomPayload(8);
		String path = "test";

		Request request = createRequest(GET, path, server);
		request.setObserve();
		SynchronousNotificationListener notificationListener = new SynchronousNotificationListener(request);
		client.addNotificationListener(notificationListener);

		// Send observe request
		client.sendRequest(request);
		// Expect observe request
		server.expectRequest(CON, GET, path).storeMID("OBS_REQ").storeToken("OBS_TOK").go();

		// send blockwise response
		server.sendResponse(ACK, CONTENT).loadMID("OBS_REQ").loadToken("OBS_TOK").block2(0, true, 16).observe(1)
				.payload(respPayload.substring(0, 16)).go();
		// Expect next block request
		server.expectRequest(CON, GET, path).storeMID("SECOND_BLOCK_MID").storeToken("SECOND_BLOCK_TOK")
				.block2(1, false, 16).go();

		// During block transfer send a complete (none blockwise) response
		int new_mid = 222;
		server.sendResponse(CON, CONTENT).loadToken("OBS_TOK").observe(2).mid(new_mid).payload(notifpayload).go();
		server.expectEmpty(ACK, new_mid++).go();
		// Check that we get the most recent response (with the higher observe
		// option value)
		Response response = request.waitForResponse();
		assertResponseContainsExpectedPayload(response, notifpayload);

		// Send next block
		server.sendResponse(CON, CONTENT).loadMID("SECOND_BLOCK_MID").loadToken("SECOND_BLOCK_TOK").block2(1, true, 16)
				.payload(respPayload.substring(16, 32)).go();
		// ensure client don't ask for block anymore
		server.expectEmpty(RST, (Integer) server.get("SECOND_BLOCK_MID")).go();
		// TODO ensure that blockdata buffer is cleared in blockwiselayer...

		// Send new notif without block
		notifpayload = generateRandomPayload(8);
		server.sendResponse(CON, CONTENT).loadToken("OBS_TOK").observe(3).mid(new_mid).payload(notifpayload).go();
		server.expectEmpty(ACK, new_mid++).go();
		response = notificationListener.waitForResponse(1000);
		assertResponseContainsExpectedPayload(response, notifpayload);

		// Send new notif without block
		notifpayload = generateRandomPayload(16 * 2);
		server.sendResponse(CON, CONTENT).loadToken("OBS_TOK").observe(4).mid(new_mid).block2(0, true, 16)
				.payload(notifpayload.substring(0, 16)).go();
		// expect ACK and GET for next block
		server.startMultiExpectation();
		server.expectEmpty(ACK, new_mid).go();
		server.expectRequest(CON, GET, path).storeBoth("BLOCK_NOTIF").block2(1, false, 16).go();
		server.goMultiExpectation();
		// send next BLOCK
		server.sendResponse(ACK, CONTENT).loadBoth("BLOCK_NOTIF").block2(1, false, 16)
				.payload(notifpayload.substring(16, 32)).go();

		response = notificationListener.waitForResponse(1000);
		assertResponseContainsExpectedPayload(response, notifpayload);

		printServerLog(clientInterceptor);
	}

	/**
	 * Verifies, that a GET is processed, while a notify is received in
	 * "transparent" blockwise mode.
	 * 
	 * <pre>
	 * (actual used MIDs may vary!)
	 * ####### establish observe #############
	 * CON [MID=8640, T=49e6fdcc16ab9ab7], GET, /test, observe(0)    ----->
	 * <-----   ACK [MID=8640, T=49e6fdcc16ab9ab7], 2.05, 2:0/1/16, observe(1)
	 * CON [MID=8641, T=027256aace12e241], GET, /test, 2:1/0/16    ----->
	 * <-----   ACK [MID=8641, T=027256aace12e241], 2.05, 2:1/0/16
	 * ####### partial notify #############
	 * <-----   CON [MID=8001, T=49e6fdcc16ab9ab7], 2.05, 2:0/1/16, observe(2)
	 * ACK [MID=8001]   ----->
	 * ####### get request #############
	 * CON [MID=8642, T=56d582eba534fb38], GET, /test, 2:1/0/16    ----->
	 * <-----   ACK [MID=8642]
	 * CON [MID=8643, T=77bfb899c0e679fb], GET, /test    ----->
	 * <-----   ACK [MID=8643, T=77bfb899c0e679fb], 2.05, 2:0/1/16
	 * CON [MID=8644, T=77bfb899c0e679fb], GET, /test, 2:1/0/16    ----->
	 * <-----   ACK [MID=8644, T=77bfb899c0e679fb], 2.05, 2:1/1/16
	 * CON [MID=8645, T=77bfb899c0e679fb], GET, /test, 2:2/0/16    ----->
	 * <-----   ACK [MID=8645, T=77bfb899c0e679fb], 2.05, 2:2/0/16	 * 
	 * </pre>
	 * 
	 * @throws Exception
	 */
	@Test
	public void testBlockwiseNotifyAndGet() throws Exception {
		System.out.println("Blockwise Observe:");
		// observer request response will be sent using blockwise
		String path = "test";
		respPayload = generateRandomPayload(32);

		Request request = createRequest(GET, path, server);
		request.setObserve();
		SynchronousNotificationListener notificationListener = new SynchronousNotificationListener(request);
		client.addNotificationListener(notificationListener);

		// Send observe request
		client.sendRequest(request);

		// Expect observe request
		server.expectRequest(CON, GET, path).storeBoth("OBS").go();
		// Send blockwise response
		server.sendResponse(ACK, CONTENT).loadBoth("OBS").observe(1).block2(0, true, 16)
				.payload(respPayload.substring(0, 16)).go();

		// Expect next block request
		server.expectRequest(CON, GET, path).storeBoth("BLOCK").block2(1, false, 16).go();

		// Send next (last) block response
		server.sendResponse(ACK, CONTENT).loadBoth("BLOCK").block2(1, false, 16).payload(respPayload.substring(16, 32))
				.go();

		// Check that we get the response
		Response response = request.waitForResponse(2000);
		assertResponseContainsExpectedPayload(response, respPayload);

		// generate new notify payload
		respPayload = generateRandomPayload(64);

		// Send new notify response
		server.sendResponse(CON, CONTENT).loadToken("OBS").observe(2).mid(++mid).block2(0, true, 16)
				.payload(respPayload.substring(0, 16)).go();

		server.startMultiExpectation();
		// Expect ACKs
		server.expectEmpty(ACK, mid).go();
		// Expect next block request
		server.expectRequest(CON, GET, path).storeBoth("BLOCK").block2(1, false, 16).go();
		server.goMultiExpectation();

		// stale blockwise notify

		// generate new response payload
		respPayload = generateRandomPayload(48);
		// Now try to send a GET on the same resource using block2.
		Request getRequest = createRequest(GET, path, server);
		client.sendRequest(getRequest);

		// Expect get request
		server.expectRequest(CON, GET, path).storeBoth("GET").go();

		// Send response with block2
		server.sendResponse(ACK, CONTENT).loadBoth("GET").block2(0, true, 16).payload(respPayload.substring(0, 16))
				.go();

		// check we receive the next block request.
		server.expectRequest(CON, GET, path).storeBoth("BLOCK").block2(1, false, 16).go();

		// Send next response block
		server.sendResponse(ACK, CONTENT).loadBoth("BLOCK").block2(1, true, 16).payload(respPayload.substring(16, 32))
				.go();

		// check we receive the next block request.
		server.expectRequest(CON, GET, path).storeBoth("BLOCK").block2(2, false, 16).go();

		// Send final response block
		server.sendResponse(ACK, CONTENT).loadBoth("BLOCK").block2(2, false, 16).payload(respPayload.substring(32, 48))
				.go();

		// Check that we get the response
		response = getRequest.waitForResponse(2000);
		assertResponseContainsExpectedPayload(response, respPayload);

		// ensure, that not transfer is still ongoing
		Message message = server.receiveNextMessage(1, TimeUnit.SECONDS);
		assertThat("still receiving messages", message, is(nullValue()));
	}

	/**
	 * Verifies, that a notify is processed, while a GET is received in
	 * "transparent" blockwise mode.
	 * 
	 * <pre>
	 * (actual used MIDs may vary!)
	 * ####### establish observe #############
	 * CON [MID=19473, T=6c4790ed471980fc], GET, /test, observe(0)    ----->
	 * <-----   ACK [MID=19473, T=6c4790ed471980fc], 2.05, 2:0/1/16, observe(1)
	 * CON [MID=19474, T=4b01b63539e7d760], GET, /test, 2:1/0/16    ----->
	 * <-----   ACK [MID=19474, T=4b01b63539e7d760], 2.05, 2:1/0/16
	 * ####### partial get #############
	 * CON [MID=19475, T=27cde2f79856f2e0], GET, /test    ----->
	 * <-----   ACK [MID=19475, T=27cde2f79856f2e0], 2.05, 2:0/1/16
	 * CON [MID=19476, T=27cde2f79856f2e0], GET, /test, 2:1/0/16    ----->
	 * <-----   ACK [MID=19476]
	 * ####### notify #############
	 * <-----   CON [MID=8001, T=6c4790ed471980fc], 2.05, 2:0/1/16, observe(2)
	 * ACK [MID=8001]   ----->
	 * CON [MID=19477, T=4c731f4fa690ba37], GET, /test, 2:1/0/16    ----->
	 * <-----   ACK [MID=19477, T=4c731f4fa690ba37], 2.05, 2:1/1/16
	 * CON [MID=19478, T=4c731f4fa690ba37], GET, /test, 2:2/0/16    ----->
	 * <-----   ACK [MID=19478, T=4c731f4fa690ba37], 2.05, 2:2/0/16
	 * </pre>
	 * 
	 * @throws Exception
	 */
	@Test
	public void testBlockwiseGetAndNotify() throws Exception {
		System.out.println("Blockwise Observe:");
		// observer request response will be sent using blockwise
		String path = "test";
		respPayload = generateRandomPayload(32);

		Request request = createRequest(GET, path, server);
		request.setObserve();
		SynchronousNotificationListener notificationListener = new SynchronousNotificationListener(request);
		client.addNotificationListener(notificationListener);

		// Send observe request
		client.sendRequest(request);

		// Expect observe request
		server.expectRequest(CON, GET, path).storeBoth("OBS").go();
		// Send blockwise response
		server.sendResponse(ACK, CONTENT).loadBoth("OBS").observe(1).block2(0, true, 16)
				.payload(respPayload.substring(0, 16)).go();

		// Expect next block request
		server.expectRequest(CON, GET, path).storeBoth("BLOCK").block2(1, false, 16).go();

		// Send next (last) block response
		server.sendResponse(ACK, CONTENT).loadBoth("BLOCK").block2(1, false, 16).payload(respPayload.substring(16, 32))
				.go();

		// Check that we get the response
		Response response = request.waitForResponse(2000);
		assertResponseContainsExpectedPayload(response, respPayload);

		// generate new payload
		respPayload = generateRandomPayload(64);
		// Send a GET on the same resource using block2.
		Request getRequest = createRequest(GET, path, server);
		client.sendRequest(getRequest);

		// Expect get request
		server.expectRequest(CON, GET, path).storeBoth("GET").go();

		// Send response with block2
		server.sendResponse(ACK, CONTENT).loadBoth("GET").block2(0, true, 16).payload(respPayload.substring(0, 16))
				.go();

		// check we receive the next block request.
		server.expectRequest(CON, GET, path).storeBoth("BLOCK").block2(1, false, 16).go();
		// send ACK
//		server.sendEmpty(ACK).loadMID("BLOCK").go();

		// stale blockwise response

		// generate new notify payload
		respPayload = generateRandomPayload(48);

		// Send new notify response
		server.sendResponse(CON, CONTENT).loadToken("OBS").observe(2).mid(++mid).block2(0, true, 16)
				.payload(respPayload.substring(0, 16)).go();

		server.startMultiExpectation();
		// Expect ACKs
		server.expectEmpty(ACK, mid).go();
		// Expect next block request
		server.expectRequest(CON, GET, path).storeBoth("BLOCK").block2(1, false, 16).go();
		server.goMultiExpectation();

		// Send next block response
		server.sendResponse(ACK, CONTENT).loadBoth("BLOCK").block2(1, true, 16).payload(respPayload.substring(16, 32))
				.go();

		// Expect next block request
		server.expectRequest(CON, GET, path).storeBoth("BLOCK").block2(2, false, 16).go();

		// Send next (last) block response
		server.sendResponse(ACK, CONTENT).loadBoth("BLOCK").block2(2, false, 16).payload(respPayload.substring(32, 48))
				.go();

		// Check that we get the notify
		Response notification = notificationListener.waitForResponse(1000);
		assertResponseContainsExpectedPayload(notification, respPayload);

		response = getRequest.waitForResponse(2000);
		assertThat(response, is(nullValue()));
		
		// ensure, that not transfer is still ongoing
		Message message = server.receiveNextMessage(1, TimeUnit.SECONDS);
		assertThat("still receiving messages", message, is(nullValue()));
	}

	/**
	 * Verifies, If a blockwise GET is correctly interrupted by a new
	 * notification. The GET request is cancelled and the notification is taken
	 * into account.
	 * 
	 * <pre>
	 * (actual used MIDs and Tokens my vary!)
	 * ####### establish observe #############
	 * CON [MID=30668, T=a42c610c7697704e], GET, /test, observe(0)    ----->
	 * <-----   ACK [MID=30668, T=a42c610c7697704e], 2.05, 2:0/1/16, observe(1)
	 * CON [MID=30669, T=17970efc30d3db36], GET, /test, 2:1/0/16    ----->
	 * <-----   ACK [MID=30669, T=17970efc30d3db36], 2.05, 2:1/0/16
	 * ###### Send a GET, response use block2 #########
	 * CON [MID=30670, T=535e41280d7c5d6b], GET, /test    ----->
	 * <-----   ACK [MID=30670, T=535e41280d7c5d6b], 2.05, 2:0/1/16
	 * CON [MID=30671, T=535e41280d7c5d6b], GET, /test, 2:1/0/16    ----->
	 * ###### block transfer interrupted by a notificaiton ########
	 * <-----   CON [MID=8001, T=a42c610c7697704e], 2.05, 2:0/1/16, observe(2)
	 * ACK [MID=8001]   ----->
	 * CON [MID=30672, T=fe773e4dc91e1930], GET, /test, 2:1/0/16    ----->
	 * ##### Send 2nd block of the GET request, should be ignored #####
	 * <-----   ACK [MID=30671, T=535e41280d7c5d6b], 2.05, 2:1/1/16
	 * ##### Send 2nd block (last) of the notification #####
	 * <-----   ACK [MID=30672, T=fe773e4dc91e1930], 2.05, 2:1/0/16
	 * ##### ensure we get the notification and GET request is canceled #####
	 * </pre>
	 * 
	 * @throws Exception
	 */
	@Test
	public void testBlockwiseGetInterruptedByBlockwiseNotification() throws Exception {
		String path = "test";

		// Send observe request
		Request request = createRequest(GET, path, server);
		request.setObserve();
		SynchronousNotificationListener notificationListener = new SynchronousNotificationListener(request);
		client.addNotificationListener(notificationListener);
		respPayload = generateRandomPayload(32);
		client.sendRequest(request);
		server.expectRequest(CON, GET, path).storeBoth("OBS").go();
		// Send blockwise response
		server.sendResponse(ACK, CONTENT).loadBoth("OBS").observe(1).block2(0, true, 16)
				.payload(respPayload.substring(0, 16)).go();
		// Expect next block request
		server.expectRequest(CON, GET, path).storeBoth("OBS_BLOCK").block2(1, false, 16).go();
		// Send next (last) block response
		server.sendResponse(ACK, CONTENT).loadBoth("OBS_BLOCK").block2(1, false, 16)
				.payload(respPayload.substring(16, 32)).go();
		// Check that we get the response
		Response response = request.waitForResponse(2000);
		assertResponseContainsExpectedPayload(response, respPayload);
		// Observation is established.

		// Send a GET Request
		Request getRequest = createRequest(GET, path, server);
		client.sendRequest(getRequest);
		String getPayload = generateRandomPayload(32);
		server.expectRequest(CON, GET, path).storeBoth("GET").go();
		// Send blockwise response
		server.sendResponse(ACK, CONTENT).loadBoth("GET").block2(0, true, 16).payload(getPayload.substring(0, 16)).go();
		// Expect next block request
		server.expectRequest(CON, GET, path).storeBoth("GET_BLOCK").block2(1, false, 16).go();
		// Block transfer not completed.....

		// ... interrupted by a new notification
		String notifPayload = generateRandomPayload(32);
		server.sendResponse(CON, CONTENT).loadToken("OBS").observe(2).mid(++mid).block2(0, true, 16)
				.payload(notifPayload.substring(0, 16)).go();
		// Expect ACK and Next Block request
		server.startMultiExpectation();
		server.expectEmpty(ACK, mid).go();
		server.expectRequest(CON, GET, path).storeBoth("BLOCK").block2(1, false, 16).go();
		server.goMultiExpectation();

		// Send 2nd block of GET request (should be ignored)
		server.sendResponse(ACK, CONTENT).loadBoth("GET_BLOCK").block2(1, false, 16)
				.payload(getPayload.substring(16, 32)).go();

		// Send 2nd block of notification
		server.sendResponse(ACK, CONTENT).loadBoth("BLOCK").block2(1, false, 16).payload(notifPayload.substring(16, 32))
				.go();
		Response notification = notificationListener.waitForResponse(1000);
		assertResponseContainsExpectedPayload(notification, notifPayload);

		// Check the GET request is canceled.
		assertTrue(getRequest.isCanceled());
	}
}
