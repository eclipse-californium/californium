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
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import static org.eclipse.californium.TestTools.*;
import static org.eclipse.californium.core.coap.CoAP.Code.GET;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.Type.*;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.*;
import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.logging.Handler;
import java.util.logging.Logger;

import org.eclipse.californium.category.Large;
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

	static Logger logger;
	static Logger cflog;
	static {
        Logger globalLogger = Logger.getLogger("");
        globalLogger.setLevel(java.util.logging.Level.OFF);
        for (Handler handler : globalLogger.getHandlers()) {
            handler.setLevel(java.util.logging.Level.ALL);
        }

		cflog = Logger.getLogger("org.eclipse.californium.core.network");
		cflog.setLevel(java.util.logging.Level.FINER);
        for (Handler handler : cflog.getHandlers()) {
            handler.setLevel(java.util.logging.Level.ALL);
        }

		// logger = Logger.getLogger(BaseMatcher.class.getCanonicalName());
		// logger.setLevel(java.util.logging.Level.FINER);
		// for (Handler handler : logger.getHandlers()) {
		// handler.setLevel(java.util.logging.Level.ALL);
		// }
	}
	
	
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
		client.cancelObservation(request.getDestinationEndpoint(), request.getToken());
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
	 * transfer and receiving a notification without blockwise at the same time.
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
		// Send complete response and blockwise response at the same time \o/ !!
		server.sendEmpty(ACK).loadMID("OBS_REQ").go();
		int mid_block = 111;
		server.sendResponse(CON, CONTENT).loadToken("OBS_TOK").observe(1).mid(mid_block).block2(0, true, 16)
				.payload(respPayload.substring(0, 16)).go();
		int mid_notif = 222;
		server.sendResponse(CON, CONTENT).loadToken("OBS_TOK").observe(2).mid(mid_notif)
				.payload(notifpayload)
				.go();

		// Expect for block request and ACKs
		server.expectEmpty(ACK, mid_block).go();
		server.expectRequest(CON, GET, path).storeMID("BLOCK_TOK").storeToken("SECOND_BLOCK").block2(1, false, 16)
				.go();
		server.expectEmpty(ACK, mid_notif).go();

		// Send next block
		server.sendResponse(ACK, CONTENT).loadMID("BLOCK_TOK").loadToken("SECOND_BLOCK").block2(1, true, 16)
				.payload(respPayload.substring(16, 32)).go();

		// Check that we get the most recent response (with the higher observe
		// option value)
		Response response = request.waitForResponse();
		assertResponseContainsExpectedPayload(response, notifpayload);


		// Send new notif without block
		notifpayload = generateRandomPayload(8);
		server.sendResponse(CON, CONTENT).loadToken("OBS_TOK").observe(3).mid(++mid_notif)
				.payload(notifpayload).go();
		response = notificationListener.waitForResponse(1000);
		assertResponseContainsExpectedPayload(response, notifpayload);

		// Send new notif without block
		server.sendResponse(CON, CONTENT).loadToken("OBS_TOK").observe(4).mid(++mid_notif).payload(notifpayload).go();
		response = notificationListener.waitForResponse(1000);
		assertResponseContainsExpectedPayload(response, notifpayload);

		printServerLog(clientInterceptor);
	}

	@Test
	public void testSameTokenForDifferentPeer() throws Exception {
		System.out.println("Same Token can be used by different peer:");
		respPayload = generatePayload(1);
		byte[] sameToken = generateNextToken();
		String path = "test";
		int obs = 100;
		LockstepEndpoint server2 = createLockstepEndpoint(client.getAddress());

		// established observe relation
		Request request = createRequest(GET, path, server);
		request.setToken(sameToken);
		SynchronousNotificationListener notificationListener = new SynchronousNotificationListener(request);
		client.addNotificationListener(notificationListener);
		request.setObserve();
		client.sendRequest(request);

		server.expectRequest(CON, GET, path).storeMID("A").storeToken("B").observe(0).go();
		server.sendResponse(ACK, CONTENT).loadMID("A").loadToken("B").payload(respPayload).go();
		Thread.sleep(50);
		Response response = request.waitForResponse(1000);
		assertResponseContainsExpectedPayload(response, respPayload);

		// send a notification
		respPayload = generatePayload(2);
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(obs).go();
		server.expectEmpty(ACK, mid).go();
		Response notification1 = notificationListener.waitForResponse(1000);
		assertResponseContainsExpectedPayload(notification1, respPayload);
		assertNumberOfReceivedNotifications(notificationListener, 1, true);

		// established observe relation with the same token to another server
		Request request2 = createRequest(GET, path, server2);
		request2.setToken(sameToken);
		SynchronousNotificationListener notificationListener2 = new SynchronousNotificationListener(request2);
		client.addNotificationListener(notificationListener2);
		request2.setObserve();
		client.sendRequest(request2);
		System.out.println(server2.getPort());

		respPayload = generatePayload(3);
		server2.expectRequest(CON, GET, path).storeMID("A").storeToken("B").observe(0).go();
		server2.sendResponse(ACK, CONTENT).loadMID("A").loadToken("B").payload(respPayload).go();
		Thread.sleep(50);
		Response response2 = request2.waitForResponse(1000);
		assertResponseContainsExpectedPayload(response2, respPayload);

		// send a notification from the 2nd server
		respPayload = generatePayload(4);
		server2.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(++obs).go();
		server2.expectEmpty(ACK, mid).go();
		Response notification2 = notificationListener2.waitForResponse(1000);
		assertResponseContainsExpectedPayload(notification2, respPayload);
		assertNumberOfReceivedNotifications(notificationListener2, 1, true);

		// send a notification from the both servers
		respPayload = generatePayload(5);
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(++obs).go();
		server.expectEmpty(ACK, mid).go();
		String respPayload2 = generatePayload(6);
		server2.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload2).mid(++mid).observe(++obs).go();
		server2.expectEmpty(ACK, mid).go();

		// check each notification is handle by the right notification listener.
		Response notification3 = notificationListener.waitForResponse(1000);
		assertResponseContainsExpectedPayload(notification3, respPayload);
		assertNumberOfReceivedNotifications(notificationListener, 1, true);

		Response notification4 = notificationListener2.waitForResponse(1000);
		assertResponseContainsExpectedPayload(notification4, respPayload2);
		assertNumberOfReceivedNotifications(notificationListener2, 1, true);

		printServerLog(clientInterceptor);
	}
}
