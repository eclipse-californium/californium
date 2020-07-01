/*******************************************************************************
 * Copyright (c) 2016 Sierra Wireless and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 *    
 * Contributors:
 *    Sierra Wireless - initial implementation
 *    Achim Kraus (Bosch Software Innovations GmbH) - use localhost for windows compatibility
 *                                                    sending to "any" doesn't work on windows
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CoapNetworkRule for
 *                                                    setup of test-network
 *    Achim Kraus (Bosch Software Innovations GmbH) - adjust to use Token
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import static org.eclipse.californium.core.coap.CoAP.Code.GET;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.Type.ACK;
import static org.eclipse.californium.core.coap.CoAP.Type.CON;
import static org.eclipse.californium.core.coap.CoAP.Type.RST;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.observe.InMemoryObservationStore;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Verifies fail-over behavior between different servers.
 *
 */
@Category(Medium.class)
public class ClusteringTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private LockstepEndpoint server;

	private Endpoint client1;
	private Endpoint client2;
	private int mid = 8000;
	private String respPayload;
	private ClientBlockwiseInterceptor clientInterceptor = new ClientBlockwiseInterceptor();
	private InMemoryObservationStore store;
	private SynchronousNotificationListener notificationListener1;
	private SynchronousNotificationListener notificationListener2;

	@Before
	public void setup() throws IOException {

		NetworkConfig config = network.createStandardTestConfig()
				.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 16)
				.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 16)
				.setInt(NetworkConfig.Keys.ACK_TIMEOUT, 200) // client retransmits after 200ms
				.setFloat(NetworkConfig.Keys.ACK_RANDOM_FACTOR, 1f)
				.setFloat(NetworkConfig.Keys.ACK_TIMEOUT_SCALE, 1f);

		store = new InMemoryObservationStore(config);

		notificationListener1 = new SynchronousNotificationListener();
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		builder.setNetworkConfig(config);
		builder.setObservationStore(store);
		client1 = builder.build();
		client1.addNotificationListener(notificationListener1);
		client1.addInterceptor(clientInterceptor);
		client1.addInterceptor(new MessageTracer());
		client1.start();
		cleanup.add(client1);
		System.out.println("Client 1 binds to port " + client1.getAddress().getPort());

		notificationListener2 = new SynchronousNotificationListener();
		builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		builder.setNetworkConfig(config);
		builder.setObservationStore(store);
		client2 = builder.build();
		client2.addNotificationListener(notificationListener2);
		client2.addInterceptor(clientInterceptor);
		client2.addInterceptor(new MessageTracer());
		client2.start();
		cleanup.add(client2);
		System.out.println("Client 2 binds to port " + client2.getAddress().getPort());

		server = new LockstepEndpoint();
		server.setDestination(client1.getAddress());
		cleanup.add(server);
	}

	@Test
	public void testNotification() throws Exception {

		System.out.println(System.lineSeparator() + "Observe:");
		respPayload = TestTools.generateRandomPayload(10);
		String path = "test";
		int obs = 100;

		assertTrue(store.isEmpty());

		// send observe request from client 1
		System.out.println(System.lineSeparator() + "Sending Observe Request to client 1 ...");
		Request request = createRequest(GET, path);
		request.setObserve();
		client1.sendRequest(request);

		// server wait for request and send response
		System.out.println(System.lineSeparator() + "Server send Observe response to client 1.");
		server.expectRequest(CON, GET, path).storeMID("A").storeToken("B").observe(0).go();
		server.sendEmpty(ACK).loadMID("A").go();
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(++obs).go();
		server.expectEmpty(ACK, mid).go();
		Thread.sleep(50);
		Response response = request.waitForResponse(1000);

		printServerLog();
		assertClientReceivedExpectedResponse(1, CONTENT, respPayload, response);
		assertFalse("Store does not contain the new Observe Request:", store.isEmpty());
		System.out.println("Relation established with client 1");

		// server send new response to client 2
		System.out.println(System.lineSeparator() + "Server send Observe response to client 2.");
		respPayload = TestTools.generateRandomPayload(10); // changed
		server.setDestination(client2.getAddress());
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(++obs).go();
		server.expectEmpty(ACK, mid).go();
		response = notificationListener2.waitForResponse(1000);

		printServerLog();
		assertClientReceivedExpectedResponse(2, CONTENT, respPayload, response);
		System.out.println("Response received");

		// server send new response to client 1
		System.out.println();
		System.out.println(System.lineSeparator() + "Server send Observe response to client 1.");
		respPayload = TestTools.generateRandomPayload(10); // changed
		server.setDestination(client1.getAddress());
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(++obs).go();
		server.expectEmpty(ACK, mid).go();
		response = notificationListener1.waitForResponse(1000);

		printServerLog();
		assertClientReceivedExpectedResponse(1, CONTENT, respPayload, response);
		System.out.println("Response received");
	}

	@Test
	public void testNotificationWithBlockWise() throws Exception {

		System.out.println(System.lineSeparator() + "Observe with blockwise:");
		respPayload = TestTools.generateRandomPayload(40);
		String path = "test";
		int obs = 100;

		assertTrue(store.isEmpty());

		// send observe request from client 1
		System.out.println(System.lineSeparator() + "Sending Observe Request to client 1 ...");
		Request request = createRequest(GET, path);
		request.setObserve();
		client1.sendRequest(request);

		// server wait for request and send response
		System.out.println(System.lineSeparator() + "Server send Observe response to client 1.");
		server.expectRequest(CON, GET, path).storeBoth("A").storeToken("T").observe(0).go();
		server.sendResponse(ACK, CONTENT).loadBoth("A").observe(obs++).block2(0, true, 16).payload(respPayload.substring(0, 16)).go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 16).payload(respPayload.substring(16, 32)).go();
		server.expectRequest(CON, GET, path).storeBoth("C").block2(2, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("C").block2(2, false, 16).payload(respPayload.substring(32, 40)).go();
		Thread.sleep(50);
		Response response = request.waitForResponse(1000);

		printServerLog();
		assertClientReceivedExpectedResponse(1, CONTENT, respPayload, response);
		assertFalse("Store does not contain the new Observe Request:", store.isEmpty());
		System.out.println("Relation established with client 1");

		// server send new response to client 2
		System.out.println(System.lineSeparator() + "Server send Observe response to client 2.");
		respPayload = TestTools.generateRandomPayload(40); // changed
		server.setDestination(client2.getAddress());
		server.sendResponse(CON, CONTENT).loadToken("T").mid(++mid).observe(obs++).block2(0, true, 16)
				.payload(respPayload.substring(0, 16)).go();
		server.startMultiExpectation();
		server.expectEmpty(ACK, mid).go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 16).go();
		server.goMultiExpectation();
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 16).payload(respPayload.substring(16, 32)).go();
		server.expectRequest(CON, GET, path).storeBoth("C").block2(2, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("C").block2(2, false, 16).payload(respPayload.substring(32, 40)).go();
		response = notificationListener2.waitForResponse(1000);

		printServerLog();
		assertClientReceivedExpectedResponse(2, CONTENT, respPayload, response);
		System.out.println("Response received");

		// server send new response to client 1
		System.out.println();
		System.out.println(System.lineSeparator() + "Server send Observe response to client 1.");
		respPayload = TestTools.generateRandomPayload(40); // changed
		server.setDestination(client1.getAddress());
		server.sendResponse(CON, CONTENT).loadToken("T").mid(++mid).observe(obs++).block2(0, true, 16)
				.payload(respPayload.substring(0, 16)).go();
		server.startMultiExpectation();
		server.expectEmpty(ACK, mid).go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 16).go();
		server.goMultiExpectation();
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 16).payload(respPayload.substring(16, 32)).go();
		server.expectRequest(CON, GET, path).storeBoth("C").block2(2, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("C").block2(2, false, 16).payload(respPayload.substring(32, 40)).go();
		response = notificationListener1.waitForResponse(1000);

		printServerLog();
		assertClientReceivedExpectedResponse(1, CONTENT, respPayload, response);
		System.out.println("Response received");
	}

	@Test
	public void testCancellingNotification() throws Exception {

		System.out.println(System.lineSeparator() + "Observe:");
		respPayload = TestTools.generateRandomPayload(10);
		String path = "test";
		int obs = 100;

		assertTrue(store.isEmpty());

		// send observe request from client 1
		System.out.println(System.lineSeparator() + "Sending Observe Request to client 1 ...");
		Request request = createRequest(GET, path);
		request.setObserve();
		client1.sendRequest(request);

		// server wait for request and send response
		System.out.println(System.lineSeparator() + "Server send Observe response to client 1.");
		server.expectRequest(CON, GET, path).storeMID("A").storeToken("B").observe(0).go();
		server.sendEmpty(ACK).loadMID("A").go();
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(++obs).go();
		server.expectEmpty(ACK, mid).go();
		Thread.sleep(50);
		Response response = request.waitForResponse(1000);

		printServerLog();
		assertClientReceivedExpectedResponse(1, CONTENT, respPayload, response);
		assertFalse("Store does not contain the new Observe Request:", store.isEmpty());
		System.out.println("Relation established with client 1");
		Thread.sleep(1000);

		// server send new response to client 2
		System.out.println(System.lineSeparator() + "Server send Observe response to client 2.");
		respPayload = TestTools.generateRandomPayload(10); // changed
		server.setDestination(client2.getAddress());
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(++obs).go();
		server.expectEmpty(ACK, mid).go();
		response = notificationListener2.waitForResponse(1000);

		printServerLog();
		assertClientReceivedExpectedResponse(2, CONTENT, respPayload, response);
		System.out.println("Response received");

		// server send new response to client 1
		System.out.println();
		System.out.println(System.lineSeparator() + "Server send Observe response to client 1.");
		respPayload = TestTools.generateRandomPayload(10); // changed
		server.setDestination(client1.getAddress());
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(++obs).go();
		server.expectEmpty(ACK, mid).go();
		response = notificationListener1.waitForResponse(1000);

		printServerLog();
		assertClientReceivedExpectedResponse(1, CONTENT, respPayload, response);
		System.out.println("Response received");

		// cancel observation
		System.out.println();
		System.out.println(System.lineSeparator() + "Cancel Observation.");
		store.remove(request.getToken());

		// server send new response to client 1
		System.out.println();
		System.out.println(System.lineSeparator() + "Server send Observe response to client 1.");
		respPayload = TestTools.generateRandomPayload(10); // changed
		server.setDestination(client1.getAddress());
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(++obs).go();
		server.expectEmpty(RST, mid).go();
		printServerLog();

		// server send new response to client 2
		System.out.println();
		System.out.println(System.lineSeparator() + "Server send Observe response to client 2.");
		respPayload = TestTools.generateRandomPayload(10); // changed
		server.setDestination(client2.getAddress());
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(obs).go();
		server.expectEmpty(RST, mid).go();
		printServerLog();
	}

	private static void assertClientReceivedExpectedResponse(
			int clientNo, ResponseCode expectedCode, String expectedPayload, Response response) {
		assertNotNull(String.format("Client %d received no response", clientNo), response);
		assertThat(String.format("Client %d received wrong response code", clientNo), response.getCode(), is(CONTENT));
		assertThat(String.format("Client %d received wrong payload", clientNo), response.getPayloadString(), is(expectedPayload));
	}

	private Request createRequest(Code code, String path) throws Exception {

		Request request = new Request(code);
		String uri = TestTools.getUri(server.getSocketAddress(), path);
		request.setURI(uri);
		return request;
	}

	private void printServerLog() {
		System.out.print(clientInterceptor.toString());
		clientInterceptor.clear();
	}
}
