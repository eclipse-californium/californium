/*******************************************************************************
 * Copyright (c) 2016 Sierra Wireless and others.
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
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import static org.eclipse.californium.core.coap.CoAP.Code.GET;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.Type.*;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.observe.InMemoryObservationStore;
import org.eclipse.californium.core.observe.NotificationListener;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Medium.class)
public class ClusteringTest {

	private static final String TOKEN_ID = "T";
	private static final String path = "test";
	private static NetworkConfig CONFIG;

	private ClientBlockwiseInterceptor clientInterceptor;
	private LockstepEndpoint server;

	private Endpoint client1;
	private Endpoint client2;

	private int mid = 8000;
	private int observeCounter;

	private InMemoryObservationStore store;

	private SynchronousNotificationListener notificationListener1;
	private SynchronousNotificationListener notificationListener2;

	@BeforeClass
	public static void init() {
		System.out.println(System.lineSeparator() + "Start " + ClusteringTest.class.getSimpleName());
		CONFIG = new NetworkConfig()
				.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 16)
				.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 16)
				.setInt(NetworkConfig.Keys.ACK_TIMEOUT, 200) // client retransmits after 200 ms
				.setFloat(NetworkConfig.Keys.ACK_RANDOM_FACTOR, 1f)
				.setFloat(NetworkConfig.Keys.ACK_TIMEOUT_SCALE, 1f);
	}

	@Before
	public void setupClient() throws IOException {

		store = new InMemoryObservationStore();
		clientInterceptor = new ClientBlockwiseInterceptor();

		notificationListener1 = new SynchronousNotificationListener();
		client1 = createAndStartClientEndpoint(notificationListener1, clientInterceptor);
		System.out.println("Client 1 binds to port " + client1.getAddress().getPort());

		notificationListener2 = new SynchronousNotificationListener();
		client2 = createAndStartClientEndpoint(notificationListener2, clientInterceptor);
		System.out.println("Client 2 binds to port " + client2.getAddress().getPort());
	}

	@After
	public void shutdownClient() {
		System.out.println();
		client1.destroy();
		client2.destroy();
	}

	@AfterClass
	public static void finish() {
		System.out.println("End " + ClusteringTest.class.getSimpleName());
	}

	private Endpoint createAndStartClientEndpoint(final NotificationListener listener, final ClientBlockwiseInterceptor interceptor) throws IOException {
		Endpoint client = new CoapEndpoint(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), CONFIG, store);
		client.addNotificationListener(listener);
		client.addInterceptor(interceptor);
		client.addInterceptor(new MessageTracer());
		client.start();
		return client;
	}

	@Test
	public void testNotificationFailOver() throws Exception {
		System.out.println(System.lineSeparator() + "Fail over notifications from client 1 to client 2 and back");

		// GIVEN a resource on server observed by client 1
		givenAResourceObservedByClient1(generateRandomPayload(10));

		// WHEN client 1 fails and server sends notification to client 2 instead
		System.out.println(System.lineSeparator() + "Crashing client 1...");
		client1.destroy();
		System.out.println("Failing over notifications to client 2...");
		String respPayload = generateRandomPayload(10); // changed
		sendNotificationToClient(client2, respPayload);

		// THEN client 2 delivers the payload to the registered notification listener
		assertClientDeliversNotificationToListener(notificationListener2, respPayload);
		printServerLog(clientInterceptor);
		System.out.println("Client 2 received notification");

		// WHEN client 2 fails and client 1 recovers and server sends notification to client 1 again
		System.out.println(System.lineSeparator() + "Crashing client 2...");
		client2.destroy();
		System.out.println(System.lineSeparator() + "Recovering client 1...");
		client1 = createAndStartClientEndpoint(notificationListener1, clientInterceptor);
		System.out.println();
		System.out.println(System.lineSeparator() + "Failing over notifications back to client 1");
		respPayload = generateRandomPayload(10); // changed
		sendNotificationToClient(client1, respPayload);

		// THEN client1 delivers the payload to the registered notification listener
		assertClientDeliversNotificationToListener(notificationListener1, respPayload);
		printServerLog(clientInterceptor);
		System.out.println("Client 1 received notification");
	}

	@Test
	public void testBlockwiseNotificationFailOver() throws Exception {
		System.out.println(System.lineSeparator() + "Fail over blockwise notifications from client 1 to client 2 and back");

		// GIVEN a resource on server observed by client 1
		givenAResourceObservedByClient1(generateRandomPayload(10));

		// WHEN the server sends a notification using blockwise transfer to client 1
		String respPayload = generateRandomPayload(40); // changed
		System.out.println();
		System.out.println(System.lineSeparator() + "Server sends blockwise observe response to client 1 [" + respPayload + "]");
		server.setDestination(client1.getAddress());
		server.sendResponse(CON, CONTENT).loadToken(TOKEN_ID).mid(++mid).observe(observeCounter++).block2(0, true, 16)
				.payload(respPayload.substring(0, 16)).go();
		server.expectEmpty(ACK, mid).go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 16).payload(respPayload.substring(16, 32)).go();
		server.expectRequest(CON, GET, path).storeBoth("C").block2(2, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("C").block2(2, false, 16).payload(respPayload.substring(32, 40)).go();
		Thread.sleep(200);

		// THEN client 1 delivers the payload to the registered notification listener
		assertClientDeliversNotificationToListener(notificationListener1, respPayload);
		printServerLog(clientInterceptor);
		System.out.println("Client 1 received blockwise notification");

		// WHEN client 1 fails and server sends next notification using blockwise transfer to client 2
		System.out.println(System.lineSeparator() + "Crashing client 1...");
		client1.destroy();
		System.out.println("Failing over notifications to client 2...");
		respPayload = generateRandomPayload(40); // changed
		System.out.println(System.lineSeparator() + "Server sends blockwise observe response to client 2 [" + respPayload + "]");
		server.setDestination(client2.getAddress());
		server.sendResponse(CON, CONTENT).loadToken(TOKEN_ID).mid(++mid).observe(observeCounter++).block2(0, true, 16)
				.payload(respPayload.substring(0, 16)).go();
		server.expectEmpty(ACK, mid).go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 16).payload(respPayload.substring(16, 32)).go();
		server.expectRequest(CON, GET, path).storeBoth("C").block2(2, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("C").block2(2, false, 16).payload(respPayload.substring(32, 40)).go();
		Thread.sleep(200);

		// THEN client 2 delivers the payload to the registered notification listener
		assertClientDeliversNotificationToListener(notificationListener2, respPayload);
		printServerLog(clientInterceptor);
		System.out.println("Client 2 received blockwise notification");
	}

	@Test
	public void testCancellingNotification() throws Exception {
		System.out.println(System.lineSeparator() + "Cancel failed over observation:");

		// GIVEN a resource on server observed by client 1
		byte[] requestToken = givenAResourceObservedByClient1(generateRandomPayload(10));

		// WHEN client 1 fails and server sends notification to client 2 instead
		System.out.println(System.lineSeparator() + "Crashing client 1...");
		client1.destroy();
		System.out.println(System.lineSeparator() + "Failing over to client 2...");
		// server send new response to client 2
		System.out.println("Server sends Observe response to client 2...");
		String respPayload = generateRandomPayload(10); // changed
		sendNotificationToClient(client2, respPayload);

		// THEN client 2 successfully delivers the payload to the registered notification listener
		assertClientDeliversNotificationToListener(notificationListener2, respPayload);
		printServerLog(clientInterceptor);
		System.out.println("Client 2 received notification");

		// WHEN client 2 cancels observation and next notification arrives from server
		System.out.println();
		System.out.println(System.lineSeparator() + "Now cancelling observation from client 2");
		client2.cancelObservation(requestToken);

		System.out.println();
		System.out.println(System.lineSeparator() + "Server sends notification to client 2...");
		respPayload = generateRandomPayload(10); // changed
		server.setDestination(client2.getAddress());
		server.sendResponse(CON, CONTENT).loadToken(TOKEN_ID).payload(respPayload).mid(++mid).observe(observeCounter).go();

		// THEN client 2 rejects the notification and cancels the observation on the server
		server.expectEmpty(RST, mid).go();
		printServerLog(clientInterceptor);
		System.out.println("Client 2 has rejected received notification");

		// WHEN client 1 recovers and the next notification arrives from server
		client2.destroy();
		System.out.println(System.lineSeparator() + "Recovering client 1...");
		client1 = createAndStartClientEndpoint(notificationListener1, clientInterceptor);

		// server send new response to client 1
		System.out.println();
		System.out.println(System.lineSeparator() + "Server sends notification to recovered client 1...");
		respPayload = generateRandomPayload(10); // changed
		server.setDestination(client1.getAddress());
		server.sendResponse(CON, CONTENT).loadToken(TOKEN_ID).payload(respPayload).mid(++mid).observe(++observeCounter).go();
		server.expectEmpty(RST, mid).go();
		printServerLog(clientInterceptor);
		System.out.println("Recovered client 1 has rejected received notification");
	}

	private byte[] givenAResourceObservedByClient1(final String expectedResponse) throws Exception {
		server = createLockstepEndpoint(client1.getAddress());
		observeCounter = 100;

		// send observe request from client 1
		System.out.println(System.lineSeparator() + "Establishing observation from client 1 ...");
		Request request = createRequest(GET, path, server);
		request.setObserve();
		client1.sendRequest(request);

		// server wait for request and send response
		System.out.println(System.lineSeparator() + "Server sends Observe response to client 1.");
		server.expectRequest(CON, GET, path).storeMID("MID").storeToken(TOKEN_ID).observe(0).go();
		server.sendEmpty(ACK).loadMID("MID").go();
		server.sendResponse(CON, CONTENT).loadToken(TOKEN_ID).payload(expectedResponse).mid(++mid).observe(++observeCounter).go();
		server.expectEmpty(ACK, mid).go();
		Response response = request.waitForResponse(1000);

		printServerLog(clientInterceptor);
		assertClientReceivedExpectedPayload(expectedResponse, response);
		assertNotNull("ObservationStore does not contain token for new observation: ", store.get(response.getToken()));
		System.out.println("Observe relation established with client 1");
		return request.getToken();
	}

	private void assertClientDeliversNotificationToListener(final SynchronousNotificationListener listener,
			final String expectedPayload) throws Exception {
		Response receivedResponse =  listener.waitForResponse(1000);
		assertClientReceivedExpectedPayload(expectedPayload, receivedResponse);
	}

	private void assertClientReceivedExpectedPayload(final String expectedPayload, final Response receivedResponse) {
		assertNotNull("Client received no response", receivedResponse);
		assertEquals("Client received wrong response code", CONTENT, receivedResponse.getCode());
		assertEquals("Client received wrong payload", expectedPayload, receivedResponse.getPayloadString());
	}

	private void sendNotificationToClient(final Endpoint client, final String payload) throws Exception {
		server.setDestination(client.getAddress());
		server.sendResponse(CON, CONTENT).loadToken(TOKEN_ID).payload(payload).mid(++mid).observe(++observeCounter).go();
		server.expectEmpty(ACK, mid).go();
	}
}
