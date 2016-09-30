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
import static org.eclipse.californium.core.coap.CoAP.Type.ACK;
import static org.eclipse.californium.core.coap.CoAP.Type.CON;
import static org.eclipse.californium.core.coap.CoAP.Type.RST;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Random;

import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.InMemoryRandomTokenProvider;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.observe.InMemoryObservationStore;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class ClusteringTest {

	private static boolean RANDOM_PAYLOAD_GENERATION = true;

	private LockstepEndpoint server;

	private Endpoint client1;
	private int clientPort1;

	private int mid = 8000;

	private String respPayload;

	private ClientBlockwiseInterceptor clientInterceptor = new ClientBlockwiseInterceptor();

	private CoapEndpoint client2;

	private int clientPort2;

	private InMemoryObservationStore store;
	
	private InMemoryRandomTokenProvider tokenProvider;

	private SynchronousNotificationListener notificationListener1;

	private SynchronousNotificationListener notificationListener2;

	@Before
	public void setupClient() throws IOException {
		System.out.println("\nStart " + getClass().getSimpleName());

		NetworkConfig config = new NetworkConfig().setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 16)
				.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 16).setInt(NetworkConfig.Keys.ACK_TIMEOUT, 200) // client
																													// retransmits
																													// after
																													// 200
																													// ms
				.setFloat(NetworkConfig.Keys.ACK_RANDOM_FACTOR, 1f).setFloat(NetworkConfig.Keys.ACK_TIMEOUT_SCALE, 1f);

		store = new InMemoryObservationStore();
		tokenProvider = new InMemoryRandomTokenProvider(config);
		notificationListener1 = new SynchronousNotificationListener();

		client1 = new CoapEndpoint(new InetSocketAddress(0), config, store, tokenProvider);
		client1.addNotificationListener(notificationListener1);
		client1.addInterceptor(clientInterceptor);
		client1.addInterceptor(new MessageTracer());
		client1.start();
		clientPort1 = client1.getAddress().getPort();
		System.out.println("Client 1 binds to port " + clientPort1);

		notificationListener2 = new SynchronousNotificationListener();
		client2 = new CoapEndpoint(new InetSocketAddress(0), config, store, tokenProvider);
		client2.addNotificationListener(notificationListener2);
		client2.addInterceptor(clientInterceptor);
		client2.addInterceptor(new MessageTracer());
		client2.start();
		clientPort2 = client2.getAddress().getPort();
		System.out.println("Client 2 binds to port " + clientPort2);
	}

	@After
	public void shutdownClient() {
		System.out.println();
		client1.destroy();
		client2.destroy();
		System.out.println("End " + getClass().getSimpleName());
	}

	@Test
	public void testNotification() throws Exception {
		System.out.println("\nObserve:");
		respPayload = generatePayload(10);
		String path = "test";
		server = createLockstepEndpoint();
		int obs = 100;

		// Make sure the ObserveRequestStore is empty
		Assert.assertTrue(store.isEmpty());

		// send observe request from client 1
		System.out.println("\nSending Observe Request to client 1 ...");
		Request request = createRequest(GET, path);
		request.setObserve();
		client1.sendRequest(request);

		// server wait for request and send response
		System.out.println("\nServer send Observe response to client 1.");
		server.expectRequest(CON, GET, path).storeMID("A").storeToken("B").observe(0).go();
		server.sendEmpty(ACK).loadMID("A").go();
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(++obs).go();
		server.expectEmpty(ACK, mid).go();
		Thread.sleep(50);
		Response response = request.waitForResponse(1000);

		printServerLog();
		Assert.assertNotNull("Client 1 received no response", response);
		Assert.assertEquals("Client 1 received wrong response code:", CONTENT, response.getCode());
		Assert.assertEquals("Client 1 received wrong payload:", respPayload, response.getPayloadString());
		Assert.assertTrue("Store does not contain the new Observe Request:", !store.isEmpty());
		System.out.println("Relation established with client 1");

		// server send new response to client 2
		System.out.println("\nServer send Observe response to client 2.");
		respPayload = generatePayload(10); // changed
		server.setDestination(client2.getAddress());
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(++obs).go();
		server.expectEmpty(ACK, mid).go();
		response = notificationListener2.waitForResponse(1000);

		printServerLog();
		Assert.assertNotNull("Client 2 received no response", response);
		Assert.assertEquals("Client 2 received wrong response code:", CONTENT, response.getCode());
		Assert.assertEquals("Client 2 received wrong payload:", respPayload, response.getPayloadString());
		System.out.println("Response received");

		// server send new response to client 1
		System.out.println();
		System.out.println("\nServer send Observe response to client 1.");
		respPayload = generatePayload(10); // changed
		server.setDestination(client1.getAddress());
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(++obs).go();
		server.expectEmpty(ACK, mid).go();
		response = notificationListener1.waitForResponse(1000);

		printServerLog();
		Assert.assertNotNull("Client 1 received no response", response);
		Assert.assertEquals("Client 1 received wrong response code:", CONTENT, response.getCode());
		Assert.assertEquals("Client 1 received wrong payload:", respPayload, response.getPayloadString());
		System.out.println("Response received");
	}

	@Test
	public void testNotificationWithBlockWise() throws Exception {
		System.out.println("\nObserve with blockwise:");
		respPayload = generatePayload(40);
		String path = "test";
		server = createLockstepEndpoint();
		int obs = 100;

		// Make sure the ObserveRequestStore is empty
		store.clear();
		Assert.assertTrue(store.isEmpty());

		// send observe request from client 1
		System.out.println("\nSending Observe Request to client 1 ...");
		Request request = createRequest(GET, path);
		request.setObserve();
		client1.sendRequest(request);

		// server wait for request and send response
		System.out.println("\nServer send Observe response to client 1.");
		server.expectRequest(CON, GET, path).storeBoth("A").storeToken("T").observe(0).go();
		server.sendResponse(ACK, CONTENT).loadBoth("A").observe(obs++).block2(0, true, 16).payload(respPayload.substring(0, 16)).go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 16).payload(respPayload.substring(16, 32)).go();
		server.expectRequest(CON, GET, path).storeBoth("C").block2(2, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("C").block2(2, false, 16).payload(respPayload.substring(32, 40)).go();
		Thread.sleep(50);
		Response response = request.waitForResponse(1000);

		printServerLog();
		Assert.assertNotNull("Client 1 received no response", response);
		Assert.assertEquals("Client 1 received wrong response code:", CONTENT, response.getCode());
		Assert.assertEquals("Client 1 received wrong payload:", respPayload, response.getPayloadString());
		Assert.assertTrue("Store does not contain the new Observe Request:", !store.isEmpty());
		System.out.println("Relation established with client 1");

		// server send new response to client 2
		System.out.println("\nServer send Observe response to client 2.");
		respPayload = generatePayload(40); // changed
		server.setDestination(client2.getAddress());
		server.sendResponse(CON, CONTENT).loadToken("T").mid(++mid).observe(obs++).block2(0, true, 16)
				.payload(respPayload.substring(0, 16)).go();
		server.expectEmpty(ACK, mid).go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 16).payload(respPayload.substring(16, 32)).go();
		server.expectRequest(CON, GET, path).storeBoth("C").block2(2, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("C").block2(2, false, 16).payload(respPayload.substring(32, 40)).go();
		response = notificationListener2.waitForResponse(1000);

		printServerLog();
		Assert.assertNotNull("Client 2 received no response", response);
		Assert.assertEquals("Client 2 received wrong response code:", CONTENT, response.getCode());
		Assert.assertEquals("Client 2 received wrong payload:", respPayload, response.getPayloadString());
		System.out.println("Response received");

		// server send new response to client 1
		System.out.println();
		System.out.println("\nServer send Observe response to client 1.");
		respPayload = generatePayload(40); // changed
		server.setDestination(client1.getAddress());
		server.sendResponse(CON, CONTENT).loadToken("T").mid(++mid).observe(obs++).block2(0, true, 16)
				.payload(respPayload.substring(0, 16)).go();
		server.expectEmpty(ACK, mid).go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 16).payload(respPayload.substring(16, 32)).go();
		server.expectRequest(CON, GET, path).storeBoth("C").block2(2, false, 16).go();
		server.sendResponse(ACK, CONTENT).loadBoth("C").block2(2, false, 16).payload(respPayload.substring(32, 40)).go();
		response = notificationListener1.waitForResponse(1000);


		printServerLog();
		Assert.assertNotNull("Client 1 received no response", response);
		Assert.assertEquals("Client 1 received wrong response code:", CONTENT, response.getCode());
		Assert.assertEquals("Client 1 received wrong payload:", respPayload, response.getPayloadString());
		System.out.println("Response received");
	}

	@Test
	public void testCancellingNotification() throws Exception {
		System.out.println("\nObserve:");
		respPayload = generatePayload(10);
		String path = "test";
		server = createLockstepEndpoint();
		int obs = 100;

		// Make sure the ObserveRequestStore is empty
		store.clear();
		Assert.assertTrue(store.isEmpty());

		// send observe request from client 1
		System.out.println("\nSending Observe Request to client 1 ...");
		Request request = createRequest(GET, path);
		request.setObserve();
		client1.sendRequest(request);

		// server wait for request and send response
		System.out.println("\nServer send Observe response to client 1.");
		server.expectRequest(CON, GET, path).storeMID("A").storeToken("B").observe(0).go();
		server.sendEmpty(ACK).loadMID("A").go();
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(++obs).go();
		server.expectEmpty(ACK, mid).go();
		Thread.sleep(50);
		Response response = request.waitForResponse(1000);

		printServerLog();
		Assert.assertNotNull("Client 1 received no response", response);
		Assert.assertEquals("Client 1 received wrong response code:", CONTENT, response.getCode());
		Assert.assertEquals("Client 1 received wrong payload:", respPayload, response.getPayloadString());
		Assert.assertTrue("Store does not contain the new Observe Request:", !store.isEmpty());
		System.out.println("Relation established with client 1");
		Thread.sleep(1000);

		// server send new response to client 2
		System.out.println("\nServer send Observe response to client 2.");
		respPayload = generatePayload(10); // changed
		server.setDestination(client2.getAddress());
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(++obs).go();
		server.expectEmpty(ACK, mid).go();
		response = notificationListener2.waitForResponse(1000);

		printServerLog();
		Assert.assertNotNull("Client 2 received no response", response);
		Assert.assertEquals("Client 2 received wrong response code:", CONTENT, response.getCode());
		Assert.assertEquals("Client 2 received wrong payload:", respPayload, response.getPayloadString());
		System.out.println("Response received");

		// server send new response to client 1
		System.out.println();
		System.out.println("\nServer send Observe response to client 1.");
		respPayload = generatePayload(10); // changed
		server.setDestination(client1.getAddress());
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(++obs).go();
		server.expectEmpty(ACK, mid).go();
		response = notificationListener1.waitForResponse(1000);

		printServerLog();
		Assert.assertNotNull("Client 1 received no response", response);
		Assert.assertEquals("Client 1 received wrong response code:", CONTENT, response.getCode());
		Assert.assertEquals("Client 1 received wrong payload:", respPayload, response.getPayloadString());
		System.out.println("Response received");

		// cancel observation
		System.out.println();
		System.out.println("\nCancel Observation.");
		store.remove(request.getToken());

		// server send new response to client 1
		System.out.println();
		System.out.println("\nServer send Observe response to client 1.");
		respPayload = generatePayload(10); // changed
		server.setDestination(client1.getAddress());
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(++obs).go();
		server.expectEmpty(RST, mid).go();
		printServerLog();

		// server send new response to client 2
		System.out.println();
		System.out.println("\nServer send Observe response to client 2.");
		respPayload = generatePayload(10); // changed
		server.setDestination(client2.getAddress());
		server.sendResponse(CON, CONTENT).loadToken("B").payload(respPayload).mid(++mid).observe(obs).go();
		server.expectEmpty(RST, mid).go();
		printServerLog();
	}

	private LockstepEndpoint createLockstepEndpoint() {
		try {
			LockstepEndpoint endpoint = new LockstepEndpoint();
			endpoint.setDestination(new InetSocketAddress(InetAddress.getByName("localhost"), clientPort1));
			return endpoint;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private Request createRequest(Code code, String path) throws Exception {
		Request request = new Request(code);
		String uri = "coap://localhost:" + (server.getPort()) + "/" + path;
		request.setURI(uri);
		return request;
	}

	private void printServerLog() {
		System.out.print(clientInterceptor.toString());
		clientInterceptor.clear();
	}

	private static String generatePayload(int length) {
		StringBuffer buffer = new StringBuffer();
		if (RANDOM_PAYLOAD_GENERATION) {
			Random rand = new Random();
			while (buffer.length() < length) {
				buffer.append(rand.nextInt());
			}
		} else { // Deterministic payload
			int n = 1;
			while (buffer.length() < length) {
				buffer.append(n++);
			}
		}
		return buffer.substring(0, length);
	}
}
