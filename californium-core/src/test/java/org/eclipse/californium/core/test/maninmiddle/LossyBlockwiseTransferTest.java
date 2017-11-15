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
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CoapNetworkRule for
 *                                                    setup of test-network
 ******************************************************************************/
package org.eclipse.californium.core.test.maninmiddle;

import static org.eclipse.californium.TestTools.*;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Random;

import org.eclipse.californium.category.Large;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * This test randomly drops packets of a blockwise transfer and checks if the
 * transfer still succeeds.
 */
@Category(Large.class)
public class LossyBlockwiseTransferTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	private CoapServer server;
	private Endpoint clientEndpoint;
	private ManInTheMiddle middle;

	private int clientPort;
	private int serverPort;
	private InetAddress middleAddress;
	private int middlePort;

	private String respPayload;
	private Random rand = new Random();

	@Before
	public void setupEndpoints() throws Exception {

		System.out.println(System.lineSeparator() + "Start" + getClass().getSimpleName());

		NetworkConfig config =  network.getStandardTestConfig()
			.setInt(NetworkConfig.Keys.ACK_TIMEOUT, 300)
			.setFloat(NetworkConfig.Keys.ACK_RANDOM_FACTOR, 1f)
			.setFloat(NetworkConfig.Keys.ACK_TIMEOUT_SCALE, 1f)
			.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 32)
			.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 32);

		clientEndpoint = new CoapEndpoint(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), config);
		clientEndpoint.start();

		Endpoint serverEndpoint = new CoapEndpoint(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), config);
		server = new CoapServer();
		server.addEndpoint(serverEndpoint);
		server.add(new CoapResource("test") {

			@Override
			public void handleGET(final CoapExchange exchange) {
				exchange.respond(ResponseCode.CONTENT, respPayload);
			}
		});
		server.start();

		clientPort = clientEndpoint.getAddress().getPort();
		serverPort = serverEndpoint.getAddress().getPort();
		middleAddress = InetAddress.getLoopbackAddress();
		middle = new ManInTheMiddle(middleAddress, clientPort, serverPort);
		middlePort = middle.getPort();

		System.out.println(
				String.format(
						"client at %s:%d, middle at %s:%d, server at %s:%d",
						clientEndpoint.getAddress().getHostString(), clientPort,
						middleAddress.getHostAddress(), middlePort,
						serverEndpoint.getAddress().getHostString(), serverPort));
	}

	@After
	public void shutdownServer() {
		System.out.println();
		server.destroy();
		clientEndpoint.destroy();
		middle.stop();
		System.out.printf("End %s", getClass().getSimpleName());
	}

	@Test
	public void testBlockwiseTransferToleratesLostMessages() throws Exception {

		String uri = getUri(new InetSocketAddress(middleAddress, middlePort), "test");
		respPayload = generateRandomPayload(250);

		CoapClient coapclient = new CoapClient(uri);
		coapclient.setTimeout(10000);
		coapclient.setEndpoint(clientEndpoint);

		middle.drop(5, 6, 8, 9, 15);

		getResourceAndAssertPayload(coapclient, respPayload);

		for (int i = 0; i < 5; i++) {
			int[] numbers = new int[10];
			for (int j = 0; j < numbers.length; j++) {
				numbers[j] = rand.nextInt(16);
			}
			middle.reset();
			middle.drop(numbers);

			getResourceAndAssertPayload(coapclient, respPayload);
		}
	}

	private static void getResourceAndAssertPayload(final CoapClient client, final String expectedPayload) {

		System.out.println(String.format("doing a blockwise GET on: %s", client.getURI()));

		long start = System.currentTimeMillis();
		CoapResponse response = client.get();
		long end = System.currentTimeMillis();
		assertThat("Blockwise GET timed out after " + (end - start) + "ms", response, is(notNullValue()));
		System.out.println(String.format("Received %d bytes after %dms", response.getPayload().length, end - start));
		assertThat("Did not receive expected resource body", response.getResponseText(), is(expectedPayload));
	}
}
