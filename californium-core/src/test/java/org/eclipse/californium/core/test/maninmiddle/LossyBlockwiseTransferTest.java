/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CoapNetworkRule for
 *                                                    setup of test-network
 ******************************************************************************/
package org.eclipse.californium.core.test.maninmiddle;

import static org.eclipse.californium.TestTools.LOCALHOST_EPHEMERAL;
import static org.eclipse.californium.TestTools.generateRandomPayload;
import static org.eclipse.californium.TestTools.getUri;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Random;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.test.lockstep.ClientBlockwiseInterceptor;
import org.eclipse.californium.elements.category.Large;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.elements.util.TestScope;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
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

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private Endpoint clientEndpoint;
	private ManInTheMiddle middle;

	private InetAddress middleAddress;
	private int middlePort;

	private String respPayload;
	private Random rand = new Random();

	private ClientBlockwiseInterceptor clientInterceptor = new ClientBlockwiseInterceptor();

	@Before
	public void setupEndpoints() throws Exception {

		System.out.println(System.lineSeparator() + "Start" + getClass().getSimpleName());

		NetworkConfig config = network.getStandardTestConfig()
			.setInt(NetworkConfig.Keys.ACK_TIMEOUT, 300)
			.setFloat(NetworkConfig.Keys.ACK_RANDOM_FACTOR, 1f)
			.setFloat(NetworkConfig.Keys.ACK_TIMEOUT_SCALE, 1.5f)
			.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 32)
			.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 32);

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(LOCALHOST_EPHEMERAL);
		builder.setNetworkConfig(config);

		clientEndpoint = builder.build();
		cleanup.add(clientEndpoint);
		clientEndpoint.addInterceptor(clientInterceptor);
		clientEndpoint.start();

		builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(LOCALHOST_EPHEMERAL);
		builder.setNetworkConfig(config);

		Endpoint serverEndpoint = builder.build();
		CoapServer server = new CoapServer(config);
		cleanup.add(server);
		server.addEndpoint(serverEndpoint);
		server.add(new CoapResource("test") {

			@Override
			public void handleGET(final CoapExchange exchange) {
				exchange.respond(ResponseCode.CONTENT, respPayload);
			}
		});
		server.start();

		int clientPort = clientEndpoint.getAddress().getPort();
		int serverPort = serverEndpoint.getAddress().getPort();
		middleAddress = InetAddress.getLoopbackAddress();
		middle = new ManInTheMiddle(middleAddress, clientPort, serverPort, config.getInt(NetworkConfig.Keys.MAX_RETRANSMIT), clientInterceptor);
		middlePort = middle.getPort();

		System.out.println(
				String.format(
						"client at %s, middle at %s:%d, server at %s",
						StringUtil.toString(clientEndpoint.getAddress()),
						middleAddress.getHostAddress(), middlePort,
						StringUtil.toString(serverEndpoint.getAddress())));
	}

	@After
	public void shutdownServer() {
		System.out.println();
		System.out.printf("End %s", getClass().getSimpleName());
		middle.stop();
	}

	@Test
	public void testBlockwiseTransferToleratesLostMessages() throws Exception {

		String uri = getUri(middleAddress, middlePort, "test");
		respPayload = generateRandomPayload(250);

		CoapClient coapclient = new CoapClient(uri);
		coapclient.setTimeout(10000L);
		coapclient.setEndpoint(clientEndpoint);

		middle.drop(5, 6, 8, 9, 15);

		getResourceAndAssertPayload(coapclient, respPayload);
		int loops = TestScope.enableIntensiveTests() ? 5 : 1;
		for (int i = 0; i < loops; i++) {
			int[] numbers = new int[10];
			for (int j = 0; j < numbers.length; j++) {
				numbers[j] = rand.nextInt(16);
			}
			middle.drop(numbers);

			getResourceAndAssertPayload(coapclient, respPayload);
		}
		coapclient.shutdown();
	}

	private static void getResourceAndAssertPayload(final CoapClient client, final String expectedPayload) throws ConnectorException, IOException {

		System.out.println(String.format("doing a blockwise GET on: %s", client.getURI()));

		long start = System.currentTimeMillis();
		CoapResponse response = client.get();
		long end = System.currentTimeMillis();
		assertThat("Blockwise GET timed out after " + (end - start) + " ms", response, is(notNullValue()));
		System.out.println(String.format("Received %d bytes after %d ms", response.getPayload().length, end - start));
		assertThat("Did not receive expected resource body", response.getResponseText(), is(expectedPayload));
	}
}
