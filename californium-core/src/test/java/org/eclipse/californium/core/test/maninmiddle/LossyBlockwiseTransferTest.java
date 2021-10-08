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
import static org.hamcrest.MatcherAssert.assertThat;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.test.lockstep.ClientBlockwiseInterceptor;
import org.eclipse.californium.elements.category.Large;
import org.eclipse.californium.elements.config.Configuration;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This test randomly drops packets of a blockwise transfer and checks if the
 * transfer still succeeds.
 */
@Category(Large.class)
public class LossyBlockwiseTransferTest {
	private static final Logger LOGGER = LoggerFactory.getLogger(LossyBlockwiseTransferTest.class);

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

		Configuration config = network.getStandardTestConfig()
			.set(CoapConfig.ACK_TIMEOUT, 300, TimeUnit.MILLISECONDS)
			.set(CoapConfig.ACK_INIT_RANDOM, 1f)
			.set(CoapConfig.ACK_TIMEOUT_SCALE, 1.5f)
			.set(CoapConfig.MAX_MESSAGE_SIZE, 32)
			.set(CoapConfig.PREFERRED_BLOCK_SIZE, 32);

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(LOCALHOST_EPHEMERAL);
		builder.setConfiguration(config);

		clientEndpoint = builder.build();
		cleanup.add(clientEndpoint);
		clientEndpoint.addInterceptor(clientInterceptor);
		clientEndpoint.start();

		builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(LOCALHOST_EPHEMERAL);
		builder.setConfiguration(config);

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
		middle = new ManInTheMiddle(middleAddress, clientPort, serverPort, config.get(CoapConfig.MAX_RETRANSMIT), clientInterceptor);
		middlePort = middle.getPort();

		LOGGER.info("client at {}, middle at {}:{}, server at {}",
				StringUtil.toLog(clientEndpoint.getAddress()),
				middleAddress.getHostAddress(),
				middlePort,
				StringUtil.toLog(serverEndpoint.getAddress()));
	}

	@After
	public void shutdownServer() {
		LOGGER.info("End");
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

		LOGGER.info("doing a blockwise GET on: {}", client.getURI());

		long start = System.currentTimeMillis();
		CoapResponse response = client.get();
		long end = System.currentTimeMillis();
		assertThat("Blockwise GET timed out after " + (end - start) + " ms", response, is(notNullValue()));
		LOGGER.info("Received {} bytes after {} ms", response.getPayload().length, end - start);
		assertThat("Did not receive expected resource body", response.getResponseText(), is(expectedPayload));
	}
}
