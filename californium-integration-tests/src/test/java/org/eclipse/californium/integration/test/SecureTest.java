/*******************************************************************************
 * Copyright (c) 2018 Sierra wirelss and others.
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
 *    Simon Bernard (Sierra Wireless) - initial implementation.
 ******************************************************************************/
package org.eclipse.californium.integration.test;

import static org.eclipse.californium.core.test.MessageExchangeStoreTool.assertAllExchangesAreCompleted;

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.test.CountingHandler;
import org.eclipse.californium.core.test.MessageExchangeStoreTool.CoapTestEndpoint;
import org.eclipse.californium.elements.StrictDtlsEndpointContextMatcher;
import org.eclipse.californium.integration.test.util.CoapsNetworkRule;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig.Builder;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Medium.class)
public class SecureTest {

	@ClassRule
	public static CoapsNetworkRule network = new CoapsNetworkRule(CoapsNetworkRule.Mode.DIRECT,
			CoapsNetworkRule.Mode.NATIVE);

	// CoAP config constants
	private static final int TEST_EXCHANGE_LIFETIME = 247; // milliseconds
	private static final int TEST_SWEEP_DEDUPLICATOR_INTERVAL = 100; // milliseconds

	// DTLS config constants
	private static final String PSK_IDENITITY = "client1";
	private static final String PSK_KEY = "key1";
	private static final int NB_RETRANSMISSION = 2;
	private static final int RETRANSMISSION_TIMEOUT = 100; // milliseconds

	private CoapTestEndpoint coapTestEndpoint;

	@Before
	public void startupServer() {
		System.out.println(System.lineSeparator() + "Start " + getClass().getSimpleName());
	}

	@After
	public void shutdownServer() {
		System.out.println("End " + getClass().getSimpleName());
	}

	/**
	 * Ensure there is no leak when we try to send a request to an absent peer
	 */
	@Test
	public void testSecureGetHandshakeTimeout() throws Exception {
		// Get a free port to be sure we send request to an absent port
		try (DatagramSocket datagramSocket = new DatagramSocket(0)) {
			int freePort = datagramSocket.getLocalPort();

			// Create an endpoint
			createEndpoint();

			// Send a request to an absent peer
			CoapClient client = new CoapClient("coaps", InetAddress.getLoopbackAddress().getHostAddress(), freePort);
			CountingHandler handler = new CountingHandler();
			client.get(handler);

			// Wait for error
			handler.waitForErrorCalls(1, 1000, TimeUnit.MILLISECONDS);

			// We should get a handshake timeout error and so exchange store is empty
			Assert.assertEquals("An error is expected", 1, handler.errorCalls.get());

			// Ensure there is no leak : all exchanges are completed
			assertAllExchangesAreCompleted(coapTestEndpoint);
		}
	}

	private void createEndpoint() {
		// setup DTLS Config
		Builder builder = new DtlsConnectorConfig.Builder()
				.setAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
				.setLoggingTag("server")
				.setPskStore(new TestUtilPskStore(PSK_IDENITITY, PSK_KEY.getBytes()))
				.setMaxRetransmissions(NB_RETRANSMISSION)
				.setRetransmissionTimeout(RETRANSMISSION_TIMEOUT);
		DtlsConnectorConfig dtlsConfig = builder.build();

		// setup CoAP config
		NetworkConfig config = network.createTestConfig().setInt(Keys.ACK_TIMEOUT, 200)
				.setFloat(Keys.ACK_RANDOM_FACTOR, 1f).setFloat(Keys.ACK_TIMEOUT_SCALE, 1f)
				.setLong(Keys.EXCHANGE_LIFETIME, TEST_EXCHANGE_LIFETIME)
				.setLong(Keys.MARK_AND_SWEEP_INTERVAL, TEST_SWEEP_DEDUPLICATOR_INTERVAL);

		// create endpoint for tests
		DTLSConnector clientConnector = new DTLSConnector(dtlsConfig);
		coapTestEndpoint = new CoapTestEndpoint(clientConnector, config, new StrictDtlsEndpointContextMatcher());
		EndpointManager.getEndpointManager().setDefaultEndpoint(coapTestEndpoint);
	}
}
