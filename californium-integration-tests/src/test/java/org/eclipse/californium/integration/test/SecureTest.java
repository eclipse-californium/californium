/*******************************************************************************
 * Copyright (c) 2018 Sierra wireless and others.
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
import static org.junit.Assert.fail;
import static org.junit.Assert.assertEquals;

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.test.CountingHandler;
import org.eclipse.californium.core.test.MessageExchangeStoreTool.CoapTestEndpoint;
import org.eclipse.californium.elements.StrictDtlsEndpointContextMatcher;
import org.eclipse.californium.elements.rule.TestTimeRule;
import org.eclipse.californium.integration.test.util.CoapsNetworkRule;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig.Builder;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Medium.class)
public class SecureTest {

	@ClassRule
	public static CoapsNetworkRule network = new CoapsNetworkRule(CoapsNetworkRule.Mode.DIRECT,
			CoapsNetworkRule.Mode.NATIVE);

	@Rule
	public TestTimeRule time = new TestTimeRule();

	// CoAP config constants
	private static final int TEST_TIMEOUT_EXCHANGE_LIFETIME = 247; // milliseconds
	private static final int TEST_TIMEOUT_SWEEP_DEDUPLICATOR_INTERVAL = 100; // milliseconds

	private static final int TEST_EXCHANGE_LIFETIME = 15000; // milliseconds
	private static final int TEST_ACK_TIMEOUT = 5000; // milliseconds

	private static final int TEST_CLIENTS = 50;
	private static final int TEST_LOOPS = 5;

	// DTLS config constants
	private static final String PSK_IDENITITY = "client1";
	private static final String PSK_KEY = "key1";
	private static final int NB_RETRANSMISSION = 2;
	private static final int RETRANSMISSION_TIMEOUT = 100; // milliseconds

	// DTLS config constants for simultaneous handshakes
	private static final int TEST_DTLS_TIMEOUT = 2000; // milliseconds
	private static final int TEST_DTLS_FAST_TIMEOUT = 100; // milliseconds
	private static final int TEST_DTLS_PSK_DELAY = 50; // milliseconds

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
			createTestEndpoint();

			// Send a request to an absent peer
			CoapClient client = new CoapClient("coaps", InetAddress.getLoopbackAddress().getHostAddress(), freePort);
			CountingHandler handler = new CountingHandler();
			client.get(handler);

			// Wait for error
			handler.waitForErrorCalls(1, 5000, TimeUnit.MILLISECONDS);

			// We should get a handshake timeout error and so exchange store is
			// empty
			assertEquals("An error is expected", 1, handler.errorCalls.get());

			// Ensure there is no leak : all exchanges are completed
			assertAllExchangesAreCompleted(coapTestEndpoint, time);
		}
	}

	@Test
	public void testMultipleSecureHandshakes() throws Exception {
		for (int i = 0; i < TEST_LOOPS; ++i) {
			testSecureHandshakes(i);
		}
	}

	/**
	 * Test processing of repeated CLIENT_HELLOs.
	 * 
	 * Setup the dtls server to emulate a slow psk lookup by adding a delay. Use
	 * a short dtls retransmission timeout for the clients to generate more dtls
	 * message retransmission. With both, the probability that multiple
	 * CLIENT_HELLOs are executed simultaneous is high enough to fail the test.
	 * 
	 * @param loop number of loop for error message
	 * @throws Exception if the test fails
	 */
	public void testSecureHandshakes(int loop) throws Exception {
		CoapEndpoint serverEndpoint = createEndpoint("server", TEST_EXCHANGE_LIFETIME, TEST_ACK_TIMEOUT,
				TEST_DTLS_TIMEOUT, TEST_DTLS_PSK_DELAY);
		CoapServer server = new CoapServer(serverEndpoint.getConfig(), new int[0]);
		server.addEndpoint(serverEndpoint);
		server.start();
		URI uri = serverEndpoint.getUri();
		List<CoapEndpoint> clientEndpoints = new ArrayList<>();
		for (int i = 0; i < TEST_CLIENTS; ++i) {
			CoapEndpoint clientEndpoint = createEndpoint("client-" + i, TEST_EXCHANGE_LIFETIME, TEST_ACK_TIMEOUT,
					TEST_DTLS_FAST_TIMEOUT, 0);
			clientEndpoint.start();
			clientEndpoints.add(clientEndpoint);
		}
		List<Request> requests = new ArrayList<>();
		for (CoapEndpoint clientEndpoint : clientEndpoints) {
			Request request = Request.newGet();
			request.setURI(uri);
			clientEndpoint.sendRequest(request);
			requests.add(request);
		}
		List<Integer> pending = new ArrayList<>();
		List<Integer> errors = new ArrayList<>();
		for (int index = 0; index < requests.size(); ++index) {
			Request request = requests.get(index);
			Response response = request.waitForResponse(15000);
			if (response == null) {
				if (request.getSendError() != null) {
					errors.add(index);
				} else {
					pending.add(index);
				}
			}
		}
		for (CoapEndpoint clientEndpoint : clientEndpoints) {
			clientEndpoint.destroy();
		}
		server.destroy();
		if (!pending.isEmpty() || !errors.isEmpty()) {
			StringBuilder message = new StringBuilder("loop: ");
			message.append(loop).append(" - ");
			if (!errors.isEmpty()) {
				message.append(errors.size()).append(" requests failed, ");
				int max = Math.min(5, errors.size());
				for (int index = 0; index < max; ++index) {
					message.append(errors.get(index)).append(' ');
				}
				message.append(", ");
			}
			if (!errors.isEmpty()) {
				message.append(pending.size()).append(" requests pending, ");
				int max = Math.min(5, pending.size());
				for (int index = 0; index < max; ++index) {
					message.append(pending.get(index)).append(' ');
				}
			}
			fail(message.toString());
		}
		System.gc();
		Thread.sleep(200);
	}

	private void createTestEndpoint() {
		// setup DTLS Config
		Builder builder = new DtlsConnectorConfig.Builder()
				.setAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0)).setLoggingTag("client")
				.setPskStore(new TestUtilPskStore(PSK_IDENITITY, PSK_KEY.getBytes()))
				.setMaxRetransmissions(NB_RETRANSMISSION).setRetransmissionTimeout(RETRANSMISSION_TIMEOUT);
		DtlsConnectorConfig dtlsConfig = builder.build();

		// setup CoAP config
		NetworkConfig config = network.createTestConfig().setInt(Keys.ACK_TIMEOUT, 200)
				.setFloat(Keys.ACK_RANDOM_FACTOR, 1f).setFloat(Keys.ACK_TIMEOUT_SCALE, 1f)
				.setLong(Keys.EXCHANGE_LIFETIME, TEST_TIMEOUT_EXCHANGE_LIFETIME)
				.setLong(Keys.MARK_AND_SWEEP_INTERVAL, TEST_TIMEOUT_SWEEP_DEDUPLICATOR_INTERVAL);

		// create endpoint for tests
		DTLSConnector clientConnector = new DTLSConnector(dtlsConfig);
		coapTestEndpoint = new CoapTestEndpoint(clientConnector, config, new StrictDtlsEndpointContextMatcher());
		EndpointManager.getEndpointManager().setDefaultEndpoint(coapTestEndpoint);
	}

	private CoapEndpoint createEndpoint(String tag, int exchangeTimeout, int coapTimeout, int dtlsTimeout,
			int pskDelay) {
		// setup DTLS Config
		Builder builder = new DtlsConnectorConfig.Builder()
				.setAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0)).setLoggingTag(tag)
				.setPskStore(new TestUtilPskStore(PSK_IDENITITY, PSK_KEY.getBytes(), pskDelay))
				.setReceiverThreadCount(2).setConnectionThreadCount(2).setRetransmissionTimeout(dtlsTimeout);
		DtlsConnectorConfig dtlsConfig = builder.build();

		// setup CoAP config
		NetworkConfig config = network.createTestConfig().setInt(Keys.ACK_TIMEOUT, coapTimeout)
				.setLong(Keys.EXCHANGE_LIFETIME, exchangeTimeout);

		// create endpoint for tests
		DTLSConnector connector = new DTLSConnector(dtlsConfig);
		CoapEndpoint.Builder coapBuilder = new CoapEndpoint.Builder();
		coapBuilder.setConnector(connector);
		coapBuilder.setNetworkConfig(config);
		CoapEndpoint coapEndpoint = coapBuilder.build();
		return coapEndpoint;
	}

}
