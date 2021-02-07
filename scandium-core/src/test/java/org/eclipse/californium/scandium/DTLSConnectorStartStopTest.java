/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add tests to start and stop 
 *                                                    the DTLSConnector
 ******************************************************************************/
package org.eclipse.californium.scandium;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.category.Large;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.rule.ThreadsRule;
import org.eclipse.californium.elements.util.SimpleMessageCallback;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.elements.util.TestScope;
import org.eclipse.californium.scandium.ConnectorHelper.LatchDecrementingRawDataChannel;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.DebugConnectionStore;
import org.eclipse.californium.scandium.rule.DtlsNetworkRule;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies behavior of {@link DTLSConnector}.
 * <p>
 * Focus on start and stop the DTLSConnector. Currently it only tests the stop,
 * if the DTLS session is successful established.
 */
@Category(Large.class)
public class DTLSConnectorStartStopTest {

	public static final Logger LOGGER = LoggerFactory.getLogger(DTLSConnectorStartStopTest.class);

	@ClassRule
	public static DtlsNetworkRule network = new DtlsNetworkRule(DtlsNetworkRule.Mode.DIRECT, DtlsNetworkRule.Mode.NATIVE);

	@ClassRule
	public static ThreadsRule cleanup = new ThreadsRule();

	@Rule
	public TestNameLoggerRule names = new TestNameLoggerRule();

	private static final int CLIENT_CONNECTION_STORE_CAPACITY	= 5;
	private static final int MAX_TIME_TO_WAIT_SECS				= 5;

	static ConnectorHelper serverHelper;
	static String testLogTagHead;
	static int testLogTagCounter;

	DTLSConnector client;
	LatchDecrementingRawDataChannel clientChannel;
	DebugConnectionStore clientConnectionStore;
	Connection restoreClientConnection;

	String testLogTag = "";

	/**
	 * Configures and starts a server side connector for running the tests
	 * against.
	 * 
	 * @throws IOException if the key store to read the server's keys from
	 *             cannot be found.
	 * @throws GeneralSecurityException if the server's keys cannot be read.
	 */
	@BeforeClass
	public static void startServer() throws IOException, GeneralSecurityException {
		if (testLogTagHead == null) {
			byte[] logid = new byte[5];
			SecureRandom rand = new SecureRandom();
			rand.nextBytes(logid);
			testLogTagHead = StringUtil.byteArray2HexString(logid, StringUtil.NO_SEPARATOR, 0) + "-";
		}
		serverHelper = new ConnectorHelper();
		serverHelper.startServer();
	}

	/**
	 * Shuts down and destroys the sever side connector.
	 */
	@AfterClass
	public static void tearDown() {
		serverHelper.destroyServer();
	}

	@Before
	public void setUp() throws IOException, GeneralSecurityException {
		testLogTag = testLogTagHead + testLogTagCounter++;
		clientConnectionStore = new DebugConnectionStore(CLIENT_CONNECTION_STORE_CAPACITY, 60, null);
		clientConnectionStore.setTag(testLogTag + "-client");
		InetSocketAddress clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
		DtlsConnectorConfig.Builder builder = serverHelper.newStandardClientConfigBuilder(clientEndpoint)
				.setLoggingTag(testLogTag + "-client")
				.setMaxConnections(CLIENT_CONNECTION_STORE_CAPACITY);
		DtlsConnectorConfig clientConfig = builder.build();
		client = new DTLSConnector(clientConfig, clientConnectionStore);
		clientChannel = new LatchDecrementingRawDataChannel();
		client.setRawDataReceiver(clientChannel);
		if (restoreClientConnection != null) {
			client.restoreConnection(restoreClientConnection);
			restoreClientConnection = null;
		}
	}

	@After
	public void cleanUp() {
		if (client != null) {
			client.stop();
			ConnectorHelper.assertReloadConnections("client", client);
			client.destroy();
		}
		serverHelper.cleanUpServer();
	}

	@Test
	public void testStopCallsMessageCallbackOnError()
			throws InterruptedException, IOException, GeneralSecurityException {
		if (TestScope.enableIntensiveTests()) {
			testStopCallsMessageCallbackOnError(100, 20, false);
		} else {
			testStopCallsMessageCallbackOnError(20, 5, false);
		}
	}

	@Test
	public void testStopCallsMessageCallbackOnErrorCirtical()
			throws InterruptedException, IOException, GeneralSecurityException {
		if (TestScope.enableIntensiveTests()) {
			testStopCallsMessageCallbackOnError(2, 20, false);
		} else {
			testStopCallsMessageCallbackOnError(2, 10, false);
		}
	}

	@Test
	public void testRestartFromClientSessionCache() throws InterruptedException, IOException, GeneralSecurityException {
		if (TestScope.enableIntensiveTests()) {
			testStopCallsMessageCallbackOnError(10, 20, true);
		} else {
			testStopCallsMessageCallbackOnError(4, 10, true);
		}
	}

	private void testStopCallsMessageCallbackOnError(final int pending, final int loops, boolean restart)
			throws InterruptedException, IOException, GeneralSecurityException {
		byte[] data = { 0, 1, 2 };
		int lastServerRemaining = -1;
		InetSocketAddress dest = serverHelper.serverEndpoint;
		EndpointContext context = new AddressEndpointContext(dest);
		boolean setup = false;

		for (int loop = 0; loop < loops; ++loop) {
			if (setup) {
				setUp();
			}
			try {
				client.start();
			} catch (IOException e) {
			}
			clientConnectionStore.dump();
			serverHelper.serverConnectionStore.dump();
			LOGGER.info("{} start/stop: {}/{} loops, {} msgs server {}, client {}",
					testLogTag, loop, loops, pending, dest, client.getAddress());

			List<SimpleMessageCallback> callbacks = new ArrayList<>();

			clientChannel.setLatchCount(1);

			SimpleMessageCallback callback = new SimpleMessageCallback(pending, false);
			SimpleMessageCallback messageCallback = new SimpleMessageCallback(0, true, callback);
			callbacks.add(messageCallback);
			RawData message = RawData.outbound(data, context, messageCallback, false);
			client.send(message);
			assertTrue(testLogTag + " loop: " + loop + ", " + pending + " msgs," 
					+ " DTLS handshake timed out after " + MAX_TIME_TO_WAIT_SECS + " seconds",
					clientChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			if (lastServerRemaining > -1) {
				assertThat(testLogTag + " number of server sessions changed!", 
						serverHelper.serverConnectionStore.remainingCapacity(), is(lastServerRemaining));
			}

			for (int index = 1; index < pending; ++index) {
				LOGGER.info("{} loop: {}, send {}", testLogTag, loop, index);
				messageCallback = new SimpleMessageCallback(0, true, callback);
				callbacks.add(messageCallback);
				message = RawData.outbound(data, context, messageCallback, false);
				client.send(message);
			}

			client.stop();
			serverHelper.serverRawDataProcessor.quiet(100, 5000);

			boolean complete = callback.await(200);
			if (!complete) {
				LOGGER.info("{} loop: {}, still miss {} callbacks!", testLogTag, loop, callback.getPendingCalls());
				for (int index = 0; index < callbacks.size(); ++index) {
					SimpleMessageCallback calls = callbacks.get(index);
					if (!calls.isSent() && calls.getError() == null) {
						LOGGER.info("{} loop: {}, call {} {}", testLogTag, loop, index, calls);
					}
				}
			}
			assertThat(testLogTag + " loop: " + loop + ", missing callbacks " + callback, complete, is(true));
			lastServerRemaining = serverHelper.serverConnectionStore.remainingCapacity();
			if (restart) {
				restoreClientConnection = clientConnectionStore.get(serverHelper.serverEndpoint);
				restoreClientConnection.setResumptionRequired(true);
				client.destroy();
				setup = true;
			}
			System.gc();
			Thread.sleep(200);
		}
	}
}
