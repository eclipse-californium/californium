/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add tests to start and stop 
 *                                                    the DTLSConnector
 ******************************************************************************/
package org.eclipse.californium.scandium;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.util.SimpleMessageCallback;
import org.eclipse.californium.scandium.ConnectorHelper.LatchDecrementingRawDataChannel;
import org.eclipse.californium.scandium.category.Medium;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.InMemoryConnectionStore;
import org.eclipse.californium.scandium.rule.DtlsNetworkRule;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.TestName;
import org.junit.runner.Description;

/**
 * Verifies behavior of {@link DTLSConnector}.
 * <p>
 * Focus on start and stop the DTLSConnector.
 * Currently it only tests the stop, if the DTLS session is successful established.
 */
@Category(Medium.class)
public class DTLSConnectorStartStopTest {

	@ClassRule
	public static DtlsNetworkRule network = new DtlsNetworkRule(DtlsNetworkRule.Mode.DIRECT,
			DtlsNetworkRule.Mode.NATIVE);

	@Rule
	public TestName names = new TestName() {

		@Override
		protected void starting(Description d) {
			System.out.println("Test " + d.getMethodName());
		}
	};

	private static final int CLIENT_CONNECTION_STORE_CAPACITY = 5;

	static ConnectorHelper serverHelper;

	DTLSConnector client;
	DtlsConnectorConfig clientConfig;
	LatchDecrementingRawDataChannel clientChannel;
	InMemoryConnectionStore clientConnectionStore;

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
	public void setUp() throws Exception {
		clientConnectionStore = new InMemoryConnectionStore(CLIENT_CONNECTION_STORE_CAPACITY, 60);
		InetSocketAddress clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
		clientConfig = ConnectorHelper.newStandardClientConfig(clientEndpoint);
		client = new DTLSConnector(clientConfig, clientConnectionStore);
		clientChannel = serverHelper.new LatchDecrementingRawDataChannel();
		client.setRawDataReceiver(clientChannel);
		client.start();
	}

	@After
	public void cleanUp() {
		if (client != null) {
			client.destroy();
		}
		serverHelper.cleanUpServer();
	}

	@Test
	public void testStopCallsMessageCallbackOnError() throws InterruptedException {
		testStopCallsMessageCallbackOnError(100, 20);
	}

	@Test
	public void testStopCallsMessageCallbackOnErrorCirtical() throws InterruptedException {
		testStopCallsMessageCallbackOnError(2, 20);
	}

	private void testStopCallsMessageCallbackOnError(final int pending, final int loops) throws InterruptedException {
		byte[] data = { 0, 1, 2 };
		InetSocketAddress dest = serverHelper.serverEndpoint;
		EndpointContext context = new AddressEndpointContext(dest);

		for (int loop = 0; loop < loops; ++loop) {
			Thread.sleep(100);
			System.out.format("start/stop: %d/%d loops, %d msgs server %s, client %s%n", loop, loops, pending, dest, client.getAddress());

			CountDownLatch latch = new CountDownLatch(1);
			clientChannel.setLatch(latch);

			SimpleMessageCallback callback = new SimpleMessageCallback(pending, false);
			RawData message = RawData.outbound(data, context, callback, false);
			client.send(message);
			assertTrue("loop: " + loop + ", DTLS handshake timed out after " + ConnectorHelper.MAX_TIME_TO_WAIT_SECS
					+ " seconds", latch.await(ConnectorHelper.MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			for (int i = 1; i < pending; ++i) {
				message = RawData.outbound(data, context, callback, false);
				client.send(message);
			}

			client.stop();
			assertThat("loop: " + loop + ", " + callback.toString(), callback.await(200), is(true));
			try {
				client.start();
			} catch (IOException e) {
			}
		}
	}
}
