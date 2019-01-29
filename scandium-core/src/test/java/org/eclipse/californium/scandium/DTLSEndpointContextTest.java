/*******************************************************************************
 * Copyright (c) 2017, 2018 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - move correlation tests from
 *                                                    DTLSConnectorTest.
 *    Achim Kraus (Bosch Software Innovations GmbH) - use timeout for await
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix unintended PortUnreachableException
 ******************************************************************************/
package org.eclipse.californium.scandium;

import static org.eclipse.californium.scandium.ConnectorHelper.MAX_TIME_TO_WAIT_SECS;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.util.SimpleMessageCallback;
import org.eclipse.californium.scandium.ConnectorHelper.LatchDecrementingRawDataChannel;
import org.eclipse.californium.scandium.category.Medium;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.DTLSSession;
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
 * Mainly contains integration test cases verifying the correct interaction
 * between a client and a server.
 */
@Category(Medium.class)
public class DTLSEndpointContextTest {

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

	private static final long TIMEOUT_IN_MILLIS = 2000;
	private static final int CLIENT_CONNECTION_STORE_CAPACITY = 5;

	static ConnectorHelper serverHelper;

	DTLSConnector client;
	DtlsConnectorConfig clientConfig;
	DTLSSession establishedClientSession;
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
	}

	@After
	public void cleanUp() {
		if (client != null) {
			client.destroy();
		}
		serverHelper.cleanUpServer();
	}

	/**
	 * Test invoking of EndpointContextMatcher on initial send. The
	 * EndpointContextMatcher is called once and block the sending.
	 */
	@Test
	public void testInitialSendingBlockedInvokesEndpointContextMatcher() throws Exception {
		// GIVEN a EndpointContextMatcher, blocking
		SimpleMessageCallback callback = new SimpleMessageCallback();
		TestEndpointContextMatcher endpointContextMatcher = new TestEndpointContextMatcher(1);
		client.setEndpointContextMatcher(endpointContextMatcher);
		// GIVEN a message to send
		RawData outboundMessage = RawData.outbound(new byte[] { 0x01 },
				new AddressEndpointContext(serverHelper.serverEndpoint), callback, false);

		// WHEN sending the initial message, but being blocked by
		// EndpointContextMatcher
		CountDownLatch latch = new CountDownLatch(1);
		givenAStartedSession(outboundMessage, latch);

		// THEN assert that no session is established.
		assertFalse(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// THEN assert that the EndpointContextMatcher is invoked once
		assertThat(endpointContextMatcher.getConnectionEndpointContext(0), is(nullValue()));

		// THEN assert that onError is invoked
		assertThat(callback.getError(TimeUnit.SECONDS.toMillis(MAX_TIME_TO_WAIT_SECS)), is(notNullValue()));
	}

	/**
	 * Test invoking of EndpointContextMatcher on initial send. The
	 * EndpointContextMatcher is called twice, first without a connector context
	 * and a second time after the DTLS session was established.
	 */
	@Test
	public void testInitialSendingInvokesEndpointContextMatcher() throws Exception {
		// GIVEN a EndpointContextMatcher
		TestEndpointContextMatcher endpointMatcher = new TestEndpointContextMatcher(3);
		client.setEndpointContextMatcher(endpointMatcher);

		// WHEN sending the initial message
		serverHelper.givenAnEstablishedSession(client, true);

		// THEN assert that the EndpointContextMatcher is invoked
		assertThat(endpointMatcher.getConnectionEndpointContext(0), is(nullValue()));
		assertThat(endpointMatcher.getConnectionEndpointContext(1), is(notNullValue()));
	}

	/**
	 * Test invoking of EndpointContextMatcher when sending with already
	 * established DTLS Session.
	 */
	@Test
	public void testSendingInvokesEndpointContextMatcher() throws Exception {

		// GIVEN a EndpointContextMatcher
		TestEndpointContextMatcher endpointMatcher = new TestEndpointContextMatcher(3);
		client.setEndpointContextMatcher(endpointMatcher);
		// GIVEN a established session
		LatchDecrementingRawDataChannel channel = serverHelper.givenAnEstablishedSession(client, false);

		EndpointContext endpointContext = endpointMatcher.getConnectionEndpointContext(1);

		// GIVEN a message with endpoint context
		RawData outboundMessage = RawData.outbound(new byte[] { 0x01 }, endpointContext, null, false);

		// prepare waiting for response
		CountDownLatch latch = new CountDownLatch(1);
		channel.setLatch(latch);

		// WHEN sending a message
		client.send(outboundMessage);

		// THEN assert that the EndpointContextMatcher is invoked
		assertTrue(endpointMatcher.await(TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS));

		// THEN wait for response from server before shutdown client
		assertTrue("DTLS client timed out after " + MAX_TIME_TO_WAIT_SECS + " seconds waiting for response!",
				latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
	}

	/**
	 * Test invoking of EndpointContextMatcher when sending with resuming DTLS
	 * Session.
	 */
	@Test
	public void testSendingWhileResumingInvokesEndpointContextMatcher() throws Exception {

		// GIVEN a EndpointContextMatcher
		TestEndpointContextMatcher endpointMatcher = new TestEndpointContextMatcher(3);
		client.setEndpointContextMatcher(endpointMatcher);
		// GIVEN a established session
		LatchDecrementingRawDataChannel channel = serverHelper.givenAnEstablishedSession(client, false);

		client.forceResumeAllSessions();

		// GIVEN a message with endpoint context
		RawData outboundMessage = RawData.outbound(new byte[] { 0x01 },
				new AddressEndpointContext(serverHelper.serverEndpoint), null, false);

		// prepare waiting for response
		CountDownLatch latch = new CountDownLatch(1);
		channel.setLatch(latch);

		// WHEN sending a message
		client.send(outboundMessage);

		// THEN assert that the EndpointContextMatcher is invoked
		assertThat(endpointMatcher.await(TIMEOUT_IN_MILLIS, TimeUnit.MILLISECONDS), is(true));
		assertThat(endpointMatcher.getConnectionEndpointContext(2), is(notNullValue()));

		// THEN wait for response from server before shutdown client
		assertTrue("DTLS client timed out after " + MAX_TIME_TO_WAIT_SECS + " seconds waiting for response!",
				latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
	}

	@Test
	public void testConnectorAddsEndpointContextToReceivedApplicationMessage() throws Exception {
		// GIVEN a message to be sent to the server
		RawData outboundMessage = RawData.outbound(new byte[] { 0x01 },
				new AddressEndpointContext(serverHelper.serverEndpoint), null, false);

		// WHEN a session has been established and the message has been sent to
		// the server
		serverHelper.givenAnEstablishedSession(client, outboundMessage, true);

		assertEstablishedClientSession();

		assertThat(serverHelper.serverRawDataProcessor.getLatestInboundMessage(), is(notNullValue()));
		// THEN assert that the message delivered to the server side application
		// layer contains a endpoint context containing the established
		// session's ID, epoch and cipher
		DtlsEndpointContext context = (DtlsEndpointContext) serverHelper.serverRawDataProcessor
				.getLatestInboundMessage().getEndpointContext();
		assertThat(context, is(notNullValue()));
		assertThat(context.getSessionId(), is(establishedClientSession.getSessionIdentifier().toString()));
		assertThat(context.getEpoch(), is(Integer.toString(establishedClientSession.getReadEpoch())));
		assertThat(context.getCipher(), is(establishedClientSession.getReadStateCipher()));
	}

	private void givenAStartedSession(RawData msgToSend, CountDownLatch latch) throws Exception {

		LatchDecrementingRawDataChannel clientRawDataChannel = new ConnectorHelper.LatchDecrementingRawDataChannel(client);
		clientRawDataChannel.setLatch(latch);
		client.setRawDataReceiver(clientRawDataChannel);
		client.start();
		client.send(msgToSend);
	}

	private void assertEstablishedClientSession() {
		Connection con = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertNotNull(con);
		establishedClientSession = con.getEstablishedSession();
		assertNotNull(establishedClientSession);
	}

	private static class TestEndpointContextMatcher implements EndpointContextMatcher {

		private final int count;
		private final CountDownLatch latchSendMatcher;
		private final EndpointContext[] messageContexts;
		private final EndpointContext[] connectorContexts;
		private int current;

		public TestEndpointContextMatcher(int count) {
			this.count = count;
			this.latchSendMatcher = new CountDownLatch(count);
			this.messageContexts = new EndpointContext[count + 1];
			this.connectorContexts = new EndpointContext[count + 1];
		}

		public synchronized EndpointContext getMessageEndpointContext(final int index) {
			if (index > current) {
				throw new IllegalArgumentException("Index  " + index + " is not reached! Current " + current);
			}
			return messageContexts[index];
		}

		public synchronized EndpointContext getConnectionEndpointContext(final int index) {
			if (index > current) {
				throw new IllegalArgumentException("Index  " + index + " is not reached! Current " + current);
			}
			return connectorContexts[index];
		}

		@Override
		public String getName() {
			return "test-only";
		}

		@Override
		public boolean isResponseRelatedToRequest(EndpointContext requestContext, EndpointContext responseContext) {
			return false;
		}

		@Override
		public synchronized boolean isToBeSent(EndpointContext messageContext, EndpointContext connectorContext) {
			current = count - (int) latchSendMatcher.getCount();
			messageContexts[current] = messageContext;
			connectorContexts[current] = connectorContext;
			latchSendMatcher.countDown();
			return current < count;
		}

		public boolean await(long timeout, TimeUnit unit) throws InterruptedException {
			return latchSendMatcher.await(timeout, unit);
		}

	};
}
