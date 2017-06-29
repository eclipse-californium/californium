/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 ******************************************************************************/
package org.eclipse.californium.scandium;

import static org.eclipse.californium.scandium.ConnectorHelper.MAX_TIME_TO_WAIT_SECS;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.CorrelationContext;
import org.eclipse.californium.elements.CorrelationContextMatcher;
import org.eclipse.californium.elements.DtlsCorrelationContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.tcp.SimpleMessageCallback;
import org.eclipse.californium.scandium.ConnectorHelper.LatchDecrementingRawDataChannel;
import org.eclipse.californium.scandium.category.Medium;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.InMemoryConnectionStore;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Verifies behavior of {@link DTLSConnector}.
 * <p>
 * Mainly contains integration test cases verifying the correct interaction
 * between a client and a server.
 */
@Category(Medium.class)
public class DTLSCorrelationTest {

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
	 * Test invoking of CorrelationContextMatcher on initial send. The
	 * CorrelationContextMatcher is called once and block the sending.
	 */
	@Test
	public void testInitialSendingBlockedInvokesCorrelationContextMatcher() throws Exception {
		// GIVEN a CorrelationContextMatcher, blocking
		SimpleMessageCallback callback = new SimpleMessageCallback();
		TestCorrelationContextMatcher correlationMatcher = new TestCorrelationContextMatcher(1);
		client.setCorrelationContextMatcher(correlationMatcher);
		// GIVEN a message to send
		RawData outboundMessage = RawData.outbound(new byte[] { 0x01 }, serverHelper.serverEndpoint, null, callback,
				false);

		// WHEN sending the initial message, but being blocked by
		// CorrelationContextMatcher
		CountDownLatch latch = new CountDownLatch(1);
		givenAStartedSession(outboundMessage, latch);

		// THEN assert that no session is established.
		assertFalse(latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// THEN assert that the CorrelationContextMatcher is invoked once
		assertThat(correlationMatcher.getConnectionCorrelationContext(0), is(nullValue()));

		// THEN assert that onError is invoked
		assertThat(callback.getError(TimeUnit.SECONDS.toMillis(MAX_TIME_TO_WAIT_SECS)), is(notNullValue()));
	}

	/**
	 * Test invoking of CorrelationContextMatcher on initial send. The
	 * CorrelationContextMatcher is called twice, first without a connector
	 * context and a second time after the DTLS session was established.
	 */
	@Test
	public void testInitialSendingInvokesCorrelationContextMatcher() throws Exception {
		// GIVEN a CorrelationContextMatcher
		TestCorrelationContextMatcher correlationMatcher = new TestCorrelationContextMatcher(3);
		client.setCorrelationContextMatcher(correlationMatcher);

		// WHEN sending the initial message
		serverHelper.givenAnEstablishedSession(client, true);

		// THEN assert that the CorrelationContextMatcher is invoked
		assertThat(correlationMatcher.getConnectionCorrelationContext(0), is(nullValue()));
		assertThat(correlationMatcher.getConnectionCorrelationContext(1), is(notNullValue()));
	}

	/**
	 * Test invoking of CorrelationContextMatcher when sending with already
	 * established DTLS Session.
	 */
	@Test
	public void testSendingInvokesCorrelationContextMatcher() throws Exception {

		// GIVEN a CorrelationContextMatcher
		TestCorrelationContextMatcher correlationMatcher = new TestCorrelationContextMatcher(3);
		client.setCorrelationContextMatcher(correlationMatcher);
		// GIVEN a established session
		serverHelper.givenAnEstablishedSession(client, false);

		CorrelationContext correlationContext = correlationMatcher.getConnectionCorrelationContext(1);

		// GIVEN a message with correlation context
		RawData outboundMessage = RawData.outbound(new byte[] { 0x01 }, serverHelper.serverEndpoint, correlationContext,
				null, false);

		// WHEN sending a message
		client.send(outboundMessage);

		// THEN assert that the CorrelationContextMatcher is invoked
		correlationMatcher.await();
		assertThat(correlationMatcher.getConnectionCorrelationContext(2), is(correlationContext));
		assertThat(correlationMatcher.getMessageCorrelationContext(2), is(correlationContext));
	}

	/**
	 * Test invoking of CorrelationContextMatcher when sending with resuming
	 * DTLS Session.
	 */
	@Test
	public void testSendingWhileResumingInvokesCorrelationContextMatcher() throws Exception {

		// GIVEN a CorrelationContextMatcher
		TestCorrelationContextMatcher correlationMatcher = new TestCorrelationContextMatcher(3);
		client.setCorrelationContextMatcher(correlationMatcher);
		// GIVEN a established session
		serverHelper.givenAnEstablishedSession(client, false);

		client.forceResumeAllSessions();

		// GIVEN a message with correlation context
		RawData outboundMessage = RawData.outbound(new byte[] { 0x01 }, serverHelper.serverEndpoint, null, null, false);

		// WHEN sending a message
		client.send(outboundMessage);

		// THEN assert that the CorrelationContextMatcher is invoked
		correlationMatcher.await();
		assertThat(correlationMatcher.getConnectionCorrelationContext(2), is(notNullValue()));
	}

	@Test
	public void testConnectorAddsCorrelationContextToReceivedApplicationMessage() throws Exception {
		// GIVEN a message to be sent to the server
		RawData outboundMessage = RawData.outbound(new byte[] { 0x01 }, serverHelper.serverEndpoint, null, null, false);

		// WHEN a session has been established and the message has been sent to
		// the server
		serverHelper.givenAnEstablishedSession(client, outboundMessage, true);

		assertEstablishedClientSession();
		
		assertThat(serverHelper.serverRawDataProcessor.getLatestInboundMessage(), is(notNullValue()));
		// THEN assert that the message delivered to the server side application layer
		// contains a correlation context containing the established session's ID, epoch and cipher
		DtlsCorrelationContext context = (DtlsCorrelationContext) serverHelper.serverRawDataProcessor
				.getLatestInboundMessage().getCorrelationContext();
		assertThat(context, is(notNullValue()));
		assertThat(context.getSessionId(), is(establishedClientSession.getSessionIdentifier().toString()));
		assertThat(context.getEpoch(), is(String.valueOf(establishedClientSession.getReadEpoch())));
		assertThat(context.getCipher(), is(establishedClientSession.getReadStateCipher()));
	}

	private void givenAStartedSession(RawData msgToSend, CountDownLatch latch) throws Exception {

		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.new LatchDecrementingRawDataChannel();
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

	private static class TestCorrelationContextMatcher implements CorrelationContextMatcher {

		private final int count;
		private final CountDownLatch latchSendMatcher;
		private final CorrelationContext[] messageContexts;
		private final CorrelationContext[] connectorContexts;
		private int current;

		public TestCorrelationContextMatcher(int count) {
			this.count = count;
			this.latchSendMatcher = new CountDownLatch(count);
			this.messageContexts = new CorrelationContext[count + 1];
			this.connectorContexts = new CorrelationContext[count + 1];
		}

		public synchronized CorrelationContext getMessageCorrelationContext(final int index) {
			if (index > current) {
				throw new IllegalArgumentException("Index  " + index + " is not reached! Current " + current);
			}
			return messageContexts[index];
		}

		public synchronized CorrelationContext getConnectionCorrelationContext(final int index) {
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
		public boolean isResponseRelatedToRequest(CorrelationContext requestContext,
				CorrelationContext responseContext) {
			return false;
		}

		@Override
		public synchronized boolean isToBeSent(CorrelationContext messageContext, CorrelationContext connectorContext) {
			current = count - (int) latchSendMatcher.getCount();
			messageContexts[current] = messageContext;
			connectorContexts[current] = connectorContext;
			latchSendMatcher.countDown();
			return current < count;
		}

		public void await() throws InterruptedException {
			latchSendMatcher.await();
		}

	};
}
