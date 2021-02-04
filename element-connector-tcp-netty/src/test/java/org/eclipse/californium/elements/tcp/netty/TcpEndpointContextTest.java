/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add test for sending correlation context.
 *    Achim Kraus (Bosch Software Innovations GmbH) - use import static ConnectorTestUtil.
 *    Achim Kraus (Bosch Software Innovations GmbH) - use create server address
 *                                                    (LoopbackAddress)
 *    Achim Kraus (Bosch Software Innovations GmbH) - use timeout when get the 
 *                                                    correlation context
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove type checks for
 *                                                    EndpointContext. Functionality
 *                                                    should not depend on that.
 *    Achim Kraus (Bosch Software Innovations GmbH) - use timeouts for waiting on
 *                                                    messages.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add sleep to stop/start test
 *                                                    to ensure, client detects the
 *                                                    lost connection.
 ******************************************************************************/
package org.eclipse.californium.elements.tcp.netty;

import static org.eclipse.californium.elements.tcp.netty.ConnectorTestUtil.*;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.text.IsEmptyString.isEmptyOrNullString;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.fail;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.TcpEndpointContext;
import org.eclipse.californium.elements.TcpEndpointContextMatcher;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.rule.ThreadsRule;
import org.eclipse.californium.elements.util.SimpleMessageCallback;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;

public class TcpEndpointContextTest {

	public static final long MESSAGE_TIMEOUT_MILLIS = 2000;

	@Rule
	public final Timeout timeout = new Timeout(TEST_TIMEOUT_IN_MS, TimeUnit.MILLISECONDS);

	@Rule
	public TestNameLoggerRule names = new TestNameLoggerRule();

	@Rule
	public ThreadsRule threads = THREADS_RULE;

	private final List<Connector> cleanup = new ArrayList<>();

	@After
	public void cleanup() {
		stop(cleanup);
	}

	/**
	 * Test, if the endpoint context is determined proper.
	 *
	 * <pre>
	 * 1. Send a request and check, if the response has the same endpoint
	 *    context on the client side.
	 * 2. Send a second request and check, if this has the same endpoint
	 *    context on the client side.
	 * 3. Also check, if the server response is sent with the same context
	 *    as the request was received.
	 * </pre>
	 */
	@Test
	public void testEndpointContext() throws Exception {
		TcpServerConnector server = new TcpServerConnector(createServerAddress(0), ConnectorTestUtil.NUMBER_OF_THREADS,
				ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
		TcpClientConnector client = new TcpClientConnector(ConnectorTestUtil.NUMBER_OF_THREADS,
				ConnectorTestUtil.CONNECTION_TIMEOUT_IN_MS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);

		cleanup.add(server);
		cleanup.add(client);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		server.start();
		client.start();

		SimpleMessageCallback clientCallback = new SimpleMessageCallback();
		RawData msg = createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(1, MESSAGE_TIMEOUT_MILLIS);
		EndpointContext receivingServerContext = serverCatcher.getMessage(0).getEndpointContext();
		assertThat(receivingServerContext.getString(TcpEndpointContext.KEY_CONNECTION_ID), is(not(isEmptyOrNullString())));

		EndpointContext clientContext = clientCallback.getEndpointContext(CONTEXT_TIMEOUT_IN_MS);
		assertThat(clientContext.getString(TcpEndpointContext.KEY_CONNECTION_ID), is(not(isEmptyOrNullString())));

		// Response message must go over the same connection client already
		// opened
		SimpleMessageCallback serverCallback = new SimpleMessageCallback();
		msg = createMessage(serverCatcher.getMessage(0).getInetSocketAddress(), 100, serverCallback);
		server.send(msg);
		clientCatcher.blockUntilSize(1, MESSAGE_TIMEOUT_MILLIS);

		EndpointContext serverContext = serverCallback.getEndpointContext(CONTEXT_TIMEOUT_IN_MS);
		assertThat("Serverside no TCP Endpoint Context", serverContext, is(instanceOf(TcpEndpointContext.class)));
		assertThat(serverContext.get(TcpEndpointContext.KEY_CONNECTION_ID),
				is(receivingServerContext.get(TcpEndpointContext.KEY_CONNECTION_ID)));

		// check response endpoint context
		EndpointContext responseContext = clientCatcher.getMessage(0).getEndpointContext();
		assertThat("no response TCP Endpoint Context", responseContext, is(instanceOf(TcpEndpointContext.class)));
		assertThat(responseContext.get(TcpEndpointContext.KEY_CONNECTION_ID),
				is(clientContext.get(TcpEndpointContext.KEY_CONNECTION_ID)));

		// send next message
		clientCallback = new SimpleMessageCallback();
		msg = createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);

		EndpointContext context2 = clientCallback.getEndpointContext(ConnectorTestUtil.CONTEXT_TIMEOUT_IN_MS);
		assertThat("no TCP Endpoint Context", context2, is(instanceOf(TcpEndpointContext.class)));
		assertThat(context2.get(TcpEndpointContext.KEY_CONNECTION_ID),
				is(clientContext.get(TcpEndpointContext.KEY_CONNECTION_ID)));
	}

	/**
	 * Test, if the endpoint context is different when reconnect after timeout.
	 *
	 * <pre>
	 * 1. Send a request and fetch the endpoint context on client and
	 *    server side.
	 * 2. Wait for connection timeout.
	 * 3. Send a new request and fetch the endpoint context on client and
	 *    server side. The endpoint contexts must be different.
	 * </pre>
	 */
	@Test
	public void testEndpointContextWhenReconnectAfterTimeout() throws Exception {
		TcpServerConnector server = new TcpServerConnector(createServerAddress(0), ConnectorTestUtil.NUMBER_OF_THREADS,
				ConnectorTestUtil.IDLE_TIMEOUT_RECONNECT_IN_S);
		TcpClientConnector client = new TcpClientConnector(ConnectorTestUtil.NUMBER_OF_THREADS,
				ConnectorTestUtil.CONNECTION_TIMEOUT_IN_MS, ConnectorTestUtil.IDLE_TIMEOUT_RECONNECT_IN_S);

		cleanup.add(server);
		cleanup.add(client);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		server.start();
		client.start();

		SimpleMessageCallback clientCallback = new SimpleMessageCallback();
		RawData msg = createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(1, MESSAGE_TIMEOUT_MILLIS);
		EndpointContext serverContext = serverCatcher.getMessage(0).getEndpointContext();

		EndpointContext clientContext = clientCallback.getEndpointContext(CONTEXT_TIMEOUT_IN_MS);

		// timeout connection, hopefully this triggers a reconnect
		Thread.sleep(
				TimeUnit.MILLISECONDS.convert(ConnectorTestUtil.IDLE_TIMEOUT_RECONNECT_IN_S * 2, TimeUnit.SECONDS));

		clientCallback = new SimpleMessageCallback();
		msg = createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(2, MESSAGE_TIMEOUT_MILLIS);

		EndpointContext clientContextAfterReconnect = clientCallback.getEndpointContext(CONTEXT_TIMEOUT_IN_MS);
		// new (different) client side connection id
		assertThat(clientContextAfterReconnect, is(not(clientContext)));
		assertThat(clientContextAfterReconnect.get(TcpEndpointContext.KEY_CONNECTION_ID),
				is(not(clientContext.get(TcpEndpointContext.KEY_CONNECTION_ID))));

		// new (different) server side connection id
		EndpointContext serverContextAfterReconnect = serverCatcher.getMessage(1).getEndpointContext();
		// new (different) server side connection id
		assertThat(serverContextAfterReconnect.get(TcpEndpointContext.KEY_CONNECTION_ID),
				is(not(serverContext.get(TcpEndpointContext.KEY_CONNECTION_ID))));
		assertThat(serverContextAfterReconnect, is(not(serverContext)));

	}

	/**
	 * Test, if the endpoint context is different when reconnect after server
	 * stop/start.
	 *
	 * <pre>
	 * 1. Send a request and fetch the endpoint context on client and
	 *    server side.
	 * 2. Stop/start the server.
	 * 3. Send a new request and fetch the endpoint context on client and
	 *    server side. The endpoint contexts must be different.
	 * </pre>
	 */
	@Test
	public void testEndpointContextWhenReconnectAfterStopStart() throws Exception {
		TcpServerConnector server = new TcpServerConnector(createServerAddress(0), ConnectorTestUtil.NUMBER_OF_THREADS,
				ConnectorTestUtil.IDLE_TIMEOUT_RECONNECT_IN_S);
		TcpClientConnector client = new TcpClientConnector(ConnectorTestUtil.NUMBER_OF_THREADS,
				ConnectorTestUtil.CONNECTION_TIMEOUT_IN_MS, ConnectorTestUtil.IDLE_TIMEOUT_RECONNECT_IN_S);

		cleanup.add(server);
		cleanup.add(client);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		server.start();
		client.start();

		SimpleMessageCallback clientCallback = new SimpleMessageCallback();
		RawData msg = createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(1, MESSAGE_TIMEOUT_MILLIS);
		EndpointContext serverContext = serverCatcher.getMessage(0).getEndpointContext();

		EndpointContext clientContext = clientCallback.getEndpointContext(CONTEXT_TIMEOUT_IN_MS);

		/* stop / start the server */
		server.stop();
		/* give client time to detect the closed connection, but much less then the idle timeout */
		/* when the connector gets extended to report the connection state, this may be improved */
		/* by waiting for that disconnect */
		Thread.sleep(TimeUnit.MILLISECONDS.convert(ConnectorTestUtil.IDLE_TIMEOUT_RECONNECT_IN_S, TimeUnit.SECONDS) / 5);
		server.start();

		clientCallback = new SimpleMessageCallback();
		msg = createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);
		if (!serverCatcher.blockUntilSize(2, MESSAGE_TIMEOUT_MILLIS)) {
			Throwable error = clientCallback.getError();
			if (error != null) {
				error.printStackTrace();
				fail("send error " + error.toString());
			}
		}

		EndpointContext clientContextAfterReconnect = clientCallback.getEndpointContext(CONTEXT_TIMEOUT_IN_MS);
		// new (different) client side connection id
		assertThat(clientContextAfterReconnect, is(not(clientContext)));
		assertThat(clientContextAfterReconnect.get(TcpEndpointContext.KEY_CONNECTION_ID),
				is(not(clientContext.get(TcpEndpointContext.KEY_CONNECTION_ID))));

		// Response message must go over the reconnected connection

		EndpointContext serverContextAfterReconnect = serverCatcher.getMessage(1).getEndpointContext();
		// new (different) server side connection id
		assertThat(serverContextAfterReconnect, is(not(serverContext)));
		assertThat(serverContextAfterReconnect.get(TcpEndpointContext.KEY_CONNECTION_ID),
				is(not(serverContext.get(TcpEndpointContext.KEY_CONNECTION_ID))));
	}

	/**
	 * Test, if the endpoint context provided for sending is handled proper on
	 * the client side.
	 * 
	 * <pre>
	 * 1. Send a request with endpoint context and check, that the message
	 *    is dropped (server doesn't receive a message).
	 * 2. Send a request without endpoint context and check, that the
	 *    message is sent (server receives the message).
	 * 3. Send a 2. request with retrieved endpoint context and check,
	 *    that the message is sent (server receives a 2. message).
	 * 4. Send a 3. request with different endpoint context and check,
	 *    that the message is dropped (server doesn't receive a 3. message).
	 * </pre>
	 */
	@Test
	public void testClientSendingEndpointContext() throws Exception {
		TcpEndpointContextMatcher matcher = new TcpEndpointContextMatcher();
		TcpServerConnector server = new TcpServerConnector(createServerAddress(0), ConnectorTestUtil.NUMBER_OF_THREADS,
				ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
		TcpClientConnector client = new TcpClientConnector(ConnectorTestUtil.NUMBER_OF_THREADS,
				ConnectorTestUtil.CONNECTION_TIMEOUT_IN_MS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
		client.setEndpointContextMatcher(matcher);

		cleanup.add(server);
		cleanup.add(client);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		server.start();
		client.start();

		SimpleMessageCallback clientCallback = new SimpleMessageCallback();
		TcpEndpointContext context = new TcpEndpointContext(getDestination(server.getAddress()), "n.a.", System.currentTimeMillis());
		RawData msg = createMessage(100, context, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(1, MESSAGE_TIMEOUT_MILLIS);
		assertThat("Serverside received unexpected message", !serverCatcher.hasMessage(0));

		clientCallback = new SimpleMessageCallback();
		msg = createMessage(server.getAddress(), 100, clientCallback);
		client.send(msg);
		serverCatcher.blockUntilSize(1, MESSAGE_TIMEOUT_MILLIS);

		EndpointContext clientContext = clientCallback.getEndpointContext(CONTEXT_TIMEOUT_IN_MS);
		assertThat(clientContext.getString(TcpEndpointContext.KEY_CONNECTION_ID), is(not(isEmptyOrNullString())));

		msg = createMessage(100, clientContext, clientCallback);
		client.send(msg);
		serverCatcher.blockUntilSize(2, MESSAGE_TIMEOUT_MILLIS);

		clientCallback = new SimpleMessageCallback();
		msg = createMessage(100, context, clientCallback);
		client.send(msg);

		serverCatcher.blockUntilSize(3, MESSAGE_TIMEOUT_MILLIS);
		assertThat("Serverside received unexpected message", !serverCatcher.hasMessage(3));
	}

	/**
	 * Test, if the endpoint context provided for sending is handled proper on
	 * the server side.
	 *
	 * <pre>
	 * 1. Send a request without endpoint context and check, that the
	 *    message is received by the server.
	 * 2. Send a response with the received endpoint context, and check,
	 *    if the client receives the response.
	 * 3. Send a 2. response without a endpoint context, and check,
	 *    if the client received the 2. response.
	 * 4. Send a 3. response with a different endpoint context, and check,
	 *    if the client doesn't receive the 3. response.
	 * </pre>
	 */
	@Test
	public void testServerSendingEndpointContext() throws Exception {
		TcpEndpointContextMatcher matcher = new TcpEndpointContextMatcher();
		TcpServerConnector server = new TcpServerConnector(createServerAddress(0), ConnectorTestUtil.NUMBER_OF_THREADS,
				ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
		TcpClientConnector client = new TcpClientConnector(ConnectorTestUtil.NUMBER_OF_THREADS,
				ConnectorTestUtil.CONNECTION_TIMEOUT_IN_MS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
		server.setEndpointContextMatcher(matcher);

		cleanup.add(server);
		cleanup.add(client);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		server.start();
		client.start();

		SimpleMessageCallback clientCallback = new SimpleMessageCallback();
		RawData msg = createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(1, MESSAGE_TIMEOUT_MILLIS);

		RawData receivedMsg = serverCatcher.getMessage(0);
		EndpointContext serverContext = receivedMsg.getEndpointContext();
		assertThat(serverContext.getString(TcpEndpointContext.KEY_CONNECTION_ID), is(not(isEmptyOrNullString())));

		SimpleMessageCallback serverCallback = new SimpleMessageCallback();
		msg = createMessage(100, serverContext, serverCallback);
		server.send(msg);

		clientCatcher.blockUntilSize(1, MESSAGE_TIMEOUT_MILLIS);

		serverCallback = new SimpleMessageCallback();
		msg = createMessage(receivedMsg.getInetSocketAddress(), 100, serverCallback);
		server.send(msg);

		clientCatcher.blockUntilSize(2, MESSAGE_TIMEOUT_MILLIS);

		serverCallback = new SimpleMessageCallback();
		TcpEndpointContext context = new TcpEndpointContext(receivedMsg.getInetSocketAddress(), "n.a.", System.currentTimeMillis());
		msg = createMessage(100, context, serverCallback);
		server.send(msg);

		clientCatcher.blockUntilSize(3, MESSAGE_TIMEOUT_MILLIS);
		assertThat("Clientside received unexpected message", !clientCatcher.hasMessage(3));

	}

	/**
	 * Test, if the endpoint context is determined proper when connecting to
	 * different servers.
	 * 
	 * <pre>
	 * 1. Send a message to different servers and determine the used 
	 *    endpoint context on the client side.
	 * 2. Send a second message to different servers and determine the 
	 *    endpoint context used then on the client side. 
	 * 3. Compare the endpoint contexts, they must be the same per server.
	 * </pre>
	 */
	@Test
	public void testSingleClientManyServersEndpointContext() throws Exception {
		int serverCount = 3;
		Map<InetSocketAddress, Catcher> servers = new IdentityHashMap<>();
		for (int i = 0; i < serverCount; i++) {
			TcpServerConnector server = new TcpServerConnector(createServerAddress(0),
					ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
			cleanup.add(server);
			Catcher serverCatcher = new Catcher();
			server.setRawDataReceiver(serverCatcher);
			server.start();

			servers.put(ConnectorTestUtil.getDestination(server.getAddress()), serverCatcher);
		}
		Set<InetSocketAddress> serverAddresses = servers.keySet();

		TcpClientConnector client = new TcpClientConnector(ConnectorTestUtil.NUMBER_OF_THREADS,
				ConnectorTestUtil.CONNECTION_TIMEOUT_IN_MS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
		cleanup.add(client);
		Catcher clientCatcher = new Catcher();
		client.setRawDataReceiver(clientCatcher);
		client.start();

		/* send messages to all servers */
		List<RawData> messages = new ArrayList<>();
		List<SimpleMessageCallback> callbacks = new ArrayList<>();
		for (InetSocketAddress address : serverAddresses) {
			SimpleMessageCallback callback = new SimpleMessageCallback();
			RawData message = createMessage(address, 100, callback);
			callbacks.add(callback);
			messages.add(message);
			client.send(message);
		}

		/* receive messages for all servers */
		for (RawData message : messages) {
			Catcher catcher = servers.get(message.getInetSocketAddress());
			catcher.blockUntilSize(1, MESSAGE_TIMEOUT_MILLIS);
			assertArrayEquals(message.getBytes(), catcher.getMessage(0).getBytes());
		}

		/* send 2. (follow up) messages to all servers */
		List<RawData> followupMessages = new ArrayList<>();
		List<SimpleMessageCallback> followupCallbacks = new ArrayList<>();
		for (InetSocketAddress address : serverAddresses) {
			SimpleMessageCallback callback = new SimpleMessageCallback();
			RawData message = createMessage(address, 100, callback);
			followupCallbacks.add(callback);
			followupMessages.add(message);
			client.send(message);
		}

		/* receive 2. (follow up) messages for all servers */
		for (RawData followupMessage : followupMessages) {
			Catcher catcher = servers.get(followupMessage.getInetSocketAddress());
			catcher.blockUntilSize(2, MESSAGE_TIMEOUT_MILLIS);
			assertArrayEquals(followupMessage.getBytes(), catcher.getMessage(1).getBytes());
		}

		/*
		 * check matching endpoint contexts for both messages sent to all
		 * servers
		 */
		for (int index = 0; index < messages.size(); ++index) {
			EndpointContext context1 = callbacks.get(index).getEndpointContext(CONTEXT_TIMEOUT_IN_MS);
			EndpointContext context2 = followupCallbacks.get(index).getEndpointContext(CONTEXT_TIMEOUT_IN_MS);
			// same connection id used for follow up message
			assertThat(context1.get(TcpEndpointContext.KEY_CONNECTION_ID),
					is(context2.get(TcpEndpointContext.KEY_CONNECTION_ID)));
		}
	}

}
