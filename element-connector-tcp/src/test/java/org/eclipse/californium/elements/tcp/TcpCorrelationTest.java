/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add test for sending correlation context.
 *    Achim Kraus (Bosch Software Innovations GmbH) - use import static ConnectorTestUtil.
 *    Achim Kraus (Bosch Software Innovations GmbH) - use create server address
 *                                                    (LoopbackAddress)
 *    Achim Kraus (Bosch Software Innovations GmbH) - use timeout when get the 
 *                                                    correlation context
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.text.IsEmptyString.isEmptyOrNullString;
import static org.junit.Assert.assertArrayEquals;
import static org.eclipse.californium.elements.tcp.ConnectorTestUtil.*;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.CorrelationContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.TcpCorrelationContext;
import org.eclipse.californium.elements.TcpCorrelationContextMatcher;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;

public class TcpCorrelationTest {

	@Rule
	public final Timeout timeout = new Timeout(20, TimeUnit.SECONDS);

	private final List<Connector> cleanup = new ArrayList<>();

	@After
	public void cleanup() {
		for (Connector connector : cleanup) {
			connector.stop();
		}
	}

	/**
	 * Test, if the correlation context is determined proper.
	 *
	 * <pre>
	 * 1. Send a request and check, if the response has the same correlation
	 *    context on the client side.
	 * 2. Send a second request and check, if this has the same correlation
	 *    context on the client side.
	 * 3. Also check, if the server response is sent with the same context
	 *    as the request was received.
	 * </pre>
	 */
	@Test
	public void testCorrelationContext() throws Exception {
		TcpServerConnector server = new TcpServerConnector(createServerAddress(0),
				ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
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
		RawData msg = createMessage(server.getAddress(), 100, null, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(1);
		CorrelationContext receivingServerContext = serverCatcher.getMessage(0).getCorrelationContext();
		assertThat("Serverside received no TCP Correlation Context", receivingServerContext,
				is(instanceOf(TcpCorrelationContext.class)));
		assertThat(receivingServerContext.get(TcpCorrelationContext.KEY_CONNECTION_ID), is(not(isEmptyOrNullString())));

		CorrelationContext clientContext = clientCallback.getCorrelationContext(CONTEXT_TIMEOUT_IN_MS);
		assertThat("no TCP Correlation Context", clientContext, is(instanceOf(TcpCorrelationContext.class)));
		assertThat(clientContext.get(TcpCorrelationContext.KEY_CONNECTION_ID), is(not(isEmptyOrNullString())));

		// Response message must go over the same connection client already
		// opened
		SimpleMessageCallback serverCallback = new SimpleMessageCallback();
		msg = createMessage(serverCatcher.getMessage(0).getInetSocketAddress(), 100, null,
				serverCallback);
		server.send(msg);
		clientCatcher.blockUntilSize(1);

		CorrelationContext serverContext = serverCallback.getCorrelationContext(CONTEXT_TIMEOUT_IN_MS);
		assertThat("Serverside no TCP Correlation Context", serverContext, is(instanceOf(TcpCorrelationContext.class)));
		assertThat(serverContext, is(receivingServerContext));
		assertThat(serverContext.get(TcpCorrelationContext.KEY_CONNECTION_ID),
				is(receivingServerContext.get(TcpCorrelationContext.KEY_CONNECTION_ID)));

		// check response correlation context
		CorrelationContext responseContext = clientCatcher.getMessage(0).getCorrelationContext();
		assertThat("no response TCP Correlation Context", responseContext, is(instanceOf(TcpCorrelationContext.class)));
		assertThat(responseContext, is(clientContext));
		assertThat(responseContext.get(TcpCorrelationContext.KEY_CONNECTION_ID),
				is(clientContext.get(TcpCorrelationContext.KEY_CONNECTION_ID)));

		// send next message
		clientCallback = new SimpleMessageCallback();
		msg = createMessage(server.getAddress(), 100, null, clientCallback);

		client.send(msg);

		CorrelationContext context2 = clientCallback.getCorrelationContext(ConnectorTestUtil.CONTEXT_TIMEOUT_IN_MS);
		assertThat("no TCP Correlation Context", context2, is(instanceOf(TcpCorrelationContext.class)));
		assertThat(context2, is(clientContext));
		assertThat(context2.get(TcpCorrelationContext.KEY_CONNECTION_ID),
				is(clientContext.get(TcpCorrelationContext.KEY_CONNECTION_ID)));
	}

	/**
	 * Test, if the correlation context is different when reconnect after
	 * timeout.
	 *
	 * <pre>
	 * 1. Send a request and fetch the correlation context on client and
	 *    server side.
	 * 2. Wait for connection timeout.
	 * 3. Send a new request and fetch the correlation context on client and
	 *    server side. The correlation contexts must be different.
	 * </pre>
	 */
	@Test
	public void testCorrelationContextWhenReconnectAfterTimeout() throws Exception {
		TcpServerConnector server = new TcpServerConnector(createServerAddress(0),
				ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.IDLE_TIMEOUT_RECONNECT_IN_S);
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
		RawData msg = createMessage(server.getAddress(), 100, null, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(1);
		CorrelationContext serverContext = serverCatcher.getMessage(0).getCorrelationContext();

		CorrelationContext clientContext = clientCallback.getCorrelationContext(CONTEXT_TIMEOUT_IN_MS);

		// timeout connection, hopefully this triggers a reconnect
		Thread.sleep(TimeUnit.MILLISECONDS.convert(ConnectorTestUtil.IDLE_TIMEOUT_RECONNECT_IN_S * 2, TimeUnit.SECONDS));

		clientCallback = new SimpleMessageCallback();
		msg = createMessage(server.getAddress(), 100, null, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(2);

		CorrelationContext clientContextAfterReconnect = clientCallback.getCorrelationContext(CONTEXT_TIMEOUT_IN_MS);
		assertThat("no TCP Correlation Context after reconnect", clientContextAfterReconnect,
				is(instanceOf(TcpCorrelationContext.class)));
		// new (different) client side connection id
		assertThat(clientContextAfterReconnect, is(not(clientContext)));
		assertThat(clientContextAfterReconnect.get(TcpCorrelationContext.KEY_CONNECTION_ID),
				is(not(clientContext.get(TcpCorrelationContext.KEY_CONNECTION_ID))));

		// new (different) server side connection id
		CorrelationContext serverContextAfterReconnect = serverCatcher.getMessage(1).getCorrelationContext();
		assertThat("Serverside no TCP Correlation Context after reconnect", serverContextAfterReconnect,
				is(instanceOf(TcpCorrelationContext.class)));
		// new (different) server side connection id
		assertThat(serverContextAfterReconnect.get(TcpCorrelationContext.KEY_CONNECTION_ID),
				is(not(serverContext.get(TcpCorrelationContext.KEY_CONNECTION_ID))));
		assertThat(serverContextAfterReconnect, is(not(serverContext)));

	}

	/**
	 * Test, if the correlation context is different when reconnect after server
	 * stop/start.
	 *
	 * <pre>
	 * 1. Send a request and fetch the correlation context on client and
	 *    server side.
	 * 2. Stop/start the server.
	 * 3. Send a new request and fetch the correlation context on client and
	 *    server side. The correlation contexts must be different.
	 * </pre>
	 */
	@Test
	public void testCorrelationContextWhenReconnectAfterStopStart() throws Exception {
		TcpServerConnector server = new TcpServerConnector(createServerAddress(0),
				ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.IDLE_TIMEOUT_RECONNECT_IN_S);
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
		RawData msg = createMessage(server.getAddress(), 100, null, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(1);
		CorrelationContext serverContext = serverCatcher.getMessage(0).getCorrelationContext();

		CorrelationContext clientContext = clientCallback.getCorrelationContext(CONTEXT_TIMEOUT_IN_MS);

		/* stop / start the server */
		server.stop();
		server.start();

		clientCallback = new SimpleMessageCallback();
		msg = createMessage(server.getAddress(), 100, null, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(2);

		CorrelationContext clientContextAfterReconnect = clientCallback.getCorrelationContext(CONTEXT_TIMEOUT_IN_MS);
		assertThat("no TCP Correlation Context after reconnect", clientContextAfterReconnect,
				is(instanceOf(TcpCorrelationContext.class)));
		// new (different) client side connection id
		assertThat(clientContextAfterReconnect, is(not(clientContext)));
		assertThat(clientContextAfterReconnect.get(TcpCorrelationContext.KEY_CONNECTION_ID),
				is(not(clientContext.get(TcpCorrelationContext.KEY_CONNECTION_ID))));

		// Response message must go over the reconnected connection

		CorrelationContext serverContextAfterReconnect = serverCatcher.getMessage(1).getCorrelationContext();
		assertThat("Serverside no TCP Correlation Context after reconnect", serverContextAfterReconnect,
				is(instanceOf(TcpCorrelationContext.class)));
		// new (different) server side connection id
		assertThat(serverContextAfterReconnect, is(not(serverContext)));
		assertThat(serverContextAfterReconnect.get(TcpCorrelationContext.KEY_CONNECTION_ID),
				is(not(serverContext.get(TcpCorrelationContext.KEY_CONNECTION_ID))));
	}

	/**
	 * Test, if the correlation context provided for sending is handled proper
	 * on the client side. 
	 * 
	 * <pre>
	 * 1. Send a request with correlation context and check, that the message
	 *    is dropped (server doesn't receive a message).
	 * 2. Send a request without correlation context and check, that the
	 *    message is sent (server receives the message).
	 * 3. Send a 2. request with retrieved correlation context and check,
	 *    that the message is sent (server receives a 2. message).
	 * 4. Send a 3. request with different correlation context and check,
	 *    that the message is dropped (server doesn't receive a 3. message).
	 * </pre>
	 */
	@Test
	public void testClientSendingCorrelationContext() throws Exception {
		TcpCorrelationContextMatcher matcher = new TcpCorrelationContextMatcher();
		TcpCorrelationContext context = new TcpCorrelationContext("n.a.");
		TcpServerConnector server = new TcpServerConnector(createServerAddress(0),
				ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
		TcpClientConnector client = new TcpClientConnector(ConnectorTestUtil.NUMBER_OF_THREADS,
				ConnectorTestUtil.CONNECTION_TIMEOUT_IN_MS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
		client.setCorrelationContextMatcher(matcher);

		cleanup.add(server);
		cleanup.add(client);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		server.start();
		client.start();

		SimpleMessageCallback clientCallback = new SimpleMessageCallback();
		RawData msg = createMessage(server.getAddress(), 100, context, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(1, 2000);
		assertThat("Serverside received unexpected message", !serverCatcher.hasMessage(0));

		clientCallback = new SimpleMessageCallback();
		msg = createMessage(server.getAddress(), 100, null, clientCallback);
		client.send(msg);
		serverCatcher.blockUntilSize(1);

		CorrelationContext clientContext = clientCallback.getCorrelationContext(CONTEXT_TIMEOUT_IN_MS);
		assertThat("client side missing TCP Correlation Context", clientContext,
				is(instanceOf(TcpCorrelationContext.class)));
		assertThat(clientContext.get(TcpCorrelationContext.KEY_CONNECTION_ID), is(not(isEmptyOrNullString())));

		msg = createMessage(server.getAddress(), 100, clientContext, clientCallback);
		client.send(msg);
		serverCatcher.blockUntilSize(2);

		clientCallback = new SimpleMessageCallback();
		msg = createMessage(server.getAddress(), 100, context, clientCallback);
		client.send(msg);

		serverCatcher.blockUntilSize(3, 2000);
		assertThat("Serverside received unexpected message", !serverCatcher.hasMessage(3));
	}

	/**
	 * Test, if the correlation context provided for sending is handled proper
	 * on the server side.
	 *
	 * <pre>
	 * 1. Send a request without correlation context and check, that the
	 *    message is received by the server.
	 * 2. Send a response with the received correlation context, and check,
	 *    if the client receives the response.
	 * 3. Send a 2. response without a correlation context, and check,
	 *    if the client received the 2. response.
	 * 4. Send a 3. response with a different correlation context, and check,
	 *    if the client doesn't receive the 3. response.
	 * </pre>
	 */
	@Test
	public void testServerSendingCorrelationContext() throws Exception {
		TcpCorrelationContextMatcher matcher = new TcpCorrelationContextMatcher();
		TcpCorrelationContext context = new TcpCorrelationContext("n.a.");
		TcpServerConnector server = new TcpServerConnector(createServerAddress(0),
				ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
		TcpClientConnector client = new TcpClientConnector(ConnectorTestUtil.NUMBER_OF_THREADS,
				ConnectorTestUtil.CONNECTION_TIMEOUT_IN_MS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
		server.setCorrelationContextMatcher(matcher);

		cleanup.add(server);
		cleanup.add(client);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		server.start();
		client.start();

		SimpleMessageCallback clientCallback = new SimpleMessageCallback();
		RawData msg = createMessage(server.getAddress(), 100, null, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(1);

		RawData receivedMsg = serverCatcher.getMessage(0);
		CorrelationContext serverContext = receivedMsg.getCorrelationContext();
		assertThat("server side missing TCP Correlation Context", serverContext,
				is(instanceOf(TcpCorrelationContext.class)));
		assertThat(serverContext.get(TcpCorrelationContext.KEY_CONNECTION_ID), is(not(isEmptyOrNullString())));

		SimpleMessageCallback serverCallback = new SimpleMessageCallback();
		msg = createMessage(receivedMsg.getInetSocketAddress(), 100, serverContext, serverCallback);
		server.send(msg);

		clientCatcher.blockUntilSize(1);

		serverCallback = new SimpleMessageCallback();
		msg = createMessage(receivedMsg.getInetSocketAddress(), 100, null, serverCallback);
		server.send(msg);

		clientCatcher.blockUntilSize(2);

		serverCallback = new SimpleMessageCallback();
		msg = createMessage(receivedMsg.getInetSocketAddress(), 100, context, serverCallback);
		server.send(msg);

		clientCatcher.blockUntilSize(3, 2000);
		assertThat("Clientside received unexpected message", !clientCatcher.hasMessage(3));

	}

	/**
	 * Test, if the correlation context is determined proper when connecting to
	 * different servers. 
	 * 
	 * <pre>
	 * 1. Send a message to different servers and determine the used 
	 *    correlation context on the client side.
	 * 2. Send a second message to different servers and determine the 
	 *    correlation context used then on the client side. 
	 * 3. Compare the correlation contexts, they must be the same per server.
	 * </pre>
	 */
	@Test
	public void testSingleClientManyServersCorrelationContext() throws Exception {
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
			RawData message = createMessage(address, 100, null, callback);
			callbacks.add(callback);
			messages.add(message);
			client.send(message);
		}

		/* receive messages for all servers */
		for (RawData message : messages) {
			Catcher catcher = servers.get(message.getInetSocketAddress());
			catcher.blockUntilSize(1);
			assertArrayEquals(message.getBytes(), catcher.getMessage(0).getBytes());
		}

		/* send 2. (follow up) messages to all servers */
		List<RawData> followupMessages = new ArrayList<>();
		List<SimpleMessageCallback> followupCallbacks = new ArrayList<>();
		for (InetSocketAddress address : serverAddresses) {
			SimpleMessageCallback callback = new SimpleMessageCallback();
			RawData message = createMessage(address, 100, null, callback);
			followupCallbacks.add(callback);
			followupMessages.add(message);
			client.send(message);
		}

		/* receive 2. (follow up) messages for all servers */
		for (RawData followupMessage : followupMessages) {
			Catcher catcher = servers.get(followupMessage.getInetSocketAddress());
			catcher.blockUntilSize(2);
			assertArrayEquals(followupMessage.getBytes(), catcher.getMessage(1).getBytes());
		}

		/*
		 * check matching correlation contexts for both messages sent to all
		 * servers
		 */
		for (int index = 0; index < messages.size(); ++index) {
			CorrelationContext context1 = callbacks.get(index).getCorrelationContext(CONTEXT_TIMEOUT_IN_MS);
			CorrelationContext context2 = followupCallbacks.get(index).getCorrelationContext(CONTEXT_TIMEOUT_IN_MS);
			// same connection id used for follow up message
			assertThat(context1, is(context2));
			assertThat(context1.get(TcpCorrelationContext.KEY_CONNECTION_ID),
					is(context2.get(TcpCorrelationContext.KEY_CONNECTION_ID)));
		}
	}

}
