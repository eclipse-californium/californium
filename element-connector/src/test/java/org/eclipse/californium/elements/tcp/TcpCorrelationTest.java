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
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.text.IsEmptyString.isEmptyOrNullString;
import static org.junit.Assert.assertArrayEquals;

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

	@Test
	public void correlationContext() throws Exception {
		TcpServerConnector server = new TcpServerConnector(new InetSocketAddress(0),
				ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
		TcpClientConnector client = new TcpClientConnector(ConnectorTestUtil.NUMBER_OF_THREADS,
				ConnectorTestUtil.CONECTION_TIMEOUT_IN_MS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);

		cleanup.add(server);
		cleanup.add(client);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		server.start();
		client.start();

		SimpleMessageCallback clientCallback = new SimpleMessageCallback();
		RawData msg = ConnectorTestUtil.createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(1);

		CorrelationContext clientContext = clientCallback.getCorrelationContext();
		assertThat("no TCP Correlation Context", clientContext, is(instanceOf(TcpCorrelationContext.class)));
		assertThat(clientContext.get(TcpCorrelationContext.KEY_CONNECTION_ID), is(not(isEmptyOrNullString())));

		// Response message must go over the same connection client already
		// opened
		SimpleMessageCallback serverCallback = new SimpleMessageCallback();
		msg = ConnectorTestUtil.createMessage(serverCatcher.getMessage(0).getInetSocketAddress(), 100, serverCallback);
		server.send(msg);
		clientCatcher.blockUntilSize(1);

		CorrelationContext serverContext = serverCallback.getCorrelationContext();
		assertThat("Serverside no TCP Correlation Context", serverContext, is(instanceOf(TcpCorrelationContext.class)));
		assertThat(serverContext.get(TcpCorrelationContext.KEY_CONNECTION_ID), is(not(isEmptyOrNullString())));

		// check response correlation context
		CorrelationContext responseContext = clientCatcher.getMessage(0).getCorrelationContext();
		assertThat("no response TCP Correlation Context", responseContext, is(instanceOf(TcpCorrelationContext.class)));
		assertThat(responseContext, is(clientContext));
		assertThat(responseContext.get(TcpCorrelationContext.KEY_CONNECTION_ID),
				is(clientContext.get(TcpCorrelationContext.KEY_CONNECTION_ID)));

		// send next message
		clientCallback = new SimpleMessageCallback();
		msg = ConnectorTestUtil.createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);

		CorrelationContext context2 = clientCallback.getCorrelationContext(ConnectorTestUtil.CONTEXT_TIMEOUT_IN_MS);
		assertThat("no TCP Correlation Context", context2, is(instanceOf(TcpCorrelationContext.class)));
		assertThat(context2, is(clientContext));
		assertThat(context2.get(TcpCorrelationContext.KEY_CONNECTION_ID),
				is(clientContext.get(TcpCorrelationContext.KEY_CONNECTION_ID)));
	}

	@Test
	public void correlationContextReconnectTimeout() throws Exception {
		TcpServerConnector server = new TcpServerConnector(new InetSocketAddress(0),
				ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.IDLE_TIMEOUT_RECONNECT_IN_S);
		TcpClientConnector client = new TcpClientConnector(ConnectorTestUtil.NUMBER_OF_THREADS,
				ConnectorTestUtil.CONECTION_TIMEOUT_IN_MS, ConnectorTestUtil.IDLE_TIMEOUT_RECONNECT_IN_S);

		cleanup.add(server);
		cleanup.add(client);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		server.start();
		client.start();

		SimpleMessageCallback clientCallback = new SimpleMessageCallback();
		RawData msg = ConnectorTestUtil.createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(1);

		CorrelationContext clientContext = clientCallback.getCorrelationContext();
		assertThat("no TCP Correlation Context", clientContext, is(instanceOf(TcpCorrelationContext.class)));

		// Response message must go over the same connection client already
		// opened
		SimpleMessageCallback serverCallback = new SimpleMessageCallback();
		msg = ConnectorTestUtil.createMessage(serverCatcher.getMessage(0).getInetSocketAddress(), 100, serverCallback);
		server.send(msg);
		clientCatcher.blockUntilSize(1);

		CorrelationContext serverContext = serverCallback.getCorrelationContext();
		assertThat("Serverside no TCP Correlation Context", serverContext, is(instanceOf(TcpCorrelationContext.class)));

		// timeout connection, hopefully this triggers a reconnect
		Thread.sleep(TimeUnit.MILLISECONDS.convert(ConnectorTestUtil.IDLE_TIMEOUT_RECONNECT_IN_S * 2, TimeUnit.SECONDS));

		clientCallback = new SimpleMessageCallback();
		msg = ConnectorTestUtil.createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(2);

		CorrelationContext clientContextAfterReconnect = clientCallback.getCorrelationContext();
		assertThat("no TCP Correlation Context after reconnect", clientContextAfterReconnect,
				is(instanceOf(TcpCorrelationContext.class)));
		// new (different) client side connection id
		assertThat(clientContextAfterReconnect.get(TcpCorrelationContext.KEY_CONNECTION_ID),
				is(not(clientContext.get(TcpCorrelationContext.KEY_CONNECTION_ID))));
		assertThat(clientContextAfterReconnect, is(not(clientContext)));

		// Response message must go over the reconnected connection
		serverCallback = new SimpleMessageCallback();
		msg = ConnectorTestUtil.createMessage(serverCatcher.getMessage(1).getInetSocketAddress(), 100, serverCallback);
		server.send(msg);
		clientCatcher.blockUntilSize(2);

		CorrelationContext serverContextAfterReconnect = serverCallback.getCorrelationContext();
		assertThat("Serverside no TCP Correlation Context after reconnect", serverContextAfterReconnect,
				is(instanceOf(TcpCorrelationContext.class)));
		// new (different) server side connection id
		assertThat(serverContextAfterReconnect.get(TcpCorrelationContext.KEY_CONNECTION_ID),
				is(not(serverContext.get(TcpCorrelationContext.KEY_CONNECTION_ID))));
		assertThat(serverContextAfterReconnect, is(not(serverContext)));

	}

	@Test
	public void correlationContextReconnectStopStart() throws Exception {
		TcpServerConnector server = new TcpServerConnector(new InetSocketAddress(0),
				ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.IDLE_TIMEOUT_RECONNECT_IN_S);
		TcpClientConnector client = new TcpClientConnector(ConnectorTestUtil.NUMBER_OF_THREADS,
				ConnectorTestUtil.CONECTION_TIMEOUT_IN_MS, ConnectorTestUtil.IDLE_TIMEOUT_RECONNECT_IN_S);

		cleanup.add(server);
		cleanup.add(client);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		server.start();
		client.start();

		SimpleMessageCallback clientCallback = new SimpleMessageCallback();
		RawData msg = ConnectorTestUtil.createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(1);

		CorrelationContext clientContext = clientCallback.getCorrelationContext();
		assertThat("no TCP Correlation Context", clientContext, is(instanceOf(TcpCorrelationContext.class)));

		// Response message must go over the same connection client already
		// opened
		SimpleMessageCallback serverCallback = new SimpleMessageCallback();
		msg = ConnectorTestUtil.createMessage(serverCatcher.getMessage(0).getInetSocketAddress(), 100, serverCallback);
		server.send(msg);
		clientCatcher.blockUntilSize(1);

		CorrelationContext serverContext = serverCallback.getCorrelationContext();
		assertThat("Serverside no TCP Correlation Context", serverContext, is(instanceOf(TcpCorrelationContext.class)));

		server.stop();
		server.start();

		clientCallback = new SimpleMessageCallback();
		msg = ConnectorTestUtil.createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(2);

		CorrelationContext clientContextAfterReconnect = clientCallback.getCorrelationContext();
		assertThat("no TCP Correlation Context after reconnect", clientContextAfterReconnect,
				is(instanceOf(TcpCorrelationContext.class)));
		// new (different) client side connection id
		assertThat(clientContextAfterReconnect.get(TcpCorrelationContext.KEY_CONNECTION_ID),
				is(not(clientContext.get(TcpCorrelationContext.KEY_CONNECTION_ID))));
		assertThat(clientContextAfterReconnect, is(not(clientContext)));

		// Response message must go over the reconnected connection
		serverCallback = new SimpleMessageCallback();
		msg = ConnectorTestUtil.createMessage(serverCatcher.getMessage(1).getInetSocketAddress(), 100, serverCallback);
		server.send(msg);
		clientCatcher.blockUntilSize(2);

		CorrelationContext serverContextAfterReconnect = serverCallback.getCorrelationContext();
		assertThat("Serverside no TCP Correlation Context after reconnect", serverContextAfterReconnect,
				is(instanceOf(TcpCorrelationContext.class)));
		// new (different) server side connection id
		assertThat(serverContextAfterReconnect.get(TcpCorrelationContext.KEY_CONNECTION_ID),
				is(not(serverContext.get(TcpCorrelationContext.KEY_CONNECTION_ID))));
		assertThat(serverContextAfterReconnect, is(not(serverContext)));

	}

	@Test
	public void singleClientManyServersCorrelationContext() throws Exception {
		int serverCount = 3;
		Map<InetSocketAddress, Catcher> servers = new IdentityHashMap<>();
		for (int i = 0; i < serverCount; i++) {
			TcpServerConnector server = new TcpServerConnector(new InetSocketAddress(0),
					ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
			cleanup.add(server);
			Catcher serverCatcher = new Catcher();
			server.setRawDataReceiver(serverCatcher);
			server.start();

			servers.put(server.getAddress(), serverCatcher);
		}
		Set<InetSocketAddress> serverAddresses = servers.keySet();

		TcpClientConnector client = new TcpClientConnector(ConnectorTestUtil.NUMBER_OF_THREADS,
				ConnectorTestUtil.CONECTION_TIMEOUT_IN_MS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
		cleanup.add(client);
		Catcher clientCatcher = new Catcher();
		client.setRawDataReceiver(clientCatcher);
		client.start();

		SimpleMessageCallback clientCallback = new SimpleMessageCallback();
		List<RawData> messages = new ArrayList<>();
		for (InetSocketAddress address : serverAddresses) {
			RawData message = ConnectorTestUtil.createMessage(address, 100, clientCallback);
			messages.add(message);
			client.send(message);
		}

		for (RawData message : messages) {
			Catcher catcher = servers.get(message.getInetSocketAddress());
			catcher.blockUntilSize(1);
			assertArrayEquals(message.getBytes(), catcher.getMessage(0).getBytes());
		}

		List<RawData> followupMessages = new ArrayList<>();
		for (InetSocketAddress address : serverAddresses) {
			RawData message = ConnectorTestUtil.createMessage(address, 100, clientCallback);
			followupMessages.add(message);
			client.send(message);
		}

		for (RawData followupMessage : followupMessages) {
			Catcher catcher = servers.get(followupMessage.getInetSocketAddress());
			catcher.blockUntilSize(2);
			assertArrayEquals(followupMessage.getBytes(), catcher.getMessage(1).getBytes());
		}

		for (int index = 0; index < messages.size(); ++index) {
			RawData message = messages.get(index);
			RawData followupMessage = followupMessages.get(index);
			CorrelationContext context1 = message.getCorrelationContext();
			CorrelationContext context2 = followupMessage.getCorrelationContext();
			// same connection id used for follow up message
			assertThat(context1, is(context2));
			assertThat(context1.get(TcpCorrelationContext.KEY_CONNECTION_ID),
					is(context2.get(TcpCorrelationContext.KEY_CONNECTION_ID)));
		}
	}

}
