/*******************************************************************************
 * Copyright (c) 2016 Amazon Web Services.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * <p>
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.html.
 * <p>
 * Contributors:
 * Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 * Achim Kraus (Bosch Software Innovations GmbH) - add more logging.
 * Achim Kraus (Bosch Software Innovations GmbH) - implement checkServerTrusted
 *                                                 to check the DN more relaxed.
 * Achim Kraus (Bosch Software Innovations GmbH) - use ConnectorTestUtil
 * Achim Kraus (Bosch Software Innovations GmbH) - use create server address
 *                                                 (LoopbackAddress)
 * Achim Kraus (Bosch Software Innovations GmbH) - add NUMBER_OF_CONNECTIONS
 *                                                 and reduce it to 50
 * Achim Kraus (Bosch Software Innovations GmbH) - use demo-cert (credentials and trust)
 *                                                 and move initializeSsl to 
 *                                                 TlsConnectorTestUtil
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;
import static org.eclipse.californium.elements.tcp.ConnectorTestUtil.*;
import static org.eclipse.californium.elements.tcp.TlsConnectorTestUtil.*;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;

public class TlsConnectorTest {

	private static final int NUMBER_OF_CONNECTIONS = 10;

	@Rule
	public final Timeout timeout = new Timeout(TEST_TIMEOUT_IN_MS, TimeUnit.MILLISECONDS);

	@Rule
	public TestNameLoggerRule names = new TestNameLoggerRule();

	private final List<Connector> cleanup = new ArrayList<>();

	@BeforeClass
	public static void initializeSsl() throws Exception {
		TlsConnectorTestUtil.initializeSsl();
	}

	@After
	public void cleanup() {
		stop(cleanup);
	}

	@Test
	public void pingPongMessage() throws Exception {
		TlsServerConnector server = new TlsServerConnector(serverSslContext, createServerAddress(0), NUMBER_OF_THREADS,
				IDLE_TIMEOUT_IN_S);
		TlsClientConnector client = new TlsClientConnector(clientSslContext, NUMBER_OF_THREADS,
				CONNECTION_TIMEOUT_IN_MS, IDLE_TIMEOUT_IN_S);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		cleanup.add(server);
		cleanup.add(client);
		server.start();
		client.start();

		RawData msg = createMessage(server.getAddress(), 100, null);

		client.send(msg);
		serverCatcher.blockUntilSize(1, CATCHER_TIMEOUT_IN_MS);
		assertArrayEquals(msg.getBytes(), serverCatcher.getMessage(0).getBytes());

		// Response message must go over the same connection client already
		// opened
		msg = createMessage(serverCatcher.getMessage(0).getInetSocketAddress(), 10000, null);
		server.send(msg);
		clientCatcher.blockUntilSize(1, CATCHER_TIMEOUT_IN_MS);
		assertArrayEquals(msg.getBytes(), clientCatcher.getMessage(0).getBytes());
	}

	@Test
	public void singleServerManyClients() throws Exception {
		TlsServerConnector server = new TlsServerConnector(serverSslContext, createServerAddress(0), NUMBER_OF_THREADS,
				IDLE_TIMEOUT_IN_S);
		assertThat(server.getProtocol(), is("TLS"));
		cleanup.add(server);

		Catcher serverCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		server.start();

		List<RawData> messages = new ArrayList<>();
		for (int i = 0; i < NUMBER_OF_CONNECTIONS; i++) {
			TlsClientConnector client = new TlsClientConnector(clientSslContext, NUMBER_OF_THREADS,
					CONNECTION_TIMEOUT_IN_MS, IDLE_TIMEOUT_IN_S);
			cleanup.add(client);
			Catcher clientCatcher = new Catcher();
			client.setRawDataReceiver(clientCatcher);
			client.start();

			RawData msg = createMessage(server.getAddress(), 100, null);
			messages.add(msg);
			client.send(msg);
		}

		serverCatcher.blockUntilSize(NUMBER_OF_CONNECTIONS, CATCHER_TIMEOUT_IN_MS * NUMBER_OF_CONNECTIONS);
		for (int i = 0; i < NUMBER_OF_CONNECTIONS; i++) {
			RawData received = serverCatcher.getMessage(i);

			// Make sure that we intended to send that message
			boolean matched = false;
			for (RawData sent : messages) {
				if (Arrays.equals(sent.getBytes(), received.getBytes())) {
					matched = true;
					break;
				}
			}
			assertTrue("Received unexpected message: " + received, matched);
		}
	}

	@Test
	public void singleClientManyServers() throws Exception {
		int serverCount = 3;
		Map<InetSocketAddress, Catcher> servers = new IdentityHashMap<>();
		for (int i = 0; i < serverCount; i++) {
			TlsServerConnector server = new TlsServerConnector(serverSslContext, createServerAddress(0),
					NUMBER_OF_THREADS, IDLE_TIMEOUT_IN_S);
			cleanup.add(server);
			Catcher serverCatcher = new Catcher();
			server.setRawDataReceiver(serverCatcher);
			server.start();

			servers.put(getDestination(server.getAddress()), serverCatcher);
		}

		TlsClientConnector client = new TlsClientConnector(clientSslContext, NUMBER_OF_THREADS,
				CONNECTION_TIMEOUT_IN_MS, IDLE_TIMEOUT_IN_S);
		cleanup.add(client);
		Catcher clientCatcher = new Catcher();
		client.setRawDataReceiver(clientCatcher);
		client.start();

		List<RawData> messages = new ArrayList<>();
		for (InetSocketAddress address : servers.keySet()) {
			RawData message = createMessage(address, 100, null);
			messages.add(message);
			client.send(message);
		}

		for (RawData message : messages) {
			Catcher catcher = servers.get(message.getInetSocketAddress());
			catcher.blockUntilSize(1, CATCHER_TIMEOUT_IN_MS);
			assertArrayEquals(message.getBytes(), catcher.getMessage(0).getBytes());
		}
	}
}
