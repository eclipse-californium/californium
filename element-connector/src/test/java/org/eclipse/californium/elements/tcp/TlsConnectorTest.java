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
 * Achim Kraus (Bosch Software Innovations GmbH) - use demo-cert and
 *                                                 getAddress() of server.
 *                                                 move initializeSsl to
 *                                                 new ConnectorTestUtil
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.RawData;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;

public class TlsConnectorTest {

	private static final int NUMBER_OF_THREADS = 1;
	private static final int IDLE_TIMEOUT = 100;
	private static SSLContext serverContext;
	private static SSLContext clientContext;
	private final Random random = new Random(0);

	@Rule
	public final Timeout timeout = new Timeout(10, TimeUnit.SECONDS);
	private final List<Connector> cleanup = new ArrayList<>();

	@BeforeClass
	public static void initializeSsl() throws Exception {
		ConnectorTestUtil.initializeSsl();
		serverContext = ConnectorTestUtil.serverContext;
		clientContext = ConnectorTestUtil.clientContext;
	}

	@After
	public void cleanup() {
		for (Connector connector : cleanup) {
			connector.stop();
		}
	}

	@Test
	public void pingPongMessage() throws Exception {
		TlsServerConnector server = new TlsServerConnector(serverContext, new InetSocketAddress(0),
				NUMBER_OF_THREADS, IDLE_TIMEOUT);
		TlsClientConnector client = new TlsClientConnector(clientContext, NUMBER_OF_THREADS, 100, 10);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		cleanup.add(server);
		cleanup.add(client);
		server.start();
		client.start();

		RawData msg = createMessage(server.getAddress(), 100);

		client.send(msg);
		serverCatcher.blockUntilSize(1);
		assertArrayEquals(msg.getBytes(), serverCatcher.getMessage(0).getBytes());

		// Response message must go over the same connection client already
		// opened
		msg = createMessage(serverCatcher.getMessage(0).getInetSocketAddress(), 10000);
		server.send(msg);
		clientCatcher.blockUntilSize(1);
		assertArrayEquals(msg.getBytes(), clientCatcher.getMessage(0).getBytes());
	}

	@Test
	public void singleServerManyClients() throws Exception {
		int clients = 100;
		TlsServerConnector server = new TlsServerConnector(serverContext, new InetSocketAddress(0),
				NUMBER_OF_THREADS, IDLE_TIMEOUT);
		assertThat(server.getUri().getScheme(), is("coaps+tcp"));
		cleanup.add(server);

		Catcher serverCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		server.start();

		List<RawData> messages = new ArrayList<>();
		for (int i = 0; i < clients; i++) {
			TlsClientConnector client = new TlsClientConnector(clientContext, NUMBER_OF_THREADS, 100, IDLE_TIMEOUT);
			cleanup.add(client);
			Catcher clientCatcher = new Catcher();
			client.setRawDataReceiver(clientCatcher);
			client.start();

			RawData msg = createMessage(server.getAddress(), 100);
			messages.add(msg);
			client.send(msg);
		}

		serverCatcher.blockUntilSize(clients);
		for (int i = 0; i < clients; i++) {
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
			TlsServerConnector server = new TlsServerConnector(serverContext, new InetSocketAddress(0),
					NUMBER_OF_THREADS, IDLE_TIMEOUT);
			cleanup.add(server);
			Catcher serverCatcher = new Catcher();
			server.setRawDataReceiver(serverCatcher);
			server.start();

			servers.put(server.getAddress(), serverCatcher);
		}

		TlsClientConnector client = new TlsClientConnector(clientContext, NUMBER_OF_THREADS, 100, IDLE_TIMEOUT);
		cleanup.add(client);
		Catcher clientCatcher = new Catcher();
		client.setRawDataReceiver(clientCatcher);
		client.start();

		List<RawData> messages = new ArrayList<>();
		for (InetSocketAddress address : servers.keySet()) {
			RawData message = createMessage(address, 100);
			messages.add(message);
			client.send(message);
		}

		for (RawData message : messages) {
			Catcher catcher = servers.get(message.getInetSocketAddress());
			catcher.blockUntilSize(1);
			assertArrayEquals(message.getBytes(), catcher.getMessage(0).getBytes());
		}
	}

	private RawData createMessage(InetSocketAddress address, int messageSize) throws Exception {
		byte[] data = new byte[messageSize];
		random.nextBytes(data);

		try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
			if (messageSize < 13) {
				stream.write(messageSize << 4);
			} else if (messageSize < (1 << 8) + 13) {
				stream.write(13 << 4);
				stream.write(messageSize - 13);
			} else if (messageSize < (1 << 16) + 269) {
				stream.write(14 << 4);

				ByteBuffer buffer = ByteBuffer.allocate(2);
				buffer.putShort((short) (messageSize - 269));
				stream.write(buffer.array());
			} else {
				stream.write(15 << 4);

				ByteBuffer buffer = ByteBuffer.allocate(4);
				buffer.putInt(messageSize - 65805);
				stream.write(buffer.array());
			}

			stream.write(1); // GET
			stream.write(data);
			stream.flush();
			return new RawData(stream.toByteArray(), address);
		}
	}
}
