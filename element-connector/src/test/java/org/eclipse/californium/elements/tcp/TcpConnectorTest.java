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
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.RawData;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class TcpConnectorTest {

	private static final int NUMBER_OF_THREADS = 1;
	private static final int IDLE_TIMEOUT = 100;

	@Rule
	public final Timeout timeout = new Timeout(20, TimeUnit.SECONDS);

	private final int messageSize;
	private final Random random = new Random();
	private final List<Connector> cleanup = new ArrayList<>();

	@Parameterized.Parameters
	public static List<Object[]> parameters() {
		// Trying different messages size to hit sharp corners in Coap-over-TCP
		// spec
		List<Object[]> parameters = new ArrayList<>();
		parameters.add(new Object[] { 0 });
		parameters.add(new Object[] { 7 });
		parameters.add(new Object[] { 13 });
		parameters.add(new Object[] { 35 });
		parameters.add(new Object[] { 269 });
		parameters.add(new Object[] { 313 });
		parameters.add(new Object[] { 65805 });
		parameters.add(new Object[] { 389805 });

		return parameters;
	}

	public TcpConnectorTest(int messageSize) {
		this.messageSize = messageSize;
	}

	@After
	public void cleanup() {
		for (Connector connector : cleanup) {
			connector.stop();
		}
	}

	@Test
	public void serverClientPingPong() throws Exception {
		int port = findEphemeralPort();
		TcpServerConnector server = new TcpServerConnector(new InetSocketAddress(port), NUMBER_OF_THREADS,
				IDLE_TIMEOUT);
		TcpClientConnector client = new TcpClientConnector(NUMBER_OF_THREADS, 100, IDLE_TIMEOUT);

		cleanup.add(server);
		cleanup.add(client);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		server.start();
		client.start();

		RawData msg = createMessage(new InetSocketAddress(port));

		client.send(msg);
		serverCatcher.blockUntilSize(1);
		assertArrayEquals(msg.getBytes(), serverCatcher.getMessage(0).getBytes());

		// Response message must go over the same connection client already
		// opened
		msg = createMessage(serverCatcher.getMessage(0).getInetSocketAddress());
		server.send(msg);
		clientCatcher.blockUntilSize(1);
		assertArrayEquals(msg.getBytes(), clientCatcher.getMessage(0).getBytes());
	}

	@Test
	public void singleServerManyClients() throws Exception {
		int port = findEphemeralPort();
		int clients = 100;
		TcpServerConnector server = new TcpServerConnector(new InetSocketAddress(port), NUMBER_OF_THREADS, IDLE_TIMEOUT);
		cleanup.add(server);

		Catcher serverCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		server.start();

		List<RawData> messages = new ArrayList<>();
		for (int i = 0; i < clients; i++) {
			TcpClientConnector client = new TcpClientConnector(NUMBER_OF_THREADS, 100, IDLE_TIMEOUT);
			cleanup.add(client);
			Catcher clientCatcher = new Catcher();
			client.setRawDataReceiver(clientCatcher);
			client.start();

			RawData msg = createMessage(new InetSocketAddress(port));
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

	private static int findEphemeralPort() {
		try (ServerSocket socket = new ServerSocket(0)) {
			return socket.getLocalPort();
		} catch (IOException e) {
			throw new IllegalStateException("Unable to bind to ephemeral port");
		}
	}

	private RawData createMessage(InetSocketAddress address) throws Exception {
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
