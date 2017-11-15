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
 *    Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 *    Achim Kraus (Bosch Software Innovations GmbH) - use ConnectorTestUtil
 *    Achim Kraus (Bosch Software Innovations GmbH) - use create server address
 *                                                    (LoopbackAddress)
 *    Achim Kraus (Bosch Software Innovations GmbH) - add NUMBER_OF_CONNECTIONS
 *                                                    and reduce it to 50
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import static org.eclipse.californium.elements.tcp.ConnectorTestUtil.*;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.RawData;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class TcpConnectorTest {

	private static final int NUMBER_OF_CONNECTIONS = 50;
	private static final int NUMBER_OF_THREADS = 1;
	private static final int IDLE_TIMEOUT = 100;

	@Rule
	public final Timeout timeout = new Timeout(20, TimeUnit.SECONDS);

	private final int messageSize;
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
		TcpServerConnector server = new TcpServerConnector(createServerAddress(0), NUMBER_OF_THREADS, IDLE_TIMEOUT);
		TcpClientConnector client = new TcpClientConnector(NUMBER_OF_THREADS, 100, IDLE_TIMEOUT);

		cleanup.add(server);
		cleanup.add(client);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		server.start();
		client.start();

		RawData msg = createMessage(server.getAddress(), messageSize, null, null);

		client.send(msg);
		serverCatcher.blockUntilSize(1);
		assertArrayEquals(msg.getBytes(), serverCatcher.getMessage(0).getBytes());

		// Response message must go over the same connection client already
		// opened
		msg = createMessage(serverCatcher.getMessage(0).getInetSocketAddress(), messageSize, null, null);
		server.send(msg);
		clientCatcher.blockUntilSize(1);
		assertArrayEquals(msg.getBytes(), clientCatcher.getMessage(0).getBytes());
	}

	@Test
	public void singleServerManyClients() throws Exception {
		TcpServerConnector server = new TcpServerConnector(createServerAddress(0), NUMBER_OF_THREADS, IDLE_TIMEOUT);
		cleanup.add(server);

		Catcher serverCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		server.start();

		List<RawData> messages = new ArrayList<>();
		for (int i = 0; i < NUMBER_OF_CONNECTIONS; i++) {
			TcpClientConnector client = new TcpClientConnector(NUMBER_OF_THREADS, 100, IDLE_TIMEOUT);
			cleanup.add(client);
			Catcher clientCatcher = new Catcher();
			client.setRawDataReceiver(clientCatcher);
			client.start();

			RawData msg = createMessage(server.getAddress(), messageSize, null, null);
			messages.add(msg);
			client.send(msg);
		}

		serverCatcher.blockUntilSize(NUMBER_OF_CONNECTIONS);
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
}
