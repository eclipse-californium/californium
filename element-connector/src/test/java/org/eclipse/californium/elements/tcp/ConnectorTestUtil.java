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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation
 *                                                    stuff copied from TcpConnectorTest
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Random;

import org.eclipse.californium.elements.MessageCallback;
import org.eclipse.californium.elements.RawData;

/**
 * Utils for TCP based connector tests.
 */
public class ConnectorTestUtil {

	public static final int NUMBER_OF_THREADS = 1;
	public static final int CONECTION_TIMEOUT_IN_MS = 100;
	public static final int IDLE_TIMEOUT_IN_S = 100;
	public static final int IDLE_TIMEOUT_RECONNECT_IN_S = 2;
	public static final int CONTEXT_TIMEOUT_IN_MS = 1000;

	private static final Random random = new Random(0);

	public static RawData createMessage(InetSocketAddress address, int messageSize, MessageCallback callback)
			throws Exception {
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
			return RawData.outbound(stream.toByteArray(), address, callback, false);
		}
	}
}
