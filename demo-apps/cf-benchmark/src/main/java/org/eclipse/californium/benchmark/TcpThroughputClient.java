/*******************************************************************************
 * Copyright (c) 2016, 2017 Amazon Web Services and others.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * <p>
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.html.
 * <p>
 * Contributors:
 * Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 * Achim Kraus (Bosch Software Innovations GmbH) - add NetworkConfig setup
 ******************************************************************************/

package org.eclipse.californium.benchmark;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.tcp.netty.TcpClientConnector;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.TimeUnit;

public class TcpThroughputClient {
	private static final File CONFIG_FILE = new File("CaliforniumTcpClient.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for TCP client";

	public static void main(String[] args) throws ConnectorException, IOException {
		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, null);
		int tcpThreads = config.getInt(Keys.TCP_WORKER_THREADS);
		int tcpConnectTimeout = config.getInt(Keys.TCP_CONNECT_TIMEOUT);
		int tcpIdleTimeout = config.getInt(Keys.TCP_CONNECTION_IDLE_TIMEOUT);
		int tcpPort = config.getInt(Keys.COAP_PORT);
		TcpClientConnector connector = new TcpClientConnector(tcpThreads, tcpConnectTimeout, tcpIdleTimeout);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setConnector(connector);
		builder.setNetworkConfig(config);
		EndpointManager.getEndpointManager().setDefaultEndpoint(builder.build());
		CoapClient coapClient = new CoapClient("coap+tcp", "localhost", tcpPort, "echo");
		try {
			Random random = new Random(0);
			long messages = 200_000;
			long total = 0;

			long start = System.nanoTime();
			for (int i = 0; i < messages; i++) {
				byte data[] = new byte[random.nextInt(1024 * 2)];
				total += data.length;

				random.nextBytes(data);
				CoapResponse put = coapClient.put(data, 60);

				if (put == null || !put.isSuccess()) {
					throw new RuntimeException("Did not receive response on request #" + i);
				}
				byte[] result = put.getPayload();
				if (result == null) {
					result = Bytes.EMPTY;
				}
				if (!Arrays.equals(data, result)) {
					System.out.format("sent: %d bytes, %s%n", data.length, StringUtil.byteArray2HexString(data, ' ', 32));
					System.out.format("recv: %d bytes, %s%n", result.length, StringUtil.byteArray2HexString(result, ' ', 32));
					throw new RuntimeException("Mismatched response on request #" + i);
				}
			}
			long end = System.nanoTime();

			System.out.println(messages + " messages in " + TimeUnit.NANOSECONDS.toMillis(end - start) + "ms");
			System.out.println("Rate " + messages / TimeUnit.NANOSECONDS.toSeconds(end - start) + " msg/s");
			System.out.println("Bandwidth " + total / TimeUnit.NANOSECONDS.toSeconds(end - start) / 1024 / 1024 + " MB/s");
		} finally {
			coapClient.shutdown();
			EndpointManager.reset();
		}
	}
}
