/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - get MAX_RETRANSMIT without
 *                                                    changing the NetworkConfig 
 *                                                    standard.
 *    Achim Kraus (Bosch Software Innovations GmbH) - correct thread safe
 *                                                    set of drops
 ******************************************************************************/
package org.eclipse.californium.core.test.maninmiddle;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;

import org.eclipse.californium.core.test.lockstep.ClientBlockwiseInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The man in the middle is between the server and client and monitors the
 * communication. It can drop a packet to simulate packet loss.
 */
public class ManInTheMiddle implements Runnable {
	private static final Logger LOGGER = LoggerFactory.getLogger(ManInTheMiddle.class);

	private final int clientPort;
	private final int serverPort;

	private final DatagramSocket socket;
	private final DatagramPacket packet;
	private final ClientBlockwiseInterceptor interceptor;
	private final Thread thread;
	private volatile boolean running = true;

	private int[] drops = new int[0];

	// drop bursts longer than MAX_RETRANSMIT must be avoided
	private final int max;

	public ManInTheMiddle(final InetAddress bindAddress, final int clientPort, final int serverPort, final int maxRetransmissions, final ClientBlockwiseInterceptor interceptor) throws Exception {

		this.max = maxRetransmissions;
		this.clientPort = clientPort;
		this.serverPort = serverPort;
		this.interceptor = interceptor;
		if (bindAddress == null) {
			this.socket = new DatagramSocket();
		} else {
			this.socket = new DatagramSocket(0, bindAddress);
		}
		this.packet = new DatagramPacket(new byte[2000], 2000);

		thread = new Thread(this);
		thread.start();
	}

	public void drop(int... numbers) {
		LOGGER.info(interceptor.toString());
		LOGGER.info("");
		interceptor.clear();

		Arrays.sort(numbers);

		interceptor.log("Man in the middle will drop packets " + Arrays.toString(numbers));
		synchronized(this) {
			drops = numbers;
		}
	}

	@Override
	public void run() {
		try {
			LOGGER.info("Starting man in the middle...");
			int current = 0;
			int last = -3;
			int burst = 1;
			int drops[] = null;
			while (running) {
				socket.receive(packet);

				boolean isClientPacket = packet.getPort() == clientPort;

				synchronized (this) {
					if (drops != this.drops) {
						drops= this.drops;
						// new drops, reset counters
						current = 0;
						last = -3;
						burst = 1;
					}
				}

				if (burst < max && contains(drops, current)) {
					if (last + 1 == current || last + 2 == current) {
						burst++;
					}
					interceptor.log(String.format(" Dropping packet %d (burst %d/%d) from %s", 
							current, burst, max, isClientPacket ? "client" : "server"));
					last = current;
				} else {
					if (isClientPacket) {
						packet.setPort(serverPort);
					} else {
						packet.setPort(clientPort);
					}
					socket.send(packet);
					if (last + 1 != current && last + 2 != current) {
						burst = 1;
					}
					//System.out.println("Forwarding " + packet.getLength() + " "+current+" ("+last+" burst "+burst+")");
				}
				current++;
			}
		} catch (Exception e) {
			if (running) {
				e.printStackTrace();
			}
		}
	}

	public void stop() {
		running = false;
		socket.close();
		thread.interrupt();
		LOGGER.info(interceptor.toString());
		interceptor.clear();
		try {
			thread.join(2000);
		} catch (InterruptedException e) {
		}
	}

	public int getPort() {
		return socket.getLocalPort();
	}

	private static boolean contains(final int[] array, final int value) {
		return (array != null) && (Arrays.binarySearch(array, value) >= 0);
	}
}
