/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation.
 *                                                    Modified variant of
 *              org.eclipse.californium.core.test.maninmiddle.ManInTheMiddle
 ******************************************************************************/

package org.eclipse.californium.secure.test;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;

/**
 * Test util to emulate a NAT.
 *
 * Possibly exchange the visible source address of messages.
 */
public class TestUtilNat {

	private static final int DATAGRAM_SIZE = 2000;

	/**
	 * Client side port.
	 */
	private final int clientPort;
	/**
	 * Server side port.
	 */
	private final int serverPort;

	/**
	 * Normal socket to forward message.
	 */
	private DatagramSocket socket1;
	/**
	 * Alternative socket to forward message, if {@link #changeServerAddress} is
	 * {@code true}.
	 */
	private DatagramSocket socket2;
	/**
	 * Packet to forward a message to the server.
	 */
	private DatagramPacket packet1;
	/**
	 * Packet to return a message to the client.
	 */
	private DatagramPacket packet2;

	/**
	 * Running/shutdown indicator.
	 */
	private volatile boolean running = true;
	/**
	 * Flag to enable alternative forwarding of message. Emulates a address
	 * change.
	 */
	private volatile boolean changeServerAddress = false;

	/**
	 * Create a new test util NAT.
	 * 
	 * @param bindAddress address to bin to, or {@code null}, if any should be
	 *            used.
	 * @param clientPort port of client
	 * @param serverPort port of server
	 * @throws Exception if an error occurred
	 */
	public TestUtilNat(final InetAddress bindAddress, final int clientPort, final int serverPort) throws Exception {

		this.clientPort = clientPort;
		this.serverPort = serverPort;

		if (bindAddress == null) {
			this.socket1 = new DatagramSocket();
			this.socket2 = new DatagramSocket();
		} else {
			this.socket1 = new DatagramSocket(0, bindAddress);
			this.socket2 = new DatagramSocket(0, bindAddress);
		}
		this.packet1 = new DatagramPacket(new byte[DATAGRAM_SIZE], DATAGRAM_SIZE);
		this.packet2 = new DatagramPacket(new byte[DATAGRAM_SIZE], DATAGRAM_SIZE);

		new Thread(new Runnable() {

			@Override
			public void run() {
				runNat(packet1, socket1, socket2);
			}
		}).start();
		new Thread(new Runnable() {

			@Override
			public void run() {
				runBack(packet2, socket1, socket2);
			}
		}).start();
	}

	/**
	 * Loop to exchange messages between client and server.
	 * 
	 * @param packet packet to receive and forward a message
	 * @param socketRecv normal socket to forward a message
	 * @param socketSec alternative socket to forward a message.
	 */
	private void runNat(DatagramPacket packet, DatagramSocket socketRecv, DatagramSocket socketSec) {
		try {
			System.out.println("Starting test-NAT...");
			while (running) {
				packet.setLength(DATAGRAM_SIZE);
				socketRecv.receive(packet);
				DatagramSocket send = socketRecv;
				System.out.println("Forward " + packet.getLength() + " bytes.");
				boolean isClientPacket = packet.getPort() == clientPort;
				if (isClientPacket) {
					packet.setPort(serverPort);
				} else {
					packet.setPort(clientPort);
					if (changeServerAddress) {
						send = socketSec;
					}
				}
				send.send(packet);
			}
		} catch (SocketException e) {
			if (running) {
				e.printStackTrace();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Loop to exchange messages between client and server using the alternative
	 * socket.
	 * 
	 * @param packet packet to receive and forward a message
	 * @param socketRecv normal socket to forward a message
	 * @param socketSec alternative socket to forward a message.
	 */
	private void runBack(DatagramPacket packet, DatagramSocket socketRecv, DatagramSocket socketSec) {
		try {
			System.out.println("Starting test-NAT (backwards) ...");
			while (running) {
				packet.setLength(DATAGRAM_SIZE);
				socketSec.receive(packet);
				System.out.println("Backward " + packet.getLength() + " bytes.");
				boolean isClientPacket = packet.getPort() == clientPort;
				if (isClientPacket) {
					packet.setPort(serverPort);
				} else {
					packet.setPort(clientPort);
				}
				socketRecv.send(packet);
			}
		} catch (SocketException e) {
			if (running) {
				e.printStackTrace();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Stop NAT.
	 */
	public void stop() {
		running = false;
		socket1.close();
		socket2.close();
	}

	/**
	 * Enable/disable address change when forwarding.
	 * 
	 * @param change {@code true}, if address should be changed, {@code true},
	 *            otherwise
	 */
	public void setChangeServerAddress(boolean change) {
		changeServerAddress = change;
	}

	/**
	 * Port or normal socket.
	 * 
	 * @return port of normal socket
	 */
	public int getPort1() {
		return socket1.getLocalPort();
	}

	/**
	 * Port or alternative socket.
	 * 
	 * @return port of alternative socket
	 */
	public int getPort2() {
		return socket2.getLocalPort();
	}
}
