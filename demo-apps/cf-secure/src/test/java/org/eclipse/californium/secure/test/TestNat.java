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
 *                                                    Modified variant of ManInTheMiddle
 ******************************************************************************/

package org.eclipse.californium.secure.test;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;

public class TestNat {

	private static final int DATAGRAM_SIZE = 2000;

	private final int clientPort;
	private final int serverPort;

	private DatagramSocket socket1;
	private DatagramSocket socket2;
	private DatagramPacket packet1;
	private DatagramPacket packet2;

	private volatile boolean running = true;
	private volatile boolean changeServerAddress = false;

	public TestNat(final InetAddress bindAddress, final int clientPort, final int serverPort) throws Exception {

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

	public void stop() {
		running = false;
		socket1.close();
		socket2.close();
	}

	public void setChangeServerAddress(boolean change) {
		changeServerAddress = change;
	}

	public int getPort1() {
		return socket1.getLocalPort();
	}

	public int getPort2() {
		return socket2.getLocalPort();
	}
}
