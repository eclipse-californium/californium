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
 ******************************************************************************/

package org.eclipse.californium.examples;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Test util to emulate a NAT.
 *
 * Provide function to change the address mapping.
 * 
 * @see #assignLocalAddress(InetSocketAddress)
 * @see #reassignLocalAddresses()
 */
public class NatUtil implements Runnable {

	private static final Logger LOGGER = Logger.getLogger(NatUtil.class.getCanonicalName());

	/**
	 * Supported maximum message size.
	 */
	private static final int DATAGRAM_SIZE = 2048;
	/**
	 * Socket timeout for logs and NAT timeout checks.
	 */
	private static final int SOCKET_TIMEOUT_MS = 1000 * 60;
	/**
	 * NAT timeout. Checked, when socket timeout occurs.
	 */
	private static final int NAT_TIMEOUT_MS = 1000 * 60;
	/**
	 * The name of the proxy interface address.
	 */
	private final String proxyName;
	/**
	 * Destination address.
	 */
	private final InetSocketAddress destination;
	/**
	 * The name of the destination address.
	 */
	private final String destinationName;
	/**
	 * Socket to receive incoming message for the NAT.
	 */
	private final DatagramSocket proxySocket;
	/**
	 * Packet to receive incoming message for the NAT.
	 */
	private final DatagramPacket proxyPacket;

	/**
	 * Map of external incoming addresses to local used addresses for forwarding
	 * the messages to the destination.
	 */
	private final ConcurrentMap<InetSocketAddress, NatEntry> nats = new ConcurrentHashMap<InetSocketAddress, NatEntry>();
	/**
	 * Running/shutdown indicator.
	 */
	private volatile boolean running = true;

	/**
	 * Create a new NAT util.
	 * 
	 * @param bindAddress address to bind to, or {@code null}, if any should be
	 * @param destination destination address to forward the messages using a
	 *            local port
	 * @throws Exception if an error occurred
	 */
	public NatUtil(final InetSocketAddress bindAddress, final InetSocketAddress destination) throws Exception {
		this.destination = destination;
		if (bindAddress == null) {
			proxySocket = new DatagramSocket();
		} else {
			proxySocket = new DatagramSocket(bindAddress);
		}
		proxySocket.setSoTimeout(SOCKET_TIMEOUT_MS);
		InetSocketAddress proxy = (InetSocketAddress) proxySocket.getLocalSocketAddress();
		this.proxyName = proxy.getHostString() + ":" + proxy.getPort();
		this.destinationName = destination.getHostString() + ":" + destination.getPort();
		this.proxyPacket = new DatagramPacket(new byte[DATAGRAM_SIZE], DATAGRAM_SIZE);

		new Thread(this).start();
	}

	@Override
	public void run() {
		LOGGER.log(Level.INFO, "Starting NAT {0} to {1}.", new Object[] { proxyName, destinationName });
		while (running) {
			try {
				proxyPacket.setLength(DATAGRAM_SIZE);
				proxySocket.receive(proxyPacket);
				if (running) {
					InetSocketAddress incoming = (InetSocketAddress) proxyPacket.getSocketAddress();
					NatEntry entry = nats.get(incoming);
					if (null == entry) {
						entry = new NatEntry(incoming);
						nats.put(incoming, entry);
					}
					entry.forward(proxyPacket);
				}
			} catch (SocketTimeoutException e) {
				if (running) {
					LOGGER.log(Level.INFO, "Listen NAT {0} to {1} ...", new Object[] { proxyName, destinationName });
				}
			} catch (SocketException e) {
				if (running) {
					e.printStackTrace();
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * Stop the NAT.
	 */
	public void stop() {
		running = false;
		proxySocket.close();
		stopAllNatEntries();
	}

	/**
	 * Stop all NAT entries in {@link #nats} and clear that map.
	 */
	public void stopAllNatEntries() {
		for (NatEntry entry : nats.values()) {
			entry.stop();
		}
		nats.clear();
	}

	/**
	 * Reassign all local addresses of NAT entries.
	 */
	public void reassignLocalAddresses() {
		Set<InetSocketAddress> keys = new HashSet<InetSocketAddress>();
		keys.addAll(nats.keySet());
		for (InetSocketAddress incoming : keys) {
			try {
				assignLocalAddress(incoming);
			} catch (SocketException e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * Assign local addresses for incoming address.
	 * 
	 * @param incoming incoming address a local address is to be assigned
	 * @return port number of the assigned local address
	 * @throws SocketException if reassign failed opening the new local socket
	 */
	public int assignLocalAddress(InetSocketAddress incoming) throws SocketException {
		NatEntry entry = new NatEntry(incoming);
		NatEntry old = nats.put(incoming, entry);
		if (null != old) {
			LOGGER.log(Level.INFO, "Changed NAT for {0} from {1} to {2}.",
					new Object[] { incoming, old.getPort(), entry.getPort() });
			old.stop();
		} else {
			LOGGER.log(Level.INFO, "Add NAT for {0} to {1}.", new Object[] { incoming, entry.getPort() });
		}
		return entry.getPort();
	}

	/**
	 * Remove mapping for incoming inet address.
	 * 
	 * @param incoming inet address to remove mapping
	 * @return {@code true} , if mapping is removed, {@code false}, if no
	 *         mapping was available.
	 */
	public boolean removeLocalAddress(InetSocketAddress incoming) {
		NatEntry entry = nats.remove(incoming);
		if (null != entry) {
			entry.stop();
		} else {
			LOGGER.log(Level.WARNING, "No mappigng found for {0}!", incoming);
		}
		return null != entry;
	}

	/**
	 * Get socket address of proxy.
	 * 
	 * @return socket address of proxy
	 */
	public InetSocketAddress getProxySocketAddress() {
		return (InetSocketAddress) proxySocket.getLocalSocketAddress();
	}

	/**
	 * NAT mapping entry.
	 * 
	 * Maps incoming inet addresses to local sockets.
	 */
	private class NatEntry implements Runnable {

		/**
		 * Mapped incoming inet address.
		 */
		private final InetSocketAddress incoming;
		private final DatagramSocket outgoingSocket;
		private final DatagramPacket packet;
		private final String incomingName;
		private final String natName;
		private volatile boolean running = true;
		private volatile boolean stop = false;
		private final AtomicLong lastUsage = new AtomicLong(System.nanoTime());

		public NatEntry(InetSocketAddress incoming) throws SocketException {
			this.incoming = incoming;
			outgoingSocket = new DatagramSocket(0);
			outgoingSocket.setSoTimeout(SOCKET_TIMEOUT_MS);
			packet = new DatagramPacket(new byte[DATAGRAM_SIZE], DATAGRAM_SIZE);
			incomingName = incoming.getHostString() + ":" + incoming.getPort();
			natName = Integer.toString(outgoingSocket.getLocalPort());
			new Thread(this).start();
		}

		@Override
		public void run() {
			LOGGER.log(Level.INFO, "Start listen on {0} for incoming {1}", new Object[] { natName, incomingName });
			try {
				while (running) {
					try {
						packet.setLength(DATAGRAM_SIZE);
						outgoingSocket.receive(packet);
						lastUsage.set(System.nanoTime());
						packet.setSocketAddress(incoming);
						LOGGER.log(Level.INFO, "Backward {0} bytes from {1} to {2} via {3}",
								new Object[] { packet.getLength(), destinationName, incomingName, natName });
						proxySocket.send(packet);
					} catch (SocketTimeoutException e) {
						if (running) {
							if (TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - lastUsage.get()) > NAT_TIMEOUT_MS) {
								running = false;
								LOGGER.log(Level.INFO, "Expired listen on {0} for incoming {1}",
										new Object[] { natName, incomingName });
							} else {
								LOGGER.log(Level.FINE, "Listen on {0} for incoming {1}",
										new Object[] { natName, incomingName });
							}
						}
					} catch (IOException e) {
						if (running) {
							e.printStackTrace();
						}
					}
				}
			} finally {
				LOGGER.log(Level.INFO, "Stop listen on {0} for incoming {1}", new Object[] { natName, incomingName });
				outgoingSocket.close();
				if (!stop) {
					nats.remove(incoming, this);
				}
			}
		}

		public void stop() {
			stop = true;
			running = false;
			outgoingSocket.close();
		}

		public int getPort() {
			return outgoingSocket.getLocalPort();
		}

		public void forward(DatagramPacket packet) throws IOException {
			LOGGER.log(Level.INFO, "Forward {0} bytes from {1} to {2} via {3}",
					new Object[] { packet.getLength(), incomingName, destinationName, natName });
			packet.setSocketAddress(destination);
			lastUsage.set(System.nanoTime());
			outgoingSocket.send(packet);
		}
	}
}
