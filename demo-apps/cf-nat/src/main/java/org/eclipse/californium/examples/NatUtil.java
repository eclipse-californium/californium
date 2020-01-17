/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation.
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - add message dropping.
 ******************************************************************************/

package org.eclipse.californium.examples;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Test util to emulate a NAT.
 *
 * Provide function to change the address mapping.
 * 
 * @see #assignLocalAddress(InetSocketAddress)
 * @see #reassignNewLocalAddresses()
 */
public class NatUtil implements Runnable {

	private static final Logger LOGGER = LoggerFactory.getLogger(NatUtil.class);
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
	 * Message dropping log interval.
	 */
	private static final int MESSAGE_DROPPING_LOG_INTERVAL_MS = 1000 * 10;
	/**
	 * Thread group for NAT.
	 */
	private static final ThreadGroup NAT_THREAD_GROUP = new ThreadGroup("NAT");
	/**
	 * Counter for NAT threads
	 */
	private static final AtomicInteger NAT_THREAD_COUNTER = new AtomicInteger();

	static {
		NAT_THREAD_GROUP.setDaemon(false);
	}
	/**
	 * The thread for the proxy.
	 */
	private final Thread proxyThread;
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
	 * Scheduler for reordering.
	 */
	private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2, new ThreadFactory() {

		@Override
		public Thread newThread(Runnable runnable) {
			final Thread ret = new Thread(NAT_THREAD_GROUP, runnable, "NAT-" + NAT_THREAD_COUNTER.getAndIncrement(), 0);
			ret.setDaemon(true);
			return ret;
		}
	});
	/**
	 * Running/shutdown indicator.
	 */
	private volatile boolean running = true;
	/**
	 * Nano time for next message dropping statistic log.
	 * 
	 * @see #dumpMessageDroppingStatistic()
	 */
	private AtomicLong messageDroppingLogTime = new AtomicLong();
	/**
	 * Counter for forwarded messages.
	 */
	private AtomicLong forwardCounter = new AtomicLong();
	/**
	 * Counter for backwarded messages.
	 */
	private AtomicLong backwardCounter = new AtomicLong();

	/**
	 * Message transmission manipulation configuration.
	 */
	private static class TransmissionManipulation {

		/**
		 * Title for statistic.
		 */
		private final String title;
		/**
		 * Random for message transmission manipulation.
		 */
		protected final Random random = new Random();
		/**
		 * Threshold in percent. 0 := no message transmission manipulation.
		 */
		private final int threshold;
		/**
		 * Counter for not manipulated message transmissions.
		 */
		private final AtomicInteger sentMessages = new AtomicInteger();
		/**
		 * Counter for manipulated message transmissions.
		 */
		private final AtomicInteger manipulatedMessages = new AtomicInteger();

		/**
		 * Create instance.
		 * 
		 * @param title title for statistic dump
		 * @param threshold threshold in percent
		 */
		public TransmissionManipulation(String title, int threshold) {
			this.title = title;
			this.threshold = threshold;
			this.random.setSeed(threshold);
		}

		/**
		 * Check, if message should be manipulated.
		 * 
		 * @return {@code true}, if message should be manipulated,
		 *         {@code false}, if message should be sent.
		 */
		public boolean manipulateMessage() {
			if (threshold == 0) {
				return false;
			} else if (threshold == 100) {
				return true;
			} else if (threshold > random.nextInt(100)) {
				manipulatedMessages.incrementAndGet();
				return true;
			} else {
				sentMessages.incrementAndGet();
				return false;
			}
		}

		/**
		 * Dump message manipulation statistic to log.
		 */
		public void dumpStatistic() {
			int sent = sentMessages.get();
			int manipulated = manipulatedMessages.get();
			if (sent > 0) {
				LOGGER.warn("manipulated {} {}/{}%, sent {} {}.", title, manipulated,
						manipulated * 100 / (manipulated + sent), title, sent);
			} else if (manipulated > 0) {
				LOGGER.warn("manipulated {} {}/100%, no {} sent!.", title, manipulated, title);
			}
		}
	}

	/**
	 * Message dropping configuration.
	 */
	private static class MessageDropping extends TransmissionManipulation {

		/**
		 * Create instance.
		 * 
		 * @param title title for statistic dump
		 * @param threshold threshold in percent
		 */
		public MessageDropping(String title, int threshold) {
			super(title + " drops", threshold);
		}

		/**
		 * Check, if message should be dropped.
		 * 
		 * @return {@code true}, if message should be dropped, {@code false}, if
		 *         message should be sent.
		 */
		public boolean dropMessage() {
			return manipulateMessage();
		}
	}

	/**
	 * Message dropping configuration.
	 */
	private class MessageReordering extends TransmissionManipulation {

		private final NatEntry entry;
		private final int delayMillis;
		private final int randomDelayMillis;
		private boolean reordering = true;
		
		public MessageReordering(String title, int threshold, int delayMillis, int randomDelayMillis) {
			super(title + " reorders", threshold);
			this.delayMillis = delayMillis;
			this.randomDelayMillis = randomDelayMillis;
			this.entry = null;
		}

		public MessageReordering(String title, NatEntry entry, int threshold, int delayMillis, int randomDelayMillis) {
			super(title + " reorders", threshold);
			this.delayMillis = delayMillis;
			this.randomDelayMillis = randomDelayMillis;
			this.entry = entry;
		}

		public void forward(DatagramPacket packet) throws IOException {
			if (manipulateMessage()) {
				final long delay = delayMillis + random.nextInt(randomDelayMillis);
				byte[] data = Arrays.copyOfRange(packet.getData(), packet.getOffset(),
						packet.getOffset() + packet.getLength());
				final DatagramPacket clone = new DatagramPacket(data, data.length, packet.getSocketAddress());
				scheduler.schedule(new Runnable() {

					@Override
					public void run() {
						if (isRunning()) {
							try {
								if (entry != null) {
									LOGGER.info("send message {} bytes, delayed {}ms to {}", clone.getLength(), delay,
											clone.getSocketAddress());
									entry.forward(clone);
								} else {
									LOGGER.info("deliver message {} bytes, delayed {}ms to {}", clone.getLength(),
											delay, clone.getSocketAddress());
									deliver(clone);
								}
							} catch (IOException ex) {
								LOGGER.info("delayed forward failed!", ex);
							}
						}
					}
				}, delay, TimeUnit.MILLISECONDS);
			} else {
				deliver(packet);
			}
		}

		public synchronized void stop() {
			reordering = false;
		}

		private synchronized boolean isRunning() {
			return reordering;
		}
	}

	/**
	 * Message dropping configuration for forwarded messages.
	 */
	private volatile MessageDropping forward;
	/**
	 * Message dropping configuration for messages sent backwards.
	 */
	private volatile MessageDropping backward;

	private volatile MessageReordering reorder;

	/**
	 * Create a new NAT utility.
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
		this.proxyThread = new Thread(NAT_THREAD_GROUP, this, "NAT-" + proxy.getPort());
		this.proxyThread.start();
	}

	@Override
	public void run() {
		messageDroppingLogTime.set(System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(MESSAGE_DROPPING_LOG_INTERVAL_MS));
		LOGGER.info("starting NAT {} to {}.", proxyName, destinationName);
		while (running) {
			try {
				if (messageDroppingLogTime.get() - System.nanoTime() < 0) {
					dumpMessageDroppingStatistic();
				}

				proxyPacket.setLength(DATAGRAM_SIZE);
				proxySocket.receive(proxyPacket);
				MessageReordering before = this.reorder;
				if (before != null) {
					before.forward(proxyPacket);
				} else {
					deliver(proxyPacket);
				}
			} catch (SocketTimeoutException e) {
				if (running) {
					LOGGER.info("listen NAT {} to {} ...", proxyName, destinationName);
				}
			} catch (SocketException e) {
				if (running) {
					LOGGER.error("NAT {} to {} socket error", proxyName, destinationName, e);
				}
			} catch (InterruptedIOException e) {
				if (running) {
					LOGGER.error("NAT {} to {} interrupted", proxyName, destinationName, e);
				}
			} catch (Exception e) {
				LOGGER.error("NAT {} to {} error", proxyName, destinationName, e);
			}
		}
	}

	public void deliver(DatagramPacket packet) throws IOException {
		if (running) {
			InetSocketAddress incoming = (InetSocketAddress)  packet.getSocketAddress();
			NatEntry entry = nats.get(incoming);
			if (null == entry) {
				entry = new NatEntry(incoming);
				NatEntry previousEntry = nats.putIfAbsent(incoming, entry);
				if (previousEntry != null) {
					entry.stop();
					entry = previousEntry;
				}
			}
			entry.forward(packet);
		}
	}

	/**
	 * Stop the NAT.
	 */
	public void stop() {
		running = false;
		proxySocket.close();
		proxyThread.interrupt();
		stopAllNatEntries();
		scheduler.shutdownNow();
		try {
			proxyThread.join(1000);
			scheduler.awaitTermination(1000, TimeUnit.MILLISECONDS);
		} catch (InterruptedException ex) {
			LOGGER.error("shutdown failed!", ex);
		}
		LOGGER.warn("NAT stopped. {} forwarded messages, {} backwarded", forwardCounter, backwardCounter);
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
	 * Reassign new local addresses to all NAT entries.
	 */
	public void reassignNewLocalAddresses() {
		Set<InetSocketAddress> keys = new HashSet<InetSocketAddress>(nats.keySet());
		for (InetSocketAddress incoming : keys) {
			try {
				assignLocalAddress(incoming);
			} catch (SocketException e) {
				LOGGER.error("Failed to reassing NAT entry for {}.", incoming, e);
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
			LOGGER.info("changed NAT for {} from {} to {}.", incoming, old.getPort(), entry.getPort());
			old.stop();
		} else {
			LOGGER.info("add NAT for {} to {}.", incoming, entry.getPort());
		}
		return entry.getPort();
	}

	/**
	 * Mix all local addresses of NAT entries.
	 * 
	 * Reuse the local addresses for different incoming addresses.
	 * 
	 * @throws SocketException
	 */
	public void mixLocalAddresses() {
		Random random = new Random();
		List<NatEntry> destinations = new ArrayList<NatEntry>();
		Set<InetSocketAddress> keys = new HashSet<InetSocketAddress>(nats.keySet());
		for (InetSocketAddress incoming : keys) {
			NatEntry entry = nats.remove(incoming);
			destinations.add(entry);
		}
		for (InetSocketAddress incoming : keys) {
			int index = random.nextInt(destinations.size());
			NatEntry entry = destinations.remove(index);
			entry.setIncoming(incoming);
			nats.put(incoming, entry);
		}
	}

	/**
	 * Remove mapping for incoming address.
	 * 
	 * @param incoming address to remove mapping
	 * @return {@code true} , if mapping is removed, {@code false}, if no
	 *         mapping was available.
	 */
	public boolean removeLocalAddress(InetSocketAddress incoming) {
		NatEntry entry = nats.remove(incoming);
		if (null != entry) {
			entry.stop();
		} else {
			LOGGER.warn("no mapping found for {}!", incoming);
		}
		return null != entry;
	}

	/**
	 * Get (outgoing) local port for incoming address.
	 * 
	 * @param incoming address to get assigned local port
	 * @return outgoing port. {@code -1}, if no mapping available.
	 */
	public int getLocalPortForAddress(InetSocketAddress incoming) {
		NatEntry entry = nats.get(incoming);
		if (null != entry) {
			return entry.getPort();
		} else {
			LOGGER.warn("no mapping found for {}!", incoming);
			return -1;
		}
	}

	/**
	 * Get (outgoing) local socket address for incoming address.
	 * 
	 * @param incoming address to get assigned local socket address
	 * @return outgoing local socket address. {@code null}, if no mapping available.
	 */
	public InetSocketAddress getLocalAddressForAddress(InetSocketAddress incoming) {
		NatEntry entry = nats.get(incoming);
		if (null != entry) {
			return new InetSocketAddress(destination.getAddress(), entry.getPort());
		} else {
			LOGGER.warn("no mapping found for {}!", incoming);
			return null;
		}
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
	 * Set message dropping level in percent.
	 * 
	 * Set both forward and backward dropping.
	 * 
	 * @param percent message dropping level in percent
	 * @throws IllegalArgumentException if percent is out of range 0 to 100.
	 */
	public void setMessageDropping(int percent) {
		if (percent < 0 || percent > 100) {
			throw new IllegalArgumentException("Message dropping " + percent + "% out of range [0...100]!");
		}
		if (percent == 0) {
			if (forward != null || backward != null) {
				forward = null;
				backward = null;
				LOGGER.info("NAT stops message dropping.");
			}
		} else {
			forward = new MessageDropping("request", percent);
			backward = new MessageDropping("responses", percent);
			LOGGER.trace("NAT message dropping {}%.", percent);
		}
	}

	/**
	 * Set message dropping level in percent for forwarded messages.
	 * 
	 * @param percent message dropping level in percent
	 * @throws IllegalArgumentException if percent is out of range 0 to 100.
	 */
	public void setForwardMessageDropping(int percent) {
		if (percent < 0 || percent > 100) {
			throw new IllegalArgumentException("Message dropping " + percent + "% out of range [0...100]!");
		}
		if (percent == 0) {
			if (forward != null) {
				forward = null;
				LOGGER.info("NAT stops forward message dropping.");
			}
		} else {
			forward = new MessageDropping("request", percent);
			LOGGER.trace("NAT forward message dropping {}%.", percent);
		}
	}

	/**
	 * Set message dropping level in percent for messages sent backwards.
	 * 
	 * @param percent message dropping level in percent
	 * @throws IllegalArgumentException if percent is out of range 0 to 100.
	 */
	public void setBackwardMessageDropping(int percent) {
		if (percent < 0 || percent > 100) {
			throw new IllegalArgumentException("Message dropping " + percent + "% out of range [0...100]!");
		}
		if (percent == 0) {
			if (backward != null) {
				backward = null;
				LOGGER.info("NAT stops backward message dropping.");
			}
		} else {
			backward = new MessageDropping("response", percent);
			LOGGER.trace("NAT backward message dropping {}%.", percent);
		}
	}

	/**
	 * Set message reordering level in percent.
	 * 
	 * @param percent message reordering level in percent
	 * @param delayMillis message delay in milliseconds
	 * @param randomDelayMillis maximum random message delay in milliseconds
	 * @throws IllegalArgumentException if percent is out of range 0 to 100.
	 */
	public void setMessageReordering(int percent, int delayMillis, int randomDelayMillis) {
		if (percent < 0 || percent > 100) {
			throw new IllegalArgumentException("Message reordering " + percent + "% out of range [0...100]!");
		}
		if (reorder != null) {
			reorder.stop();
		}
		if (percent == 0) {
			if (reorder != null) {
				reorder = null;
				LOGGER.info("NAT stops message reordering.");
			}
		} else {
			reorder = new MessageReordering("reordering", percent, delayMillis, randomDelayMillis);
			LOGGER.trace("NAT message reordering {}%.", percent);
		}
	}

	/**
	 * Dump message dropping statistics to log.
	 */
	public void dumpMessageDroppingStatistic() {
		messageDroppingLogTime.set(System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(MESSAGE_DROPPING_LOG_INTERVAL_MS));
		MessageDropping drops = this.forward;
		if (drops != null) {
			drops.dumpStatistic();
		}
		drops = this.backward;
		if (drops != null) {
			drops.dumpStatistic();
		}
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
		private final DatagramSocket outgoingSocket;
		private final DatagramPacket packet;
		private final String natName;
		private final Thread thread;
		private String incomingName;
		private InetSocketAddress incoming;
		private volatile boolean running = true;
		private final AtomicLong lastUsage = new AtomicLong(System.nanoTime());

		public NatEntry(InetSocketAddress incoming) throws SocketException {
			setIncoming(incoming);
			this.outgoingSocket = new DatagramSocket(0);
			this.outgoingSocket.setSoTimeout(SOCKET_TIMEOUT_MS);
			this.packet = new DatagramPacket(new byte[DATAGRAM_SIZE], DATAGRAM_SIZE);
			this.natName = Integer.toString(this.outgoingSocket.getLocalPort());
			this.thread = new Thread(NAT_THREAD_GROUP, this, "NAT-ENTRY-" + incoming.getPort());
			this.thread.start();
		}

		public synchronized void setIncoming(InetSocketAddress incoming) {
			this.incoming = incoming;
			this.incomingName = incoming.getHostString() + ":" + incoming.getPort();
		}

		@Override
		public void run() {
			LOGGER.info("start listening on {} for incoming {}", natName, incomingName);
			try {
				while (running) {
					try {
						packet.setLength(DATAGRAM_SIZE);
						outgoingSocket.receive(packet);
						lastUsage.set(System.nanoTime());
						InetSocketAddress incoming;
						String incomingName;
						synchronized (this) {
							incoming = this.incoming;
							incomingName = this.incomingName;
						}
						packet.setSocketAddress(incoming);
						MessageDropping dropping = backward;
						if (dropping != null && dropping.dropMessage()) {
							LOGGER.info("backward drops {} bytes from {} to {} via {}", packet.getLength(),
									destinationName, incomingName, natName);
						} else {
							LOGGER.info("backward {} bytes from {} to {} via {}", packet.getLength(), destinationName,
									incomingName, natName);
							proxySocket.send(packet);
							backwardCounter.incrementAndGet();
						}
					} catch (SocketTimeoutException e) {
						if (running) {
							String incomingName;
							synchronized (this) {
								incomingName = this.incomingName;
							}
							if (TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - lastUsage.get()) > NAT_TIMEOUT_MS) {
								running = false;
								LOGGER.info("expired listen on {} for incoming {}", natName, incomingName);
							} else {
								LOGGER.debug("listen on {} for incoming {}", natName, incomingName);
							}
						}
					} catch (IOException e) {
						if (running) {
							String incomingName;
							synchronized (this) {
								incomingName = this.incomingName;
							}
							LOGGER.info("error occured on {} for incoming {}", natName, incomingName, e);
						}
					}
				}
			} finally {
				InetSocketAddress incoming;
				String incomingName;
				synchronized (this) {
					incoming = this.incoming;
					incomingName = this.incomingName;
				}
				LOGGER.info("stop listen on {} for incoming {}", natName, incomingName);
				outgoingSocket.close();
				if (running) {
					nats.remove(incoming, this);
				}
			}
		}

		public void stop() {
			running = false;
			outgoingSocket.close();
			thread.interrupt();
			try {
				thread.join(2000);
			} catch (InterruptedException e) {
				LOGGER.error("shutdown failed!", e);
			}
		}

		public int getPort() {
			return outgoingSocket.getLocalPort();
		}

		public void forward(DatagramPacket packet) throws IOException {
			String incomingName;
			synchronized (this) {
				incomingName = this.incomingName;
			}
			MessageDropping dropping = forward;
			if (dropping != null && dropping.dropMessage()) {
				LOGGER.info("forward drops {} bytes from {} to {} via {}", packet.getLength(), incomingName,
						destinationName, natName);
			} else {
				LOGGER.info("forward {} bytes from {} to {} via {}", packet.getLength(), incomingName, destinationName,
						natName);
				packet.setSocketAddress(destination);
				lastUsage.set(System.nanoTime());
				outgoingSocket.send(packet);
				forwardCounter.incrementAndGet();
			}
		}
	}
}
