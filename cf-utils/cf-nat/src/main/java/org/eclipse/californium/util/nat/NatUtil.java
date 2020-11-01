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

package org.eclipse.californium.util.nat;

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
 * @deprecated please use {@link NioNatUtil}.
 */
@Deprecated
public class NatUtil implements Runnable {

	private static final Logger LOGGER = LoggerFactory.getLogger(NatUtil.class);
	/**
	 * Supported maximum message size.
	 */
	private static final int DATAGRAM_SIZE = 2048;
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
	private final InetSocketAddress[] destinations;
	/**
	 * The name of the destination address.
	 */
	private final String[] destinationNames;
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
	 * Random to select destination in NAT-LoadBalancer mode.
	 * 
	 * @see #getRandomDestination()
	 * @since 2.4
	 */
	private final Random random = new Random(System.nanoTime());
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
	 * NAT timeout in milliseconds. Remove entry, if entry is inactive.
	 * 
	 * @since 2.4
	 */
	private AtomicInteger natTimeoutMillis = new AtomicInteger(NAT_TIMEOUT_MS);

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
	 * Message size limit configuration.
	 * 
	 * @since 2.4
	 */
	private static class MessageSizeLimit extends TransmissionManipulation {

		private static enum Manipulation {
			NONE, DROP, LIMIT
		};

		private final boolean drop;
		private final int sizeLimit;

		/**
		 * Create instance.
		 * 
		 * @param title title for statistic dump
		 * @param threshold threshold in percent
		 * @param sizeLimit size limit. If exceeded, the message may be dropped
		 *            or limited.
		 * @param drop {@code true} to drop, {@code false}, to limit size
		 */
		public MessageSizeLimit(String title, int threshold, int sizeLimit, boolean drop) {
			super(title + " size limit", threshold);
			this.sizeLimit = sizeLimit;
			this.drop = drop;
		}

		/**
		 * Limit message size.
		 * 
		 * @param packet packet to limit size
		 * @return applied manipulation.
		 */
		public Manipulation limitMessageSize(DatagramPacket packet) {
			if (packet.getLength() > sizeLimit) {
				if (manipulateMessage()) {
					if (drop) {
						return Manipulation.DROP;
					} else {
						packet.setLength(sizeLimit);
						return Manipulation.LIMIT;
					}
				}
			}
			return Manipulation.NONE;
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
	/**
	 * Message size limit configuration for forwarded messages.
	 * 
	 * @since 2.4
	 */
	private volatile MessageSizeLimit forwardSizeLimit;
	/**
	 * Message size limit configuration for messages sent backwards.
	 * 
	 * @since 2.4
	 */
	private volatile MessageSizeLimit backwardSizeLimit;
	/**
	 * Message reordering configuration for messages.
	 */
	private volatile MessageReordering reorder;

	/**
	 * Create a new NAT utility.
	 * 
	 * @param bindAddress address to bind to, or {@code null}, if any should be
	 *            used
	 * @param destination destination address to forward the messages using a
	 *            local port
	 * @throws Exception if an error occurred
	 */
	public NatUtil(final InetSocketAddress bindAddress, final InetSocketAddress destination) throws Exception {
		this(bindAddress, new InetSocketAddress[] { destination });
	}

	/**
	 * Create a new NAT-LoadBalancer utility.
	 * 
	 * @param bindAddress address to bind to, or {@code null}, if any should be
	 *            used
	 * @param destinations list of destination addresses to forward the messages
	 *            using a local port
	 * @throws Exception if an error occurred
	 * @since 2.4
	 */
	public NatUtil(final InetSocketAddress bindAddress, final List<InetSocketAddress> destinations) throws Exception {
		this(bindAddress, destinations.toArray(new InetSocketAddress[0]));
	}

	/**
	 * Create a new NAT-LoadBalancer utility.
	 * 
	 * @param bindAddress address to bind to, or {@code null}, if any should be
	 *            used
	 * @param destinations destination addresses to forward the messages using a
	 *            local port
	 * @throws Exception if an error occurred
	 * @since 2.4
	 */
	public NatUtil(final InetSocketAddress bindAddress, final InetSocketAddress... destinations) throws Exception {
		this.destinations = destinations;
		if (bindAddress == null) {
			proxySocket = new DatagramSocket();
		} else {
			proxySocket = new DatagramSocket(bindAddress);
		}
		InetSocketAddress proxy = (InetSocketAddress) proxySocket.getLocalSocketAddress();
		this.proxyName = proxy.getHostString() + ":" + proxy.getPort();
		this.destinationNames = new String[destinations.length];
		for (int index = 0; index < destinations.length; ++index) {
			this.destinationNames[index] = destinations[index].getHostString() + ":" + destinations[index].getPort();
		}
		this.proxyPacket = new DatagramPacket(new byte[DATAGRAM_SIZE], DATAGRAM_SIZE);
		this.proxyThread = new Thread(NAT_THREAD_GROUP, this, "NAT-" + proxy.getPort());
		this.proxyThread.start();
	}

	@Override
	public void run() {
		messageDroppingLogTime.set(System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(MESSAGE_DROPPING_LOG_INTERVAL_MS));
		if (destinations.length == 1) {
			LOGGER.info("starting NAT {} to {}.", proxyName, destinationNames[0]);
		} else {
			LOGGER.info("starting NAT-LB {} to {}-{}.", proxyName, destinationNames[0],
					destinationNames[destinationNames.length - 1]);
		}
		while (running) {
			try {
				if (messageDroppingLogTime.get() - System.nanoTime() < 0) {
					dumpMessageDroppingStatistic();
				}

				proxyPacket.setLength(DATAGRAM_SIZE);
				proxySocket.setSoTimeout(getSocketTimeout());
				proxySocket.receive(proxyPacket);
				MessageReordering before = this.reorder;
				if (before != null) {
					before.forward(proxyPacket);
				} else {
					deliver(proxyPacket);
				}
			} catch (SocketTimeoutException e) {
				if (running) {
					if (destinations.length == 1) {
						LOGGER.debug("listen NAT {} to {}.", proxyName, destinationNames[0]);
					} else {
						LOGGER.debug("listen NAT-LB {} to {}-{}.", proxyName, destinationNames[0],
								destinationNames[destinationNames.length - 1]);
					}
				}
			} catch (SocketException e) {
				if (running) {
					if (destinations.length == 1) {
						LOGGER.error("NAT {} to {} socket error", proxyName, destinationNames[0], e);
					} else {
						LOGGER.error("NAT-LB {} to {}-{} socket error", proxyName, destinationNames[0],
								destinationNames[destinationNames.length - 1], e);
					}
				}
			} catch (InterruptedIOException e) {
				if (running) {
					if (destinations.length == 1) {
						LOGGER.error("NAT {} to {} interrupted", proxyName, destinationNames[0], e);
					} else {
						LOGGER.error("NAT-LB {} to {}-{} interrupted", proxyName, destinationNames[0],
								destinationNames[destinationNames.length - 1], e);
					}
				}
			} catch (Exception e) {
				if (destinations.length == 1) {
					LOGGER.error("NAT {} to {} error", proxyName, destinationNames[0], e);
				} else {
					LOGGER.error("NAT-LB {} to {}-{} error", proxyName, destinationNames[0],
							destinationNames[destinationNames.length - 1], e);
				}
			}
		}
	}

	public void deliver(DatagramPacket packet) throws IOException {
		if (running) {
			InetSocketAddress incoming = (InetSocketAddress) packet.getSocketAddress();
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
	 * Set NAT timeout milliseconds.
	 * 
	 * @param natTimeoutMillis timeout in milliseconds
	 * @since 2.4
	 */
	public void setNatTimeoutMillis(int natTimeoutMillis) {
		this.natTimeoutMillis.set(natTimeoutMillis);
	}

	/**
	 * Gets number of entries.
	 * 
	 * @return number fo entries
	 * @since 2.4
	 */
	public int getNumberOfEntries() {
		return nats.size();
	}

	/**
	 * Reassign new destination addresses to all NAT entries.
	 * 
	 * @return number of reassigned NAT entries.
	 * @since 2.4
	 */
	public int reassignDestinationAddresses() {
		int count = 0;
		if (destinations.length > 1) {
			for (NatEntry entry : nats.values()) {
				if (entry.setDestination(getRandomDestination())) {
					++count;
				}
			}
		}
		return count;
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
	 * @return outgoing local socket address. {@code null}, if no mapping
	 *         available.
	 */
	public InetSocketAddress getLocalAddressForAddress(InetSocketAddress incoming) {
		NatEntry entry = nats.get(incoming);
		if (null != entry) {
			return entry.getSocketAddress();
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
			LOGGER.info("NAT message dropping {}%.", percent);
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
			LOGGER.info("NAT forward message dropping {}%.", percent);
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
			LOGGER.info("NAT backward message dropping {}%.", percent);
		}
	}

	/**
	 * Set message size limit and level in percent.
	 * 
	 * Set both forward and backward size limit.
	 * 
	 * @param percent message dropping level in percent
	 * @param sizeLimit message size limit
	 * @param drop {@code true} to drop, {@code false}, to limit size
	 * @throws IllegalArgumentException if percent is out of range 0 to 100.
	 * @since 2.4
	 */
	public void setMessageSizeLimit(int percent, int sizeLimit, boolean drop) {
		if (percent < 0 || percent > 100) {
			throw new IllegalArgumentException("Message size limit " + percent + "% out of range [0...100]!");
		}
		if (percent == 0) {
			if (forwardSizeLimit != null || backwardSizeLimit != null) {
				forwardSizeLimit = null;
				backwardSizeLimit = null;
				LOGGER.info("NAT stops message size limit.");
			}
		} else {
			forwardSizeLimit = new MessageSizeLimit("request", percent, sizeLimit, drop);
			backwardSizeLimit = new MessageSizeLimit("responses", percent, sizeLimit, drop);
			LOGGER.info("NAT message size limit {} bytes, {}%.", sizeLimit, percent);
		}
	}

	/**
	 * Set message size limit and level in percent for forwarded messages.
	 * 
	 * @param percent message dropping level in percent
	 * @param sizeLimit message size limit
	 * @param drop {@code true} to drop, {@code false}, to limit size
	 * @throws IllegalArgumentException if percent is out of range 0 to 100.
	 * @since 2.4
	 */
	public void setForwardMessageSizeLimit(int percent, int sizeLimit, boolean drop) {
		if (percent < 0 || percent > 100) {
			throw new IllegalArgumentException("Message size limit " + percent + "% out of range [0...100]!");
		}
		if (percent == 0) {
			if (forwardSizeLimit != null) {
				forwardSizeLimit = null;
				LOGGER.info("NAT stops forward message size limit.");
			}
		} else {
			forwardSizeLimit = new MessageSizeLimit("request", percent, sizeLimit, drop);
			LOGGER.info("NAT forward message size limit {} bytes, {}%.", sizeLimit, percent);
		}
	}

	/**
	 * Set message size limit and level in percent for messages sent backwards.
	 * 
	 * @param percent message dropping level in percent
	 * @param sizeLimit message size limit
	 * @param drop {@code true} to drop, {@code false}, to limit size
	 * @throws IllegalArgumentException if percent is out of range 0 to 100.
	 * @since 2.4
	 */
	public void setBackwardMessageSizeLimit(int percent, int sizeLimit, boolean drop) {
		if (percent < 0 || percent > 100) {
			throw new IllegalArgumentException("Message size limit " + percent + "% out of range [0...100]!");
		}
		if (percent == 0) {
			if (backwardSizeLimit != null) {
				backwardSizeLimit = null;
				LOGGER.info("NAT stops backward message size limit.");
			}
		} else {
			backwardSizeLimit = new MessageSizeLimit("response", percent, sizeLimit, drop);
			LOGGER.info("NAT backward message size limit {} bytes, {}%.", sizeLimit, percent);
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
			LOGGER.info("NAT message reordering {}%.", percent);
		}
	}

	/**
	 * Dump message dropping statistics to log.
	 */
	public void dumpMessageDroppingStatistic() {
		messageDroppingLogTime.set(System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(MESSAGE_DROPPING_LOG_INTERVAL_MS));
		TransmissionManipulation drops = this.forward;
		if (drops != null) {
			drops.dumpStatistic();
		}
		drops = this.backward;
		if (drops != null) {
			drops.dumpStatistic();
		}
		drops = this.forwardSizeLimit;
		if (drops != null) {
			drops.dumpStatistic();
		}
		drops = this.backwardSizeLimit;
		if (drops != null) {
			drops.dumpStatistic();
		}
	}

	/**
	 * Get random destination.
	 * 
	 * @return random selected destination
	 * @since 2.4
	 */
	public InetSocketAddress getRandomDestination() {
		if (destinations.length == 1) {
			return destinations[0];
		} else {
			int index = random.nextInt(destinations.length);
			return destinations[index];
		}
	}

	/**
	 * Get socket timeout in milliseconds.
	 * 
	 * Half of the NAT timeout value.
	 * 
	 * @return socket timeout in milliseconds
	 * @since 2.4
	 * @see #natTimeoutMillis
	 */
	private int getSocketTimeout() {
		return natTimeoutMillis.get() / 2;
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
		private String destinationName;
		private InetSocketAddress destination;
		private volatile boolean running = true;
		private final AtomicLong lastUsage = new AtomicLong(System.nanoTime());

		public NatEntry(InetSocketAddress incoming) throws SocketException {
			setIncoming(incoming);
			setDestination(getRandomDestination());
			this.outgoingSocket = new DatagramSocket(0);
			this.packet = new DatagramPacket(new byte[DATAGRAM_SIZE], DATAGRAM_SIZE);
			this.natName = Integer.toString(this.outgoingSocket.getLocalPort());
			this.thread = new Thread(NAT_THREAD_GROUP, this, "NAT-ENTRY-" + incoming.getPort());
			this.thread.start();
		}

		public synchronized boolean setDestination(InetSocketAddress destination) {
			if (this.destination == null || !this.destination.equals(destination)) {
				this.destination = destination;
				this.destinationName = destination.getHostString() + ":" + destination.getPort();
				return true;
			} else {
				return false;
			}
		}

		public synchronized void setIncoming(InetSocketAddress incoming) {
			this.incoming = incoming;
			this.incomingName = incoming.getHostString() + ":" + incoming.getPort();
		}

		@Override
		public void run() {
			LOGGER.info("start listening on {} for incoming {}", natName, incomingName);
			try {
				boolean timeout = false;
				while (running && !timeout) {
					try {
						packet.setLength(DATAGRAM_SIZE);
						outgoingSocket.setSoTimeout(getSocketTimeout());
						outgoingSocket.receive(packet);
						lastUsage.set(System.nanoTime());
						InetSocketAddress incoming;
						String incomingName;
						String destinationName;
						synchronized (this) {
							incoming = this.incoming;
							incomingName = this.incomingName;
							destinationName = this.destinationName;
						}
						packet.setSocketAddress(incoming);
						MessageDropping dropping = backward;
						if (dropping != null && dropping.dropMessage()) {
							LOGGER.debug("backward drops {} bytes from {} to {} via {}", packet.getLength(),
									destinationName, incomingName, natName);
						} else {
							MessageSizeLimit limit = backwardSizeLimit;
							MessageSizeLimit.Manipulation manipulation = limit != null ? limit.limitMessageSize(packet)
									: MessageSizeLimit.Manipulation.NONE;
							switch (manipulation) {
							case NONE:
								LOGGER.debug("backward {} bytes from {} to {} via {}", packet.getLength(),
										destinationName, incomingName, natName);
								break;
							case DROP:
								LOGGER.debug("backward drops {} bytes from {} to {} via {}", packet.getLength(),
										destinationName, incomingName, natName);
								break;
							case LIMIT:
								LOGGER.debug("backward limited {} bytes from {} to {} via {}", packet.getLength(),
										destinationName, incomingName, natName);
								break;
							}
							if (manipulation != MessageSizeLimit.Manipulation.DROP) {
								proxySocket.send(packet);
								backwardCounter.incrementAndGet();
							}
						}
					} catch (SocketTimeoutException e) {
						if (running) {
							String incomingName;
							synchronized (this) {
								incomingName = this.incomingName;
							}
							long quietPeriodMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - lastUsage.get());
							if (quietPeriodMillis > natTimeoutMillis.get()) {
								timeout = true;
								LOGGER.info("expired listen on {} for incoming {}", natName, incomingName);
							} else {
								LOGGER.trace("listen on {} for incoming {}", natName, incomingName);
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

		public InetSocketAddress getSocketAddress() {
			return (InetSocketAddress) outgoingSocket.getLocalSocketAddress();
		}

		public int getPort() {
			return outgoingSocket.getLocalPort();
		}

		public void forward(DatagramPacket packet) throws IOException {
			InetSocketAddress destination;
			String incomingName;
			String destinationName;
			synchronized (this) {
				incomingName = this.incomingName;
				destinationName = this.destinationName;
				destination = this.destination;
			}
			MessageDropping dropping = forward;
			if (dropping != null && dropping.dropMessage()) {
				LOGGER.debug("forward drops {} bytes from {} to {} via {}", packet.getLength(), incomingName,
						destinationName, natName);
			} else {

				MessageSizeLimit limit = forwardSizeLimit;
				MessageSizeLimit.Manipulation manipulation = limit != null ? limit.limitMessageSize(packet)
						: MessageSizeLimit.Manipulation.NONE;
				switch (manipulation) {
				case NONE:
					LOGGER.debug("forward {} bytes from {} to {} via {}", packet.getLength(), incomingName,
							destinationName, natName);
					break;
				case DROP:
					LOGGER.debug("forward drops {} bytes from {} to {} via {}", packet.getLength(), incomingName,
							destinationName, natName);
					break;
				case LIMIT:
					LOGGER.debug("forward limited {} bytes from {} to {} via {}", packet.getLength(), incomingName,
							destinationName, natName);
					break;
				}
				if (manipulation != MessageSizeLimit.Manipulation.DROP) {
					packet.setSocketAddress(destination);
					lastUsage.set(System.nanoTime());
					outgoingSocket.send(packet);
					forwardCounter.incrementAndGet();
				}
			}
		}
	}
}
