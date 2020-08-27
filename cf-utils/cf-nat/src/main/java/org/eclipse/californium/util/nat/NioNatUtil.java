/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - NatUtil using none-blocking io.
 ******************************************************************************/

package org.eclipse.californium.util.nat;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Queue;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Test utility to emulate a NAT and LoadBalancer.
 *
 * Provide function to change the address mapping. Uses none-blocking io,
 * intended to replace {@link NatUtil}.
 * 
 * @see #assignLocalAddress(InetSocketAddress)
 * @see #reassignNewLocalAddresses()
 * @since 2.4
 */
public class NioNatUtil implements Runnable {

	private static final Logger LOGGER = LoggerFactory.getLogger(NioNatUtil.class);
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
	 * Runnables to be executed by the selector's {@link #proxyThread}.
	 */
	private final Queue<Runnable> jobs = new ConcurrentLinkedQueue<>();
	/**
	 * The name of the proxy interface address.
	 */
	private final String proxyName;
	/**
	 * Destination address.
	 */
	private final List<InetSocketAddress> destinations;
	/**
	 * The name of the destination address.
	 */
	private final List<String> destinationNames;
	/**
	 * Buffer for proxy.
	 */
	private final ByteBuffer proxyBuffer;
	/**
	 * Incoming proxy channel.
	 */
	private final DatagramChannel proxyChannel;
	/**
	 * Map of external incoming addresses to local used addresses for forwarding
	 * the messages to the destination.
	 */
	private final ConcurrentMap<InetSocketAddress, NatEntry> nats = new ConcurrentHashMap<InetSocketAddress, NatEntry>();

	private final Selector selector = Selector.open();

	/**
	 * Scheduler for reordering.
	 */
	private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2, new ThreadFactory() {

		@Override
		public Thread newThread(Runnable runnable) {
			final Thread ret = new Thread(NAT_THREAD_GROUP, runnable,
					"NAT-DELAY-" + NAT_THREAD_COUNTER.getAndIncrement(), 0);
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
	 * Counter for backwarded messages from wrong source.
	 * @since 2.5
	 */
	private AtomicLong wrongRoutedCounter = new AtomicLong();
	/**
	 * Last counter for backwarded messages from wrong source.
	 * used for logging.
	 * @since 2.5
	 */
	private long lastWrongRoutedCounter;
	/**
	 * NAT timeout in milliseconds. Remove entry, if inactive.
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
		public Manipulation limitMessageSize(ByteBuffer packet) {
			if (packet.position() > sizeLimit) {
				if (manipulateMessage()) {
					if (drop) {
						return Manipulation.DROP;
					} else {
						packet.position(sizeLimit);
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

		private final int delayMillis;
		private final int randomDelayMillis;
		private boolean reordering = true;

		public MessageReordering(String title, int threshold, int delayMillis, int randomDelayMillis) {
			super(title + " reorders", threshold);
			this.delayMillis = delayMillis;
			this.randomDelayMillis = randomDelayMillis;
		}

		public void forward(final SocketAddress source, final NatEntry entry, ByteBuffer data) throws IOException {
			if (manipulateMessage()) {
				final ByteBuffer clone = data.duplicate();
				final long delay = delayMillis + random.nextInt(randomDelayMillis);
				scheduler.schedule(new Runnable() {

					@Override
					public void run() {
						if (isRunning()) {
							try {
								LOGGER.info("deliver message {} bytes, delayed {}ms for {}", clone.position(), delay,
										source);
								entry.forward(clone);
							} catch (IOException ex) {
								LOGGER.info("delayed forward failed!", ex);
							}
						}
					}
				}, delay, TimeUnit.MILLISECONDS);
			} else {
				entry.forward(data);
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
	public NioNatUtil(final InetSocketAddress bindAddress, final InetSocketAddress destination) throws Exception {
		this.destinations = new ArrayList<>();
		this.destinationNames = new ArrayList<>();
		addDestination(destination);
		this.proxyBuffer = ByteBuffer.allocateDirect(DATAGRAM_SIZE);
		this.proxyChannel = DatagramChannel.open();
		this.proxyChannel.configureBlocking(false);
		this.proxyChannel.bind(bindAddress);
		this.proxyChannel.register(selector, SelectionKey.OP_READ);
		InetSocketAddress proxy = (InetSocketAddress) this.proxyChannel.getLocalAddress();
		this.proxyName = proxy.getHostString() + ":" + proxy.getPort();
		this.proxyThread = new Thread(NAT_THREAD_GROUP, this, "NAT-" + proxy.getPort());
		this.proxyThread.start();
	}

	/**
	 * Add destination.
	 * 
	 * @param destination additional destination
	 * @since 2.5
	 */
	public void addDestination(InetSocketAddress destination) {
		synchronized (destinations) {
			if (!destinations.contains(destination)) {
				destinations.add(destination);
				destinationNames.add(destination.getHostString() + ":" + destination.getPort());
			}
		}
	}

	/**
	 * Remove destination
	 * 
	 * @param destination destination to remove
	 * @since 2.5
	 */
	public void removeDestination(InetSocketAddress destination) {
		synchronized (destinations) {
			int index = destinations.indexOf(destination);
			if (index >= 0) {
				destinations.remove(index);
				destinationNames.remove(index);
			}
		}
	}

	@Override
	public void run() {
		messageDroppingLogTime.set(System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(MESSAGE_DROPPING_LOG_INTERVAL_MS));
		LOGGER.info("starting NAT {}.", proxyName);
		long lastTimeoutCheck = System.nanoTime();
		while (running) {
			try {
				if (messageDroppingLogTime.get() - System.nanoTime() < 0) {
					dumpMessageDroppingStatistic();
				}
				Runnable job;
				while ((job = jobs.poll()) != null) {
					job.run();
				}
				long timeout = getSocketTimeout();
				LOGGER.debug("Select {}ms, {} channels {} ready.", timeout, selector.keys().size(),
						selector.selectedKeys().size());
				int num = selector.select(timeout);
				if (num > 0) {
					Set<SelectionKey> keys = selector.selectedKeys();
					LOGGER.debug("Selected {} channels {} ready.", selector.keys().size(), keys.size());
					for (SelectionKey key : keys) {
						final NatEntry entry = (NatEntry) key.attachment();
						((Buffer) proxyBuffer).clear();
						if (entry != null) {
							// backward message
							if (entry.receive(proxyBuffer) > 0) {
								entry.backward(proxyBuffer);
							}
						} else if (!destinations.isEmpty()) {
							// forward message
							SocketAddress source = proxyChannel.receive(proxyBuffer);
							NatEntry newEntry = getNatEntry(source);
							MessageReordering before = this.reorder;
							if (before != null) {
								before.forward(source, newEntry, proxyBuffer);
							} else {
								newEntry.forward(proxyBuffer);
							}
						}
					}
					keys.clear();
				}
				long now = System.nanoTime();
				long timeoutCheckMillis = TimeUnit.NANOSECONDS.toMillis(now - lastTimeoutCheck);
				if (timeoutCheckMillis > natTimeoutMillis.get() / 4) {
					lastTimeoutCheck = now;
					for (NatEntry entry : nats.values()) {
						entry.timeout(now);
					}
				}
			} catch (SocketException e) {
				if (running) {
					LOGGER.error("NAT {} to {} socket error", proxyName, getDestinationForLogging(), e);
				}
			} catch (InterruptedIOException e) {
				if (running) {
					LOGGER.error("NAT {} to {} interrupted", proxyName, getDestinationForLogging(), e);
				}
			} catch (Exception e) {
				LOGGER.error("NAT {} to {} error", proxyName, getDestinationForLogging(), e);
			}
		}
	}

	private NatEntry getNatEntry(SocketAddress source) throws IOException {
		InetSocketAddress incoming = (InetSocketAddress) source;
		NatEntry entry = nats.get(incoming);
		if (entry == null) {

			entry = new NatEntry(incoming, selector);
			NatEntry previousEntry = nats.putIfAbsent(incoming, entry);
			if (previousEntry != null) {
				entry.stop();
				entry = previousEntry;
			}
		}
		return entry;
	}

	/**
	 * Run task in selector's thread.
	 * 
	 * Add task to {@link #jobs} and wakeup the {@link #selector}.
	 * 
	 * @param run task to run in selector's thread.
	 * @since 2.5
	 */
	private void runTask(Runnable run) {
		jobs.add(run);
		selector.wakeup();
	}

	/**
	 * Stop the NAT.
	 */
	public void stop() {
		running = false;
		try {
			proxyChannel.close();
		} catch (IOException e) {
			LOGGER.error("io-error on close!", e);
		}
		proxyThread.interrupt();
		stopAllNatEntries();
		scheduler.shutdownNow();
		try {
			proxyThread.join(1000);
			scheduler.awaitTermination(1000, TimeUnit.MILLISECONDS);
		} catch (InterruptedException ex) {
			LOGGER.error("shutdown failed!", ex);
		}
		try {
			selector.close();
		} catch (IOException e) {
			LOGGER.error("io-error on close!", e);
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
	 * @since 2.4
	 */
	public int reassignDestinationAddresses() {
		int count = 0;
		if (destinations.size() > 1) {
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
		if (Thread.currentThread() != proxyThread) {
			final CountDownLatch ready = new CountDownLatch(1);
			runTask(new Runnable() {

				@Override
				public void run() {
					reassignNewLocalAddresses();
					ready.countDown();
				}
			});
			try {
				ready.await();
			} catch (InterruptedException e) {
			}
		} else {
			Set<InetSocketAddress> keys = new HashSet<InetSocketAddress>(nats.keySet());
			for (InetSocketAddress incoming : keys) {
				try {
					assignLocalAddress(incoming);
				} catch (IOException e) {
					LOGGER.error("Failed to reassing NAT entry for {}.", incoming, e);
				}
			}
		}
	}

	/**
	 * Assign local addresses for incoming address.
	 * 
	 * @param incoming incoming address a local address is to be
	 *            assigned @return port number of the assigned local
	 *            address @throws IOException if reassign failed opening the new
	 *            local socket @throws
	 */
	public int assignLocalAddress(final InetSocketAddress incoming) throws IOException {
		if (Thread.currentThread() != proxyThread) {
			final AtomicInteger port = new AtomicInteger();
			final AtomicReference<IOException> error = new AtomicReference<>();
			final CountDownLatch ready = new CountDownLatch(1);
			runTask(new Runnable() {

				@Override
				public void run() {
					try {
						int p = assignLocalAddress(incoming);
						port.set(p);
					} catch (IOException e) {
						error.set(e);
					}
					ready.countDown();
				}
			});
			try {
				ready.await();
				if (error.get() != null) {
					throw error.get();
				}
				return port.get();
			} catch (InterruptedException e) {
				return 0;
			}
		} else {
			NatEntry entry = new NatEntry(incoming, selector);
			NatEntry old = nats.put(incoming, entry);
			if (null != old) {
				LOGGER.info("changed NAT for {} from {} to {}.", incoming, old.getPort(), entry.getPort());
				old.stop();
			} else {
				LOGGER.info("add NAT for {} to {}.", incoming, entry.getPort());
			}
			return entry.getPort();
		}
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
			return entry.getSocketAddres();
		} else {
			LOGGER.warn("no mapping found for {}!", incoming);
			return null;
		}
	}

	/**
	 * Get socket address of proxy.
	 * 
	 * @return socket address of proxy
	 * @throws IOException
	 */
	public InetSocketAddress getProxySocketAddress() throws IOException {
		return (InetSocketAddress) proxyChannel.getLocalAddress();
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
		long broken = wrongRoutedCounter.get();
		if (lastWrongRoutedCounter < broken) {
			LOGGER.warn("wrong routed messages {} (overall {}).", broken - lastWrongRoutedCounter,
					lastWrongRoutedCounter);
			lastWrongRoutedCounter = broken;
		}
	}

	/**
	 * Get random destination.
	 * 
	 * @return random selected destination
	 * @since 2.4
	 */
	public InetSocketAddress getRandomDestination() {
		if (destinations.isEmpty()) {
			return null;
		} else {
			synchronized (destinations) {
				int size = destinations.size();
				if (size == 1) {
					return destinations.get(0);
				} else {
					int index = random.nextInt(size);
					return destinations.get(index);
				}
			}
		}
	}

	private String getDestinationForLogging() {
		if (destinations.isEmpty()) {
			return "---";
		} else {
			synchronized (destinations) {
				int size = destinations.size();
				if (size == 1) {
					return destinationNames.get(0);
				} else {
					return destinationNames.get(0) + "-" + destinationNames.get(size - 1);
				}
			}
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
	private class NatEntry {

		private final DatagramChannel outgoing;
		private final String natName;
		private final AtomicLong lastUsage = new AtomicLong(System.nanoTime());
		private final InetSocketAddress local;
		private String incomingName;
		private InetSocketAddress incoming;
		private String destinationName;
		private InetSocketAddress destination;

		public NatEntry(InetSocketAddress incoming, Selector selector) throws IOException {
			setIncoming(incoming);
			setDestination(getRandomDestination());
			this.outgoing = DatagramChannel.open();
			this.outgoing.configureBlocking(false);
			this.outgoing.bind(null);
			this.local = (InetSocketAddress) this.outgoing.getLocalAddress();
			this.outgoing.register(selector, SelectionKey.OP_READ, this);
			this.natName = Integer.toString(this.local.getPort());
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

		public void timeout(long now) {
			long quietPeriodMillis = TimeUnit.NANOSECONDS.toMillis(now - lastUsage.get());
			if (quietPeriodMillis > natTimeoutMillis.get()) {
				String incomingName;
				synchronized (this) {
					incomingName = this.incomingName;
				}
				LOGGER.info("expired listen on {} for incoming {}", natName, incomingName);
				stop();
				nats.remove(incoming, this);
			}
		}

		public void stop() {
			try {
				outgoing.close();
			} catch (IOException e) {
				LOGGER.error("IO-error on closing", e);
			}
		}

		public InetSocketAddress getSocketAddres() {
			return local;
		}

		public int getPort() {
			return local.getPort();
		}

		public int receive(ByteBuffer packet) throws IOException {
			InetSocketAddress destination;
			synchronized (this) {
				destination = this.destination;
			}
			SocketAddress source = outgoing.receive(packet);
			if (!destination.equals(source)) {
				wrongRoutedCounter.incrementAndGet();
				((Buffer) packet).clear();
			}
			return packet.position();
		}

		public void backward(ByteBuffer packet) throws IOException {
			lastUsage.set(System.nanoTime());
			InetSocketAddress incoming;
			String incomingName;
			String destinationName;
			synchronized (this) {
				incoming = this.incoming;
				incomingName = this.incomingName;
				destinationName = this.destinationName;
			}
			MessageDropping dropping = backward;
			if (dropping != null && dropping.dropMessage()) {
				LOGGER.debug("backward drops {} bytes from {} to {} via {}", packet.position(), destinationName,
						incomingName, natName);
			} else {
				MessageSizeLimit limit = backwardSizeLimit;
				MessageSizeLimit.Manipulation manipulation = limit != null ? limit.limitMessageSize(packet)
						: MessageSizeLimit.Manipulation.NONE;
				switch (manipulation) {
				case NONE:
					LOGGER.debug("backward {} bytes from {} to {} via {}", packet.position(), destinationName,
							incomingName, natName);
					break;
				case DROP:
					LOGGER.debug("backward drops {} bytes from {} to {} via {}", packet.position(), destinationName,
							incomingName, natName);
					break;
				case LIMIT:
					LOGGER.debug("backward limited {} bytes from {} to {} via {}", packet.position(), destinationName,
							incomingName, natName);
					break;
				}
				if (manipulation != MessageSizeLimit.Manipulation.DROP) {
					((Buffer) packet).flip();
					if (proxyChannel.send(packet, incoming) == 0) {
						LOGGER.debug("backward overloaded {} bytes from {} to {} via {}", packet.position(),
								destinationName, incomingName, natName);
					} else {
						backwardCounter.incrementAndGet();
					}
				}
			}
		}

		public boolean forward(ByteBuffer packet) throws IOException {
			lastUsage.set(System.nanoTime());
			String incomingName;
			String destinationName;
			InetSocketAddress destination;
			synchronized (this) {
				incomingName = this.incomingName;
				destinationName = this.destinationName;
				destination = this.destination;
			}
			MessageDropping dropping = forward;
			if (dropping != null && dropping.dropMessage()) {
				LOGGER.debug("forward drops {} bytes from {} to {} via {}", packet.position(), incomingName,
						destinationName, natName);
			} else {

				MessageSizeLimit limit = forwardSizeLimit;
				MessageSizeLimit.Manipulation manipulation = limit != null ? limit.limitMessageSize(packet)
						: MessageSizeLimit.Manipulation.NONE;
				switch (manipulation) {
				case NONE:
					LOGGER.debug("forward {} bytes from {} to {} via {}", packet.position(), incomingName,
							destinationName, natName);
					break;
				case DROP:
					LOGGER.debug("forward drops {} bytes from {} to {} via {}", packet.position(), incomingName,
							destinationName, natName);
					break;
				case LIMIT:
					LOGGER.debug("forward limited {} bytes from {} to {} via {}", packet.position(), incomingName,
							destinationName, natName);
					break;
				}
				if (manipulation != MessageSizeLimit.Manipulation.DROP) {
					((Buffer) packet).flip();
					if (outgoing.send(packet, destination) == 0) {
						LOGGER.info("forward overloaded {} bytes from {} to {} via {}", packet.limit(), incomingName,
								destinationName, natName);
						return false;
					} else {
						forwardCounter.incrementAndGet();
					}
				}
			}
			return true;
		}
	}
}
