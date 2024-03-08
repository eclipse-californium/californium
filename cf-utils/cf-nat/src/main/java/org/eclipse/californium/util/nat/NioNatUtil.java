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
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Test utility to emulate a NAT and LoadBalancer.
 *
 * Provide function to change the address mapping. Uses none-blocking io.
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
	 * NAT timeout.
	 */
	public static final int NAT_TIMEOUT_MS = 1000 * 30;
	/**
	 * LB timeout.
	 * 
	 * @since 2.5
	 */
	public static final int LB_TIMEOUT_MS = 1000 * 15;
	/**
	 * Maximum number of NAT entries.
	 * 
	 * @since 3.0
	 */
	public static final int MAXIMUM_NAT_ENTRIES = 10000;

	/**
	 * Minimum length of DTLS 1.2 record.
	 */
	private static final byte DTLS_RECORD_MINIMUM_LENGTH = 14;
	/**
	 * DTLS 1.2 handshake record content type.
	 */
	private static final byte DTLS_HANDSHAKE_RECORD = 22;
	/**
	 * DTLS 1.x major version.
	 */
	private static final byte DTLS_1_X_MAJOR_VERSION = (byte)0xfe;
	/**
	 * DTLS 1.0 minor version.
	 */
	private static final byte DTLS_1_0_MINOR_VERSION = (byte)0xff;
	/**
	 * DTLS 1.2 minor version.
	 */
	private static final byte DTLS_1_2_MINOR_VERSION = (byte)0xfd;

	/**
	 * DTLS 1.2 valid record content types.
	 */
	private static final byte[] DTLS_CONTENT_TYPES = { 20, 21, DTLS_HANDSHAKE_RECORD, 23, 25 };

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
	 * 
	 * @since 2.5
	 */
	private final Queue<Runnable> jobs = new ConcurrentLinkedQueue<>();
	/**
	 * The name of the proxy interface address.
	 */
	private final String proxyName;
	/**
	 * Destination addresses.
	 */
	private final List<NatAddress> destinations;
	/**
	 * Stale destination addresses.
	 * 
	 * @since 2.5
	 */
	private final List<NatAddress> staleDestinations;
	/**
	 * Destination addresses to be probed.
	 * 
	 * The probe is done by forwarding one of the next unmappped request to this
	 * destination.
	 * 
	 * @since 3.0
	 */
	private final List<NatAddress> probeDestinations;
	/**
	 * Pending probed destination addresses.
	 * 
	 * @since 3.0
	 */
	private final List<NatAddress> pendingDestinations;
	/**
	 * Buffer for proxy.
	 */
	private final ByteBuffer proxyBuffer;
	/**
	 * Incoming proxy channels.
	 */
	private final List<DatagramChannel> proxyChannels;
	/**
	 * Map of external incoming addresses to local used addresses for forwarding
	 * the messages to the destination.
	 */
	private final ConcurrentMap<InetSocketAddress, NatEntry> nats = new ConcurrentHashMap<InetSocketAddress, NatEntry>();
	/**
	 * Selector for received messages.
	 */
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
	 * 
	 * @since 2.5
	 */
	private AtomicLong wrongRoutedCounter = new AtomicLong();
	/**
	 * Counter for dropped none-dtls-records.
	 * 
	 * @since 3.0
	 */
	private AtomicLong droppedNoneDtls = new AtomicLong();
	/**
	 * Last counter for backwarded messages from wrong source.
	 * 
	 * Used for logging.
	 * 
	 * @since 2.5
	 */
	private long lastWrongRoutedCounter;

	private AtomicLong spoofedCounter = new AtomicLong();

	/**
	 * Counter for timedout NAT entries.
	 * 
	 * @since 2.5
	 */
	private AtomicLong timedoutEntriesCounter = new AtomicLong();
	/**
	 * Last counter for timedout NAT entries.
	 * 
	 * Used for logging.
	 * 
	 * @since 2.5
	 */
	private long lastTimedoutEntriesCounter;
	/**
	 * NAT timeout in milliseconds. Remove entry, if inactive.
	 * 
	 * @since 2.4
	 */
	private AtomicInteger natTimeoutMillis = new AtomicInteger(NAT_TIMEOUT_MS);
	/**
	 * LB timeout in milliseconds. Remove entry, if inactive.
	 * 
	 * @since 2.5
	 */
	private AtomicInteger loadBalancerTimeoutMillis = new AtomicInteger(LB_TIMEOUT_MS);
	/**
	 * Maximum number of NAT entries.
	 * 
	 * @since 3.0
	 */
	private AtomicInteger maximumNumberOfNatEtries = new AtomicInteger(MAXIMUM_NAT_ENTRIES);

	/**
	 * Enable reverse NAT updates.
	 * 
	 * Update destination address, if backwards message is received from
	 * different source.
	 * 
	 * @since 2.5
	 */
	private AtomicBoolean reverseNatUpdate = new AtomicBoolean();
	/**
	 * Enable DTLS 1.2 filter.
	 * 
	 * Filter records based on the first 3 bytes. Drop all none DTLS records.
	 * 
	 * @since 3.0
	 */
	private AtomicBoolean dtlsFilter = new AtomicBoolean();

	private AtomicBoolean spoof = new AtomicBoolean();

	/**
	 * NAT address state.
	 * 
	 * @since 3.0
	 */
	public enum NatAddressState {
		REMOVED, STALE, PROBING, PENDING, ACTIVE
	}

	/**
	 * NAT address.
	 * 
	 * Address, display name, and usage times.
	 * 
	 * @since 2.5
	 */
	public static class NatAddress {

		/**
		 * Address.
		 */
		public final InetSocketAddress address;
		/**
		 * Address as name
		 */
		public final String name;
		/**
		 * Counter for usage in NatEntries.
		 */
		private final AtomicInteger usageCounter;
		/**
		 * Nanoseconds of last usage.
		 * 
		 * If used for {@link #updateSend()} and {@link #updateReceive()}, it
		 * contains the timestamp of the last sent message, and {@code -1}, if a
		 * messages is received back from that address.
		 */
		private long lastNanos;
		/**
		 * Indicates, that the address is expired according
		 * {@link #updateUsage()} or {@link #updateSend()} and
		 * {@link #updateReceive()}. Expiring is sticky, once expired, the
		 * {@link #lastNanos} gets never updated again.
		 */
		private boolean expired;
		/**
		 * State of this NAT address.
		 * 
		 * @since 3.0
		 */
		private NatAddressState state;

		/**
		 * Create new NAT address.
		 * 
		 * @param address address
		 */
		private NatAddress(InetSocketAddress address) {
			this.address = address;
			this.name = address.getHostString() + ":" + address.getPort();
			this.usageCounter = new AtomicInteger();
			this.state = NatAddressState.ACTIVE;
			updateReceive();
		}

		/**
		 * Change state to {@link NatAddressState#STALE}.
		 * 
		 * @since 3.0
		 */
		private synchronized void stale() {
			state = NatAddressState.STALE;
			expired = false;
			lastNanos = System.nanoTime();
		}

		/**
		 * Change state to {@link NatAddressState#PROBING}.
		 * 
		 * @since 3.0
		 */
		private synchronized void probe() {
			state = NatAddressState.PROBING;
			expired = false;
			lastNanos = -1;
		}

		/**
		 * Change state to {@link NatAddressState#PENDING}.
		 * 
		 * @since 3.0
		 */
		private synchronized void pending() {
			state = NatAddressState.PENDING;
			expired = false;
			lastNanos = -1;
		}

		/**
		 * Change state to {@link NatAddressState#REMOVED}.
		 * 
		 * @since 3.0
		 */
		private synchronized void remove() {
			state = NatAddressState.REMOVED;
		}

		/**
		 * Update usage.
		 * 
		 * Records any usage in {@link #lastNanos}. Intended to be frequently
		 * update on any usage in order to prevent address from expiring.
		 * 
		 * @see #expires(long)
		 */
		private synchronized void updateUsage() {
			if (!expired) {
				this.lastNanos = System.nanoTime();
			}
		}

		/**
		 * Update send usage.
		 * 
		 * Records sending a message in {@link #lastNanos}. Expires only, if no
		 * received message is reported with {@link #updateReceive()}.
		 * 
		 * @see #expires(long)
		 */
		private synchronized void updateSend() {
			if (!expired) {
				if (lastNanos < 0) {
					this.lastNanos = System.nanoTime();
				}
			}
		}

		/**
		 * Update receive.
		 * 
		 * Stops expiring until next {@link #updateSend()}.
		 * 
		 * @see #expires(long)
		 */
		private synchronized void updateReceive() {
			this.expired = false;
			this.state = NatAddressState.ACTIVE;
			this.lastNanos = -1;
		}

		/**
		 * Check, if NAT address is expired.
		 * 
		 * @param expireNanos nanoseconds of expiration (now - timeout).
		 * @return {@code true}, if expired, {@code false}, otherwise.
		 */
		private synchronized boolean expires(long expireNanos) {
			if (!expired) {
				expired = (lastNanos > 0) && (expireNanos - lastNanos) > 0;
			}
			return expired;
		}

		@Override
		public int hashCode() {
			return address.hashCode();
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			NatAddress other = (NatAddress) obj;
			return address.equals(other.address);
		}

		public int usageCounter() {
			return usageCounter.get();
		}

		/**
		 * Last usage.
		 * 
		 * @return seconds since last usage. {@code -2}, if expired, {@code -1},
		 *         if waiting for next message.
		 * @since 3.0
		 */
		public synchronized long lastUsage() {
			long usage = -2;
			if (!expired) {
				if (lastNanos > 0) {
					usage = TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - lastNanos);
				} else {
					usage = -1;
				}
			}
			return usage;
		}

		/**
		 * Get address state.
		 * 
		 * @return address state
		 * @since 3.0
		 */
		public synchronized NatAddressState getState() {
			return state;
		}

		/**
		 * Check, if address is usable/valid.
		 * 
		 * @return {@code true}, if usable, {@code false}, if not.
		 * @since 3.0
		 */
		public synchronized boolean usable() {
			if (state == NatAddressState.ACTIVE) {
				return !expired;
			}
			return false;
		}
	}

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

		public void forward(final InetSocketAddress source, NatEntry entry, ByteBuffer data) throws IOException {
			if (!isRunning()) {
				return;
			}
			if (manipulateMessage()) {
				final ByteBuffer clone = ByteBuffer.allocate(data.limit());
				clone.put(data);
				((Buffer) clone).flip();
				final long delay = delayMillis + random.nextInt(randomDelayMillis);
				scheduler.schedule(new Runnable() {

					@Override
					public void run() {
						if (isRunning()) {
							try {
								LOGGER.info("deliver message {} bytes, delayed {}ms for {}", clone.limit(), delay,
										source);
								NatEntry entry = nats.get(source);
								if (entry != null) {
									entry.forward(clone);
								}
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
	 * @throws IOException if an error occurred
	 */
	public NioNatUtil(final InetSocketAddress bindAddress, final InetSocketAddress destination) throws IOException {
		this(Arrays.asList(bindAddress), destination);
	}

	/**
	 * Create a new NAT utility.
	 * 
	 * @param bindAddresses addresses to bind to
	 * @param destination destination address to forward the messages using a
	 *            local port
	 * @throws IOException if an error occurred
	 * @throws IllegalArgumentException if bind addresses are empty
	 * @since 3.0
	 */
	public NioNatUtil(List<InetSocketAddress> bindAddresses, final InetSocketAddress destination) throws IOException {
		if (bindAddresses.isEmpty()) {
			throw new IllegalArgumentException("Bind addresses must not be empty!");
		}
		this.proxyChannels = new ArrayList<>();
		this.destinations = new ArrayList<>();
		this.staleDestinations = new ArrayList<>();
		this.probeDestinations = new ArrayList<>();
		this.pendingDestinations = new ArrayList<>();
		addDestination(destination);
		this.proxyBuffer = ByteBuffer.allocateDirect(DATAGRAM_SIZE);
		InetSocketAddress proxy = null;
		for (InetSocketAddress bindAddress : bindAddresses) {
			DatagramChannel proxyChannel = DatagramChannel.open();
			proxyChannel.configureBlocking(false);
			proxyChannel.bind(bindAddress);
			proxyChannel.register(selector, SelectionKey.OP_READ);
			proxyChannels.add(proxyChannel);
			if (proxy == null) {
				proxy = (InetSocketAddress) proxyChannel.getLocalAddress();
			}
		}
		if (proxy == null) {
			proxy = bindAddresses.get(0);
		}
		this.proxyName = proxy.getHostString() + ":" + proxy.getPort();
		this.proxyThread = new Thread(NAT_THREAD_GROUP, this, "NAT-" + proxy.getPort());
		this.proxyThread.start();
	}

	/**
	 * Add destination.
	 * 
	 * @param destination additional destination
	 * @return {@code true}, if the destination was added, {@code false},
	 *         otherwise.
	 * @since 2.5
	 */
	public boolean addDestination(InetSocketAddress destination) {
		if (destination != null) {
			NatAddress dest = new NatAddress(destination);
			synchronized (destinations) {
				if (!destinations.contains(dest)) {
					destinations.add(dest);
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Remove destination
	 * 
	 * @param destination destination to remove
	 * @return {@code true}, if the destination was removed, {@code false},
	 *         otherwise.
	 * @since 2.5
	 */
	public boolean removeDestination(InetSocketAddress destination) {
		if (destination != null) {
			synchronized (destinations) {
				for (NatAddress address : destinations) {
					if (address.address.equals(destination)) {
						destinations.remove(address);
						address.remove();
						return true;
					}
				}
				for (NatAddress address : staleDestinations) {
					if (address.address.equals(destination)) {
						staleDestinations.remove(address);
						return true;
					}
				}
			}
		}
		return false;
	}

	/**
	 * Add stale destinations back to destinations.
	 * 
	 * @return {@code true}, if stale destinations are added, {@code false}, if
	 *         not.
	 * @since 2.5
	 */
	public boolean addStaleDestinations() {
		boolean added = false;
		synchronized (destinations) {
			for (NatAddress address : staleDestinations) {
				address.updateReceive();
				if (destinations.add(address)) {
					added = true;
				}
			}
			staleDestinations.clear();
		}
		return added;
	}

	@Override
	public void run() {
		messageDroppingLogTime.set(System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(MESSAGE_DROPPING_LOG_INTERVAL_MS));
		LOGGER.info("starting NAT {}.", proxyName);
		long lastTimeoutCheck = System.nanoTime();
		long lastLoadBalancerCheck = System.nanoTime();
		while (running) {
			try {
				if (messageDroppingLogTime.get() - System.nanoTime() < 0) {
					dumpMessageDroppingStatistic();
				}
				Runnable job;
				while ((job = jobs.poll()) != null) {
					job.run();
				}
				long timeout = natTimeoutMillis.get();
				long socketTimeout = timeout > 0 ? timeout / 2 : 1000;
				LOGGER.debug("Select {}ms, {} channels {} ready.", socketTimeout, selector.keys().size(),
						selector.selectedKeys().size());
				int num = selector.select(socketTimeout);
				if (num > 0) {
					Set<SelectionKey> keys = selector.selectedKeys();
					LOGGER.debug("Selected {} channels {} ready.", selector.keys().size(), keys.size());
					for (SelectionKey key : keys) {
						((Buffer) proxyBuffer).clear();
						Object attachment = key.attachment();
						if (attachment != null) {
							LOGGER.debug("backward");
							final NatEntry entry = (NatEntry) attachment;
							// backward message
							if (entry.receive(proxyBuffer) > 0) {
								entry.backward(proxyBuffer);
							}
						} else if (!destinations.isEmpty()) {
							// forward message
							DatagramChannel channel = (DatagramChannel) key.channel();
							InetSocketAddress source = (InetSocketAddress) channel.receive(proxyBuffer);
							((Buffer) proxyBuffer).flip();
							if (dtlsFilter.get() && !isDtlsRecord(proxyBuffer)) {
								droppedNoneDtls.incrementAndGet();
								LOGGER.debug("drop none dtls {} bytes", proxyBuffer.limit());
							} else {
								NatEntry newEntry = getNatEntry(source, channel);
								if (newEntry != null) {
									MessageReordering before = this.reorder;
									if (before != null) {
										LOGGER.debug("reorder forward {} bytes", proxyBuffer.limit());
										before.forward(source, newEntry, proxyBuffer);
									} else {
										LOGGER.debug("forward {} bytes", proxyBuffer.limit());
										newEntry.forward(proxyBuffer);
									}
								} else {
									LOGGER.debug("drop {} bytes, NAT entries exhausted (max. {})", proxyBuffer.limit(), maximumNumberOfNatEtries.get());
								}
							}
						}
					}
					keys.clear();
				}
				long now = System.nanoTime();
				long balancerTimeout = loadBalancerTimeoutMillis.get();
				if (balancerTimeout > 0) {
					long timeoutCheckMillis = TimeUnit.NANOSECONDS.toMillis(now - lastLoadBalancerCheck);
					if (timeoutCheckMillis > balancerTimeout / 4) {
						lastLoadBalancerCheck = now;
						long expireNanos = now - TimeUnit.MILLISECONDS.toNanos(balancerTimeout);
						synchronized (destinations) {
							revives(expireNanos);
							Iterator<NatAddress> iterator = pendingDestinations.iterator();
							while (iterator.hasNext()) {
								NatAddress dest = iterator.next();
								if (dest.getState() != NatAddressState.PENDING) {
									iterator.remove();
									destinations.add(dest);
									LOGGER.warn("revived {}", dest.name);
								}
							}
							expires(destinations, 1, expireNanos);
							expires(pendingDestinations, 0, expireNanos);
						}
					}
				}
				if (timeout > 0) {
					long timeoutCheckMillis = TimeUnit.NANOSECONDS.toMillis(now - lastTimeoutCheck);
					if (timeoutCheckMillis > timeout / 4) {
						lastTimeoutCheck = now;
						long expireNanos = now - TimeUnit.MILLISECONDS.toNanos(timeout);
						Iterator<NatEntry> iterator = nats.values().iterator();
						while (iterator.hasNext()) {
							NatEntry entry = iterator.next();
							if (entry.expires(expireNanos)) {
								iterator.remove();
								timedoutEntriesCounter.incrementAndGet();
							}
						}
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

	private boolean isDtlsRecord(ByteBuffer packet) {
		if (packet.limit() < DTLS_RECORD_MINIMUM_LENGTH) {
			return false;
		}
		if (packet.get(1) != DTLS_1_X_MAJOR_VERSION) {
			// not DTLS 1.x
			return false;
		}
		byte minorVersion = packet.get(2);
		if (minorVersion == DTLS_1_2_MINOR_VERSION) {
			// DTLS 1.2
			byte data = packet.get(0);
			for (int index = 0; index < DTLS_CONTENT_TYPES.length; ++index) {
				byte type = DTLS_CONTENT_TYPES[index];
				if (data < type) {
					return false;
				} else if (data == type) {
					return true;
				}
			}
		} else if (minorVersion == DTLS_1_0_MINOR_VERSION) {
			// hello verify request DTLS 1.0
			return packet.get(0) == DTLS_HANDSHAKE_RECORD;
		}
		return false;
	}

	private void expires(List<NatAddress> destinations, int minimum, long expireNanos) {
		if (destinations.size() > minimum) {
			Iterator<NatAddress> iterator = destinations.iterator();
			while (iterator.hasNext()) {
				NatAddress dest = iterator.next();
				if (dest.expires(expireNanos)) {
					iterator.remove();
					// prepare for revive after timeout
					dest.stale();
					staleDestinations.add(dest);
					LOGGER.warn("expires {}", dest.name);
					if (destinations.size() <= minimum) {
						break;
					}
				}
			}
		}
	}

	private void revives(long expireNanos) {
		if (!staleDestinations.isEmpty()) {
			Iterator<NatAddress> iterator = staleDestinations.iterator();
			while (iterator.hasNext()) {
				NatAddress dest = iterator.next();
				if (dest.expires(expireNanos)) {
					iterator.remove();
					dest.probe();
					probeDestinations.add(dest);
					LOGGER.warn("revive {}", dest.name);
				}
			}
		}
	}

	private NatEntry getNatEntry(InetSocketAddress source, DatagramChannel proxyChannel) throws IOException {
		NatEntry entry = nats.get(source);
		boolean spoof = this.spoof.getAndSet(false);
		if (entry != null && spoof) {
			entry = null;
		}
		if (entry == null && nats.size() < maximumNumberOfNatEtries.get()) {
			entry = new NatEntry(source, proxyChannel, selector, spoof);
			if (spoof) {
				spoofedCounter.incrementAndGet();
			} else {
				NatEntry previousEntry = nats.putIfAbsent(source, entry);
				if (previousEntry != null) {
					entry.stop();
					entry = previousEntry;
				}
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
		if (reorder != null) {
			reorder.stop();
		}
		running = false;
		for (DatagramChannel proxyChannel : proxyChannels) {
			try {
				proxyChannel.close();
			} catch (IOException e) {
				LOGGER.error("io-error on close!", e);
			}
		}
		proxyChannels.clear();
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
		LOGGER.warn("NAT {} stopped. {} forwarded messages, {} backwarded", proxyName, forwardCounter, backwardCounter);
	}

	/**
	 * Stop all NAT entries in {@link #nats} and clear that map.
	 * 
	 * @return number of stopped NAT entries.
	 */
	public int stopAllNatEntries() {
		return stopNatEntries(nats.size());
	}

	/**
	 * Stop NAT entries in {@link #nats}.
	 * 
	 * @param num number of NAT entries to stop.
	 * @return number of effectively stopped NAT entries.
	 * @since 2.5
	 */
	public int stopNatEntries(int num) {
		int counter = 0;
		Iterator<NatEntry> iterator = nats.values().iterator();
		while (num > 0 && iterator.hasNext()) {
			NatEntry entry = iterator.next();
			iterator.remove();
			entry.stop();
			--num;
			++counter;
		}
		return counter;
	}

	/**
	 * Set NAT timeout milliseconds.
	 * 
	 * A NAT entry without received nor send messages within that timeout is
	 * expired and removed.
	 * 
	 * @param natTimeoutMillis timeout in milliseconds
	 * @since 2.4
	 */
	public void setNatTimeoutMillis(int natTimeoutMillis) {
		this.natTimeoutMillis.set(natTimeoutMillis);
	}

	/**
	 * Set the load-balancer timeout milliseconds.
	 * 
	 * If a message is sent to a load-balancer destination and no message is
	 * received back, it's considered that the destination is not longer
	 * available and so expired and removed.
	 * 
	 * @param loadBalancerTimeoutMillis timeout in milliseconds
	 * @since 2.5
	 */
	public void setLoadBalancerTimeoutMillis(int loadBalancerTimeoutMillis) {
		this.loadBalancerTimeoutMillis.set(loadBalancerTimeoutMillis);
	}

	/**
	 * Gets number of entries in this NAT.
	 * 
	 * @return number of entries
	 * @since 2.4
	 */
	public int getNumberOfEntries() {
		return nats.size();
	}

	/**
	 * Get number of destinations.
	 * 
	 * @return number of destinations
	 * @since 2.5
	 */
	public int getNumberOfDestinations() {
		return destinations.size();
	}

	/**
	 * Get number of stale destinations.
	 * 
	 * @return number of stale destinations
	 * @since 2.5
	 */
	public int getNumberOfStaleDestinations() {
		return staleDestinations.size();
	}

	/**
	 * Get number of probe destinations.
	 * 
	 * @return number of probe destinations
	 * @since 3.0
	 */
	public int getNumberOfProbeDestinations() {
		return probeDestinations.size();
	}

	/**
	 * Get number of pending destinations.
	 * 
	 * @return number of pending destinations
	 * @since 3.0
	 */
	public int getNumberOfPendingDestinations() {
		return pendingDestinations.size();
	}

	/**
	 * Get list of destinations.
	 * 
	 * @return list of destinations
	 * @since 2.5
	 */
	public List<NatAddress> getDestinations() {
		List<NatAddress> result = new ArrayList<>();
		synchronized (destinations) {
			result.addAll(destinations);
		}
		return result;
	}

	/**
	 * Get list of stale destinations.
	 * 
	 * @return list of stale destinations
	 * @since 3.0
	 */
	public List<NatAddress> getStaleDestinations() {
		List<NatAddress> result = new ArrayList<>();
		synchronized (destinations) {
			result.addAll(staleDestinations);
		}
		return result;
	}

	/**
	 * Get list of probe destinations.
	 * 
	 * @return list of probe destinations
	 * @since 3.0
	 */
	public List<NatAddress> getProbeDestinations() {
		List<NatAddress> result = new ArrayList<>();
		synchronized (destinations) {
			result.addAll(probeDestinations);
		}
		return result;
	}

	/**
	 * Get list of pending destinations.
	 * 
	 * @return list of pending destinations
	 * @since 3.0
	 */
	public List<NatAddress> getPendingDestinations() {
		List<NatAddress> result = new ArrayList<>();
		synchronized (destinations) {
			result.addAll(pendingDestinations);
		}
		return result;
	}

	public long getSpoofedMessages() {
		return spoofedCounter.get();
	}

	/**
	 * Reassign new destination addresses to all NAT entries.
	 * 
	 * @return number of reassigned NAT entries.
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
			List<NatEntry> olds = new ArrayList<>(nats.size());
			List<Map.Entry<InetSocketAddress, NatEntry>> entries = new ArrayList<>(nats.entrySet());
			for (Map.Entry<InetSocketAddress, NatEntry> entry : entries) {
				InetSocketAddress incoming = entry.getKey();
				try {
					NatEntry oldentry = entry.getValue();
					NatEntry newEntry = new NatEntry(entry.getKey(), oldentry.proxyChannel, selector, false);
					nats.put(incoming, newEntry);
					oldentry.setIncoming(null);
					olds.add(oldentry);
					LOGGER.info("changed NAT for {} from {} to {}.", incoming, oldentry.getPort(), newEntry.getPort());
				} catch (IOException e) {
					LOGGER.error("Failed to reassing NAT entry for {}.", incoming, e);
				}
			}
			for (NatEntry old : olds) {
				old.stop();
			}
		}
	}

	/**
	 * Assign local addresses for incoming address.
	 * 
	 * @param incoming incoming address a local address is to be assigned
	 * @return port number of the assigned local address
	 * @throws IOException if reassign failed opening the new local socket
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
				return -1;
			}
		} else {
			DatagramChannel channel;
			NatEntry old = nats.get(incoming);
			if (old == null) {
				if (proxyChannels.size() == 1) {
					channel = proxyChannels.get(0);
				} else {
					LOGGER.error("No NAT for {}.", incoming);
					return -1;
				}
			} else {
				channel = old.proxyChannel;
			}
			NatEntry entry = new NatEntry(incoming, channel, selector, false);
			old = nats.put(incoming, entry);
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
			entry.setIncoming(null);
			destinations.add(entry);
		}
		for (InetSocketAddress incoming : keys) {
			int index = random.nextInt(destinations.size());
			NatEntry entry = destinations.remove(index);
			entry.setIncoming(incoming);
			NatEntry temp = nats.put(incoming, entry);
			if (temp != null && temp != entry) {
				temp.stop();
			}
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
	 * @throws IOException If an I/O error occurs
	 */
	public InetSocketAddress getProxySocketAddress() throws IOException {
		return (InetSocketAddress) proxyChannels.get(0).getLocalAddress();
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
	 * Enable reverse address update of NAT entries.
	 * 
	 * Update destination address, if backwards message is received from
	 * different source.
	 * 
	 * @param reverseUpdate {@code true}, enable reverse update, {@code false},
	 *            disable it.
	 * @since 2.5
	 */
	public void setReverseNatUpdate(boolean reverseUpdate) {
		reverseNatUpdate.set(reverseUpdate);
	}

	/**
	 * Check, if reverse address update is enabled.
	 * 
	 * @return {@code true}, if reverse update is enabled, {@code false},
	 *         otherwise.
	 * @since 2.5
	 */
	public boolean useReverseNatUpdate() {
		return reverseNatUpdate.get();

	}

	/**
	 * Set maximum number of NAT entries.
	 * 
	 * @param maximumNumber maximum number of NAT entries.
	 * @since 3.0
	 */
	public void setMaxiumNumberOfNatEntries(int maximumNumber) {
		this.maximumNumberOfNatEtries.set(maximumNumber);
	}

	/**
	 * Get maximum number of NAT entries.
	 * 
	 * @return maximum number of NAT entries.
	 * @since 3.0
	 */
	public int getMaxiumNumberOfNatEntries() {
		return maximumNumberOfNatEtries.get();
	}

	/**
	 * Enable DTLS filter.
	 * 
	 * Filter dtls 1.2 records for incoming messages. Drop none dtls-records.
	 * 
	 * @param dtlsFilter {@code true}, enable dtls filter, {@code false},
	 *            disable it.
	 * @since 3.0
	 */
	public void setDtlsFilter(boolean dtlsFilter) {
		this.dtlsFilter.set(dtlsFilter);
	}

	/**
	 * Check, if DTLS filter is enabled.
	 * 
	 * @return {@code true}, if dtls filter is enabled, {@code false},
	 *         otherwise.
	 * @since 3.0
	 */
	public boolean useDtlsFilter() {
		return dtlsFilter.get();
	}

	public void activateSpoof() {
		this.spoof.set(true);
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
		long current = wrongRoutedCounter.get();
		if (lastWrongRoutedCounter < current) {
			LOGGER.warn("wrong routed messages {} (overall {}).", current - lastWrongRoutedCounter,
					lastWrongRoutedCounter);
			lastWrongRoutedCounter = current;
		}
		current = timedoutEntriesCounter.get();
		if (lastTimedoutEntriesCounter < current) {
			LOGGER.warn("timed out NAT entries {} (overall {}).", current - lastTimedoutEntriesCounter,
					lastTimedoutEntriesCounter);

			int stale = getNumberOfStaleDestinations();
			int destinations = getNumberOfDestinations();
			if (stale > 0) {
				LOGGER.warn("{} destinations, {} stale destinations.", destinations, stale);
			}
			lastTimedoutEntriesCounter = current;
		}
	}

	/**
	 * Get random destination.
	 * 
	 * If destinations are pending for probe, return that and move it to
	 * pending.
	 * 
	 * @return random selected destination
	 * @see #destinations
	 * @see #probeDestinations
	 * @see #pendingDestinations
	 * @since 2.4
	 */
	public NatAddress getRandomDestination() {
		if (destinations.isEmpty()) {
			return null;
		} else {
			synchronized (destinations) {
				if (probeDestinations.isEmpty()) {
					int size = destinations.size();
					if (size == 1) {
						return destinations.get(0);
					} else {
						int index = random.nextInt(size);
						return destinations.get(index);
					}
				} else {
					NatAddress destination = probeDestinations.remove(0);
					destination.pending();
					pendingDestinations.add(destination);
					return destination;
				}
			}
		}
	}

	/**
	 * Get destination by address.
	 * 
	 * @param destination address of destination.
	 * @return nat address of destination.
	 * @since 2.5
	 */
	public NatAddress getDestination(InetSocketAddress destination) {
		if (destination != null) {
			synchronized (destinations) {
				for (NatAddress address : destinations) {
					if (address.address.equals(destination)) {
						return address;
					}
				}
			}
		}
		return null;
	}

	/**
	 * Get logging string for destinations.
	 * 
	 * @return logging string for destinations
	 * @since 2.5
	 */
	private String getDestinationForLogging() {
		if (destinations.isEmpty()) {
			return "---";
		} else {
			synchronized (destinations) {
				int size = destinations.size();
				if (size == 1) {
					return destinations.get(0).name;
				} else {
					return destinations.get(0).name + "-" + destinations.get(size - 1).name;
				}
			}
		}
	}

	/**
	 * NAT mapping entry.
	 * 
	 * Maps incoming inet addresses to local sockets.
	 */
	private class NatEntry {

		private final DatagramChannel proxyChannel;
		private final DatagramChannel outgoing;
		private final String natName;
		private final InetSocketAddress local;
		private final boolean spoof;
		private NatAddress incoming;
		private NatAddress destination;
		private boolean first;

		public NatEntry(InetSocketAddress incoming, DatagramChannel proxyChannel, Selector selector, boolean spoof)
				throws IOException {
			setDestination(getRandomDestination());
			this.proxyChannel = proxyChannel;
			this.outgoing = DatagramChannel.open();
			this.outgoing.configureBlocking(false);
			this.outgoing.bind(null);
			this.local = (InetSocketAddress) this.outgoing.getLocalAddress();
			this.natName = Integer.toString(this.local.getPort());
			this.spoof = spoof;
			setIncoming(incoming);
			this.outgoing.register(selector, SelectionKey.OP_READ, this);
		}

		public synchronized boolean setDestination(NatAddress destination) {
			if (this.destination == destination) {
				return false;
			} else if (this.destination != null) {
				if (this.destination.equals(destination)) {
					return false;
				}
				this.destination.usageCounter.decrementAndGet();
			}
			this.destination = destination;
			if (this.destination != null) {
				this.destination.usageCounter.incrementAndGet();
				this.first = true;
			}
			return true;
		}

		public synchronized void setIncoming(InetSocketAddress incoming) {
			if (incoming != null) {
				this.incoming = new NatAddress(incoming);
			} else {
				this.incoming = null;
			}
		}

		public boolean expires(long expireNanos) {
			NatAddress incoming;
			synchronized (this) {
				incoming = this.incoming;
			}
			if (incoming == null) {
				return true;
			}
			if (incoming.expires(expireNanos)) {
				stop();
				LOGGER.info("expired listen on {} for incoming {}", natName, incoming.name);
				return true;
			}
			return false;
		}

		public void stop() {
			try {
				if (destination != null) {
					destination.usageCounter.decrementAndGet();
				}
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
			NatAddress destination;
			synchronized (this) {
				destination = this.destination;
			}
			try {
				SocketAddress source = outgoing.receive(packet);
				((Buffer) packet).flip();
				if (destination.address.equals(source)) {
					destination.updateReceive();
				} else {
					wrongRoutedCounter.incrementAndGet();
					if (reverseNatUpdate.get()) {
						NatAddress newDestination = getDestination((InetSocketAddress) source);
						setDestination(newDestination);
					} else {
						((Buffer) packet).clear();
					}
				}
				return packet.limit();
			} catch (IOException ex) {
				return -1;
			}
		}

		public void backward(ByteBuffer packet) throws IOException {
			NatAddress incoming;
			NatAddress destination;
			synchronized (this) {
				incoming = this.incoming;
				destination = this.destination;
			}
			if (incoming == null) {
				return;
			}
			incoming.updateUsage();
			MessageDropping dropping = backward;
			if (spoof || (dropping != null && dropping.dropMessage())) {
				LOGGER.debug("backward drops {} bytes from {} to {} via {}", packet.limit(), destination.name,
						incoming.name, natName);
			} else {
				MessageSizeLimit limit = backwardSizeLimit;
				MessageSizeLimit.Manipulation manipulation = limit != null ? limit.limitMessageSize(packet)
						: MessageSizeLimit.Manipulation.NONE;
				switch (manipulation) {
				case NONE:
					LOGGER.debug("backward {} bytes from {} to {} via {}", packet.limit(), destination.name,
							incoming.name, natName);
					break;
				case DROP:
					LOGGER.debug("backward drops {} bytes from {} to {} via {}", packet.limit(), destination.name,
							incoming.name, natName);
					break;
				case LIMIT:
					LOGGER.debug("backward limited {} bytes from {} to {} via {}", packet.limit(), destination.name,
							incoming.name, natName);
					break;
				}
				if (manipulation != MessageSizeLimit.Manipulation.DROP) {
					if (proxyChannel.send(packet, incoming.address) == 0) {
						LOGGER.debug("backward overloaded {} bytes from {} to {} via {}", packet.limit(),
								destination.name, incoming.name, natName);
					} else {
						backwardCounter.incrementAndGet();
					}
				}
			}
		}

		public boolean forward(ByteBuffer packet) throws IOException {
			NatAddress incoming;
			NatAddress destination;
			boolean first;
			synchronized (this) {
				incoming = this.incoming;
				destination = this.destination;
				first = this.first;
				this.first = false;
			}
			if (incoming == null) {
				LOGGER.debug("forward drops {} bytes, no incoming address.", packet.limit());
				if (spoof) {
					stop();
				}
				return false;
			}
			incoming.updateUsage();
			if (!first && !destination.usable()) {
				destination = getRandomDestination();
				setDestination(destination);
			}
			MessageDropping dropping = forward;
			if (dropping != null && dropping.dropMessage()) {
				LOGGER.debug("forward drops {} bytes from {} to {} via {}", packet.limit(), incoming.name,
						destination.name, natName);
			} else {

				MessageSizeLimit limit = forwardSizeLimit;
				MessageSizeLimit.Manipulation manipulation = limit != null ? limit.limitMessageSize(packet)
						: MessageSizeLimit.Manipulation.NONE;
				switch (manipulation) {
				case NONE:
					LOGGER.debug("forward {} bytes from {} to {} via {}", packet.limit(), incoming.name,
							destination.name, natName);
					break;
				case DROP:
					LOGGER.debug("forward drops {} bytes from {} to {} via {}", packet.limit(), incoming.name,
							destination.name, natName);
					break;
				case LIMIT:
					LOGGER.debug("forward limited {} bytes from {} to {} via {}", packet.limit(), incoming.name,
							destination.name, natName);
					break;
				}
				if (manipulation != MessageSizeLimit.Manipulation.DROP) {
					if (outgoing.send(packet, destination.address) == 0) {
						LOGGER.info("forward overloaded {} bytes from {} to {} via {}", packet.limit(), incoming.name,
								destination.name, natName);
						if (spoof) {
							stop();
						}
						return false;
					} else {
						destination.updateSend();
						forwardCounter.incrementAndGet();
						LOGGER.debug("forwarded {} bytes from {} to {} via {}", packet.limit(), incoming.name,
								destination.name, natName);
					}
				}
			}
			if (spoof) {
				stop();
			}
			return true;
		}
	}
}
